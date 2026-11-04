"""Release-path proof with disposable demo tenants only.

This validates the authoritative server lifecycle. The CINEMA browser tests
independently validate the currently wired UI buttons; this is NOT proof that
every CINEMA button has been integrated or that live PostgreSQL is ready.
"""
from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet

import app.main as backend
from scripts.secure_backup import make_backup, restore_backup, verify_backup


def _expect(response, status):
    assert response.status_code == status, response.text
    return response.json()


def test_quote_to_cash_exactly_once_and_cross_company_denial(api, quote_payload):
    created = _expect(api.post('/quotes', quote_payload), 201)
    quote_id = created['id']
    total = created['money']['total']
    assert total == 1440  # 3*101 + 2*503 + VAT rounded half up.

    # No direct order creation without a legitimately accepted quote.
    draft_order = {'quote_id': quote_id, 'due_date': '2099-12-30'}
    assert api.post('/orders/from-quote', draft_order).status_code == 409
    _expect(api.post(f'/quotes/{quote_id}/status', {'status': 'sent'}), 200)
    _expect(api.post(f'/quotes/{quote_id}/status', {'status': 'accepted'}), 200)
    order = _expect(api.post('/orders/from-quote', draft_order), 201)
    order_id = order['id']
    assert api.post('/orders/from-quote', draft_order).status_code == 409

    invoice_request = {'order_id': order_id, 'due_date': '2099-12-31'}
    statement_request = {'order_id': order_id}
    assert api.post('/automation/statements/from-order', statement_request).status_code == 409
    assert api.post('/invoices/from-order', invoice_request).status_code == 409
    assert api.post(f'/orders/{order_id}/status', {'status': 'fulfilled'}).status_code == 409
    _expect(api.post(f'/orders/{order_id}/status', {'status': 'processing'}), 200)
    _expect(api.post(f'/orders/{order_id}/status', {'status': 'fulfilled'}), 200)
    # The server stores an immutable trade statement from its fulfilled order
    # snapshot. This proves its API, NOT a real partial-delivery ledger.
    statement = _expect(api.post('/automation/statements/from-order', statement_request), 201)
    assert statement['order_id'] == order_id
    assert statement['document']['money']['total'] == total
    assert statement['document']['legal_status'] == 'internal_business_record_not_tax_invoice'
    assert statement['document']['finalized'] is True
    duplicate = _expect(api.post('/automation/statements/from-order', statement_request), 200)
    assert duplicate['id'] == statement['id'] and duplicate['reused'] is True
    detail = _expect(api.get('/automation/statements/' + statement['id']), 200)
    assert detail['document'] == statement['document']

    invoice = _expect(api.post('/invoices/from-order', invoice_request), 201)
    invoice_id = invoice['id']
    assert invoice['money']['total'] == total
    assert api.post('/invoices/from-order', invoice_request).status_code == 409
    trace = _expect(api.get('/automation/transactions/' + order_id), 200)
    assert trace['statement_id'] == statement['id']
    assert trace['invoice_id'] == invoice_id
    assert trace['remaining_balance'] == total
    assert {x['type'] for x in trace['events']} >= {'quote', 'order', 'trade_statement', 'invoice'}

    payment_url = f'/invoices/{invoice_id}/payments'
    today = datetime.now(ZoneInfo('Asia/Seoul')).date().isoformat()
    first = {'reference': uuid.uuid4().hex, 'amount': 500,
             'paid_at': today, 'note': 'CINEMA isolated first installment'}
    assert api.post(payment_url, {**first, 'amount': -1}).status_code == 422
    assert api.post(payment_url, {**first, 'amount': total + 1}).status_code == 409
    _expect(api.post(payment_url, first), 201)
    _expect(api.post(payment_url, first), 201)  # same reference, exactly-once replay
    details = _expect(api.get(f'/invoices/{invoice_id}'), 200)
    assert details['paid'] == first['amount']
    assert details['balance'] == total - first['amount']
    assert len([p for p in details['payments'] if p['reference'] == first['reference']]) == 1
    assert api.post(payment_url, {**first, 'amount': 501}).status_code == 409

    final = {'reference': uuid.uuid4().hex, 'amount': total - 500,
             'paid_at': today, 'note': 'CINEMA isolated final installment'}
    _expect(api.post(payment_url, final), 201)
    paid = _expect(api.get(f'/invoices/{invoice_id}'), 200)
    assert paid['paid'] == total and paid['balance'] == 0
    assert paid['payment_status'] == 'paid'
    assert api.post(payment_url, {**final, 'reference': uuid.uuid4().hex}).status_code == 409

    # Stateful APIs reject CSRF omission even with a valid session cookie.
    no_csrf = {'Cookie': api.auth['Cookie']}
    denied = api.c.post('/api' + payment_url, json=final, headers=no_csrf)
    assert denied.status_code == 403

    other = _expect(api.c.post('/api/login', json={
        'email': 'demo@bada.example', 'password': 'Demo!2026secure'}), 200)
    other_headers = {'Cookie': backend.SESSION_COOKIE + '=' +
                      api.c.cookies.get(backend.SESSION_COOKIE),
                     'X-CSRF-Token': other['csrf_token']}
    assert api.c.get(f'/api/invoices/{invoice_id}', headers=other_headers).status_code == 404
    assert api.c.post('/api' + payment_url, json=final, headers=other_headers).status_code == 404
    assert not any(x['id'] == invoice_id
                   for x in api.c.get('/api/invoices', headers=other_headers).json())
    assert api.c.get('/api/automation/statements/' + statement['id'], headers=other_headers).status_code == 404
    assert api.c.get('/api/automation/transactions/' + order_id, headers=other_headers).status_code == 404
    assert api.c.post('/api/automation/statements/from-order',json=statement_request,headers=other_headers).status_code == 404


def test_actual_application_sqlite_encrypted_backup_recovery(api, quote_payload,
                                                               tmp_path, monkeypatch):
    """An isolated schema/data backup can be authenticated and restored off-line."""
    quote = _expect(api.post('/quotes', quote_payload), 201)
    monkeypatch.setenv('JW_BACKUP_KEY', Fernet.generate_key().decode())
    backup = make_backup(backend.DB_PATH, tmp_path / 'backups')
    verify_backup(backup)
    assert backup.is_file() and backup.suffix == '.jwbackup'
    assert quote['title'].encode('utf-8') not in backup.read_bytes()
    restored = restore_backup(backup, tmp_path / 'restore' / 'restored.db')
    with sqlite3.connect(restored) as c:
        assert c.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert c.execute('SELECT title FROM quotes WHERE id=?', (quote['id'],)).fetchone()[0] == quote['title']
        assert c.execute('SELECT count(*) FROM customers').fetchone()[0] >= 1
