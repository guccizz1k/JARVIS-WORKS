"""Synthetic-only V6.3 multi-document preview regression. Never use real clients."""
from __future__ import annotations

import hashlib

from app import main
from tests.test_smart_import import make_xlsx
from tests.test_quote_import import qxlsx


def batch(api, *files):
    return api.c.post('/api/imports/batch/preview',
                      files=[('files', (name, data)) for name, data in files], headers=api.auth)


def test_batch_two_kinds_preview_only_then_independent_confirmation(api):
    before = {t: len(api.get('/' + t).json()) for t in ('customers', 'quotes', 'orders', 'invoices')}
    r = batch(api, ('quote.xlsx', qxlsx()), ('order.xlsx', make_xlsx()))
    assert r.status_code == 201, r.text
    d = r.json()
    assert d['staged_count'] == 2 and d['confirmation_required']
    assert d['transaction_records_created'] == 0 and d['original_files_saved'] is False
    assert [x['document']['record_type'] for x in d['previews']] == ['quote', 'order']
    for t in before: assert len(api.get('/' + t).json()) == before[t]
    assert api.get('/imports/queue').json()['pending_count'] == 2
    p = d['previews'][0]
    accepted = api.post('/imports/' + p['id'] + '/confirm', {
        'preview_digest': p['digest'], 'confirmed_customer': p['document']['company'],
        'confirmed_quote_date': p['document']['quote_date'],
        'confirmed_total': p['document']['money']['total'], 'approve': True})
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()['record_type'] == 'quote'
    assert len(api.get('/orders').json()) == before['orders']
    assert api.get('/imports/queue').json()['pending_count'] == 1


def test_atomic_fail_on_unrecognized_file_after_good(api):
    before = api.get('/imports/queue').json()['pending_count']
    response = batch(api, ('good.xlsx', make_xlsx()), ('unknown.png', b'\x89PNG\r\n\x1a\nabc'))
    assert response.status_code == 422
    assert '사진 OCR' in response.text
    assert api.get('/imports/queue').json()['pending_count'] == before
    with main.conn() as c:
        assert c.execute("SELECT count(*) FROM audit_logs WHERE action='batch_preview'").fetchone()[0] == 0


def test_semantic_duplicates_in_batch_rejected_without_db_writes(api):
    assert batch(api, ('a.xlsx', make_xlsx()), ('same.xlsx', make_xlsx())).status_code == 409
    assert api.get('/imports/queue').json()['pending_count'] == 0
    assert batch(api, ('a.xlsx', qxlsx()), ('b.xlsx', qxlsx())).status_code == 409
    assert api.get('/imports/queue').json()['pending_count'] == 0


def test_duplicate_against_confirmed_rolls_back_entire_batch(api):
    r = batch(api, ('first.xlsx', make_xlsx())).json()['previews'][0]
    assert api.post('/imports/' + r['id'] + '/confirm', {
        'preview_digest': r['digest'], 'confirmed_customer': r['document']['company'],
        'confirmed_order_date': r['document']['ordered_at'],
        'confirmed_total': r['document']['money']['total'], 'approve': True}).status_code == 201
    before=api.get('/imports/queue').json()['pending_count']
    second=batch(api, ('unrelated.xlsx', qxlsx()), ('existing.xlsx', make_xlsx()))
    assert second.status_code == 409, second.text
    assert api.get('/imports/queue').json()['pending_count'] == before


def test_batch_requires_csrf_and_still_enforces_tenant_scope(api):
    no_csrf=api.c.post('/api/imports/batch/preview',
            files=[('files', ('order.xlsx', make_xlsx()))],
            headers={'Cookie': api.auth['Cookie']})
    assert no_csrf.status_code == 403
    r=batch(api, ('order.xlsx', make_xlsx()))
    assert r.status_code == 201
    pid=r.json()['previews'][0]['id']
    with main.conn() as c:
        assert c.execute('SELECT count(*) FROM import_previews WHERE id=?',(pid,)).fetchone()[0] == 1
    # TestClient automatically carries the logged-in cookie; clear it for anonymous request.
    api.c.cookies.clear()
    assert api.c.get('/api/imports/'+pid).status_code == 401


def test_limits_and_failed_parser_leave_no_preview(api):
    assert batch(api, *[(f'{i}.xlsx', make_xlsx()) for i in range(9)]).status_code == 422
    assert batch(api, ('empty.xlsx', b'')).status_code in (413, 422)
    assert batch(api, ('malformed.pdf', b'%PDF-invalid')).status_code == 422
    assert batch(api, ('big.xlsx', b'0'*(5*1024*1024+1))).status_code == 413
    assert api.get('/imports/queue').json()['pending_count'] == 0


def test_staged_bytes_are_not_stored_and_audit_is_sanitized(api):
    raw = make_xlsx()
    response=batch(api, ('purchase.xlsx',raw))
    assert response.status_code == 201,response.text
    preview=response.json()['previews'][0]
    with main.conn() as c:
        row=c.execute('SELECT * FROM import_previews WHERE id=?',(preview['id'],)).fetchone()
        assert row['file_sha256']==hashlib.sha256(raw).hexdigest()
        assert row['status']=='pending' and row['order_id'] is None
        assert row['normalized_json'] and isinstance(row['normalized_json'],str)
        assert c.execute("SELECT count(*) FROM audit_logs WHERE entity_id=? AND action='batch_preview'",
                         (preview['id'],)).fetchone()[0]==1
    assert api.get('/dashboard').json()['orders'] == 0


def test_other_company_cannot_read_first_company_batch_preview(api):
    source = batch(api, ('a.xlsx', make_xlsx()))
    assert source.status_code == 201
    a_id = source.json()['previews'][0]['id']
    login = api.c.post('/api/login', json={
        'email': 'demo@bada.example', 'password': 'Demo!2026secure'})
    assert login.status_code == 200
    cookie=api.c.cookies.get(main.SESSION_COOKIE)
    headers={'Cookie': main.SESSION_COOKIE+'='+cookie,
             'X-CSRF-Token': login.json()['csrf_token']}
    assert api.c.get('/api/imports/'+a_id,headers=headers).status_code == 404
    assert api.c.get('/api/imports/queue',headers=headers).json()['pending_count'] == 0
    # Valid identical template is allowed for a different organization.
    other = api.c.post('/api/imports/batch/preview',
       files=[('files', ('a.xlsx', make_xlsx()))], headers=headers)
    assert other.status_code == 201, other.text
    other_id = other.json()['previews'][0]['id']
    assert other_id != a_id
    assert api.c.get('/api/imports/queue',headers=headers).json()['pending_count'] == 1
    assert api.c.get('/api/imports/'+a_id,headers=headers).status_code == 404
