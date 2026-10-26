"""No cross-tenant disclosure and no false clean bill when records do not balance."""
import sqlite3
from app import main
from app.ops_integrity_v71 import inspect_tenant, MAX_INVOICES
from tests.conftest import create_invoice


def test_clean_tenant_is_scoped(api,quote_payload):
    create_invoice(api,quote_payload)
    r=api.get('/operations/integrity')
    assert r.status_code==200,r.text
    p=r.json()
    assert p['status']=='pass' and p['checked_invoices']==1 and p['scan_complete']
    assert p['operational_pg_rls_verified'] is False and p['accounting_certified'] is False
    assert not any(p['violations'].values())
    # The other enterprise does not see this enterprise's invoices or violations.
    assert api.login('demo@bada.example').status_code==200
    p2=api.get('/operations/integrity').json()
    assert p2['checked_invoices']==0 and p2['total_invoices']==0
    assert not any(p2['violations'].values())


def test_detect_negative_balance_without_changing_original(api,quote_payload):
    _,_,invoice=create_invoice(api,quote_payload)
    with main.conn() as c:
        original=c.execute('SELECT COUNT(*) FROM payments').fetchone()[0]
        user=c.execute('SELECT id,org_id FROM users WHERE email=?',('demo@hanbit.example',)).fetchone()
        # Direct synthetic corruption: bypass API overpayment validation.
        c.execute('INSERT INTO payments(id,org_id,invoice_id,amount,paid_at,note,created_at,reference) VALUES (?,?,?,?,?,?,?,?)',
                  ('synthetic_overpay',user['org_id'],invoice['id'],invoice['money']['total']+1,'2026-10-22','',main.now(),'synthetic_overpay_001'))
    p=api.get('/operations/integrity').json()
    assert p['status']=='review_required' and p['violations']['negative_balance_or_amount']==1
    with main.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM payments').fetchone()[0]==original+1


def test_foreign_tenant_ref_violation_detected_without_cross_tenant_details(api,quote_payload):
    inv=create_invoice(api,quote_payload)[2]
    with main.conn() as c:
        org=c.execute('SELECT org_id FROM invoices WHERE id=?',(inv['id'],)).fetchone()[0]
        other=c.execute('SELECT id FROM customers WHERE org_id<>?',(org,)).fetchone()[0]
        import pytest
        with pytest.raises(sqlite3.IntegrityError):
            c.execute('UPDATE invoices SET customer_id=? WHERE id=?',(other,inv['id']))
        # Simulate a legacy database without the guard in this disposable test only.
        c.execute('DROP TRIGGER jw_guard_invoices_customer_id_update')
        c.execute('UPDATE invoices SET customer_id=? WHERE id=?',(other,inv['id']))
    report=api.get('/operations/integrity').json()
    assert report['status']=='review_required'
    assert report['violations']['invoice_customer_tenant']==1
    assert other not in str(report)
    assert inv['id'] not in str(report)


def test_member_cannot_read_integrity_endpoint(api):
    with main.conn() as c:
        org=c.execute("SELECT id FROM organizations WHERE name='한빛테크'").fetchone()[0]
        c.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                  ('test_member',org,'member.test@example.com',main.hash_password('TestSecure!2026'),'member','member',main.now()))
    assert api.login('member.test@example.com','TestSecure!2026').status_code==200
    assert api.get('/operations/integrity').status_code==403


def test_scan_cap_is_not_reported_pass(monkeypatch,api,quote_payload):
    inv=create_invoice(api,quote_payload)[2]
    # Simulate a change in policy budget, rather than synthesizing thousands of invoices.
    import app.ops_integrity_v71 as mod
    monkeypatch.setattr(mod,'MAX_INVOICES',0)
    report=api.get('/operations/integrity').json()
    assert report['total_invoices']==1 and not report['scan_complete']
    assert report['status']=='review_required'
