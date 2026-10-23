"""Static safety checks supplement (but never replace) live Supabase SQL tests."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1] / 'security'


def test_payment_migration_uses_invoice_row_lock():
    s=(ROOT/'jw_dev_v83_payment_rpc.sql').read_text()
    assert "WHERE i.id=p_invoice FOR UPDATE" in s
    assert "WHERE id=p_payment_id AND org_id=v_org AND invoice_id=p_invoice FOR UPDATE" in s


def test_finance_sql_keeps_private_helpers_private():
    s=(ROOT/'jw_dev_v83_payment_rpc.sql').read_text()
    assert 'REVOKE ALL ON FUNCTION jw_dev.financial_state_v83(text)' in s
    assert 'GRANT EXECUTE ON FUNCTION jw_dev.record_payment_v83' in s
    assert 'TO jw_app_dev' in s
    assert 'GRANT INSERT ON jw_dev.payments' not in s


def test_adjustment_guard_serializes_with_payment():
    s=(ROOT/'jw_dev_v83_adjustment_guard.sql').read_text()
    assert 'WHERE i.id=v_invoice FOR UPDATE' in s
    assert "IF v_total<v_paid THEN" in s


def test_payment_migration_preserves_audit():
    s=(ROOT/'jw_dev_v83_payment_rpc.sql').read_text()
    assert s.count('INSERT INTO jw_dev.audit_logs') == 2
    assert 'Conflicting or reversed payment request key' in s
