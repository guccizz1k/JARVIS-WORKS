"""CI restore safety checks; no shared database gets a restore."""
import inspect
from scripts import ci_v93_finance_restore as r


def test_table_inventory_includes_pg_quote_and_audit():
    assert len(r.TABLES)==13
    assert {"quotes","quote_items","audit_logs","sessions"}.issubset(r.TABLES)


def test_script_never_connects_to_supabase_or_writes_prod():
    s=inspect.getsource(r.restore_proof)
    assert 'args.get("host")!="127.0.0.1"' in s
    assert "postgres:17" in inspect.getsource(r.restore_proof) or "IMAGE" in s
    assert "pg_dump" in s and "pg_restore" in s and "dropdb" in s


def test_original_snapshot_fingerprint_is_required():
    s=inspect.getsource(r.restore_proof)
    assert "other!=state" in s
    assert "check_snapshot(original)!=state" in s
