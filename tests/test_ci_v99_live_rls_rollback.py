"""V9.9 fail-closed safety contracts for manual DEV ONLY RLS SQL scripts."""
from pathlib import Path
import re
import pytest

BASE=Path(__file__).resolve().parents[1] / "db" / "review"
SCRIPTS=("v99_live_tenant_row_read_rollback.sql","v99_live_customer_withcheck_rollback.sql")

@pytest.mark.parametrize("name",SCRIPTS)
def test_script_must_begin_transaction_and_explicitly_rollback(name):
    s=(BASE/name).read_text()
    tokens=re.findall(r"(?im)^\s*(BEGIN|COMMIT|ROLLBACK)\s*;",s)
    assert tokens==["BEGIN","ROLLBACK"]
    assert "SET LOCAL statement_timeout=" in s
    assert "SET LOCAL lock_timeout=" in s
    assert "CREATE " not in s.upper() and "ALTER TABLE" not in s.upper()
    assert "jw.session_hash" in s
    assert "SET LOCAL ROLE jw_app_dev;" in s
    assert "RESET ROLE;" in s
    assert "RAISE EXCEPTION" in s
    assert "SELECT CASE WHEN" in s
    assert "jw-v99-" in s and "@invalid.test" not in s.replace("v99-a2@invalid.test","").replace("v99-b2@invalid.test","").replace("v99-c2@invalid.test","").replace("v99check-a@invalid.test","")

def test_read_scope_must_test_all_tenants_and_four_actual_table_types():
    sql=(BASE/SCRIPTS[0]).read_text()
    for session in ("hash-a","hash-b","hash-c","hash-unknown"):
        assert session in sql
    assert sql.count("DO $rls$")==4
    for table in ("customers","quotes","orders","messenger_messages"):
        assert sql.count("FROM jw_dev."+table+" WHERE id LIKE")>=4
    for expected in ("ARRAY[1,1,1,1]","ARRAY[1,1,1,2]","ARRAY[0,0,0,1]","ARRAY[0,0,0,0]"):
        assert expected in sql
    assert "PASS_A_B_C_CUSTOMER_QUOTE_ORDER_MESSAGE_AND_ROLLBACK" in sql

def test_write_withcheck_rejects_only_rls_sqlstate_not_unrelated_trigger():
    sql=(BASE/SCRIPTS[1]).read_text()
    assert "EXCEPTION WHEN SQLSTATE '42501'" in sql
    assert "GET STACKED DIAGNOSTICS" in sql
    assert "jw_dev.customers" in sql
    assert "PASS_CROSS_ORG_CUSTOMER_INSERT_RLS_DENIED_AND_ROLLED_BACK" in sql

def test_fixture_safety_guard_prevents_nonempty_database():
    for name in SCRIPTS:
        sql=(BASE/name).read_text()
        assert "current_database()<>'postgres'" in sql
        assert "count(*) FROM jw_dev.organizations" in sql
        assert "ROLLBACK;" in sql
        assert "COMMIT;" not in sql
