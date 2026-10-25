"""J1–J6 V9.9 real DB RLS read-only probe scope and rollback assertions."""
import json
from scripts import ci_v99_live_nosession_rls as p
from scripts import ci_v97_supavisor_restricted_auth as gate


def test_fixed_real_table_scope_and_no_actual_tenant_abc_claim():
    assert len(p.TABLES)==10 and len(set(p.TABLES))==10
    assert "users" not in p.TABLES and "sessions" not in p.TABLES


def test_missing_secret_rejected_before_any_connection():
    out=p.validate_result(environ={"JW_ENV":"review","JW_V99_RLS_ACK":p.ACK})
    assert out["decision"]=="BLOCKED" and out["cross_tenant_abc"]=="NOT_VERIFIED"


def test_production_environment_cannot_use_review_probe():
    assert p.validate_result(environ={"JW_ENV":"production"})["decision"]=="BLOCKED"


class MockCursor:
    def __init__(self,expose=False):self.results=[];self.expose=expose
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def execute(self,sql,params=None):
        if sql.startswith("SELECT session_user"):
            self.results.append(("jw_trade_gateway_v90",17))
        elif sql=="SELECT current_user":
            self.results.append(("jw_app_dev",))
        elif sql=="SELECT jw_dev.current_org_from_session()":
            self.results.append((None,))
        elif sql.startswith("SELECT count(*) FROM jw_dev."):
            self.results.append((1,) if self.expose else (0,))
    def fetchone(self):return self.results.pop(0)

class MockConnection:
    def __init__(self,expose=False,fail_rollback=False):
        self.cur=MockCursor(expose)
        self.fail_rollback=fail_rollback
        self.rolled=False;self.closed=False
    def cursor(self):return self.cur
    def rollback(self):
        if self.fail_rollback:raise RuntimeError("synthetic confidential")
        self.rolled=True
    def close(self):self.closed=True


def provisioned_env():
    return {"JW_ENV":"review","JW_V99_RLS_ACK":p.ACK,
        "JW_V97_TRADE_DSN":"postgresql://"+gate.USERS["trade"]+
        ":CI_NOT_SECRET@"+gate.POOLER_HOST+":5432/postgres?sslmode=verify-full"}


def test_ten_zero_counts_real_transaction_rolls_back():
    db=MockConnection()
    result=p.validate_result(environ=provisioned_env(),connector=lambda _:db)
    assert result["decision"]=="INCONCLUSIVE",result
    assert result["row_rls_proof"]=="NOT_PROVEN_WITHOUT_POSITIVE_CONTROL"
    assert result["tested_tables"]==10
    assert db.rolled and db.closed
    assert result["cross_tenant_abc"]=="NOT_VERIFIED"
    assert "CI_NOT_SECRET" not in json.dumps(result)


def test_one_visible_row_blocks_and_rolls_back():
    db=MockConnection(expose=True)
    result=p.validate_result(environ=provisioned_env(),connector=lambda _:db)
    assert result["decision"]=="BLOCKED"
    assert result["reason"]=="INVALID_SESSION_EXPOSED_ROWS"
    assert db.rolled and db.closed


def test_failed_rollback_never_claims_success():
    db=MockConnection(fail_rollback=True)
    result=p.validate_result(environ=provisioned_env(),connector=lambda _:db)
    assert result["decision"]=="BLOCKED"
    assert result["reason"]=="ROLLBACK_FAILED"
    assert db.closed
