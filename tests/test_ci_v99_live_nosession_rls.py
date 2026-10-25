"""J1–J6 live no-session real RLS negative and fail-closed scope."""
import json

from scripts import ci_v99_live_nosession_rls as p


def test_scope_exact_ten_preexisting_tables():
    assert len(p.TABLES) == 10 and len(set(p.TABLES)) == 10
    assert set(p.TABLES) == set(p.EXPECTED)
    assert "sessions" not in p.TABLES and "users" not in p.TABLES


def test_missing_or_wrong_secret_cannot_run():
    env = {"JW_ENV":"review", "JW_V99_RLS_ACK":p.ACK}
    output = p.validated_probe(environ=env)
    assert output["decision"] == "BLOCKED"
    assert output["writes"] is False
    assert output["cross_tenant_abc"] == "NOT_VERIFIED"


def test_production_optin_rejected():
    output = p.validated_probe(environ={"JW_ENV":"production", "JW_V99_RLS_ACK":p.ACK})
    assert output["decision"] == "BLOCKED"


def test_report_never_claims_abc_or_production_from_no_session():
    result = p.validated_probe(environ={"JW_ENV":"review", "JW_V99_RLS_ACK":p.ACK})
    assert result["production_cutover"] is False
    assert result["cross_tenant_abc"] == "NOT_VERIFIED"
    assert "secret" not in json.dumps(result).lower() or result["reason"].endswith("MISSING")
