"""J1–J6 gate prevents positive launch verdicts from partial proofs."""
from scripts import jw_eight_stage_release_gate as gate

RLS={"decision":"INCONCLUSIVE","scope":"REAL_DB_UNKNOWN_SESSION_READONLY",
     "tested_tables":10,"rollback":"PASS",
     "row_rls_proof":"NOT_PROVEN_WITHOUT_POSITIVE_CONTROL",
     "cross_tenant_abc":"NOT_VERIFIED",
     "production_cutover":False}
AUTH={"decision":"PASS","authenticated":True,"read_only":True,
      "production_cutover":False}

def test_all_eight_phases_are_evaluated_without_skips():
    x=gate.report(RLS,AUTH,sha="f"*40)
    assert [s["stage"] for s in x["stages"]]==list(range(1,9))
    assert all(s["evaluation"]=="ATTEMPTED" and s["status"]!="SKIP" for s in x["stages"])
    assert x["release"]=="BLOCKED" and x["production_deployed"] is False
    assert all(s["complete"] is False for s in x["stages"])

def test_real_missing_session_is_not_fake_abc_tenant_test():
    x=gate.report(RLS,AUTH)
    assert x["stages"][0]["status"]=="PARTIAL"
    assert "NOT TESTED" in x["stages"][0]["evidence"]

def test_missing_live_evidence_hard_blocks_fraudulent_claims():
    for a,b in (({},{}),({"decision":"PASS"},AUTH),(RLS,{"decision":"PASS"})):
        x=gate.report(a,b)
        assert x["review_integrity"]=="BLOCKED"
        assert x["release"]=="BLOCKED"
        assert any(s["status"]=="BLOCKED" for s in x["stages"])

def test_public_deploy_restore_and_owner_signature_cannot_be_inferred():
    x=gate.report(RLS,AUTH)
    assert x["stages"][5]["status"]=="BLOCKED"
    assert x["stages"][6]["status"]=="PARTIAL"
    assert x["stages"][7]["status"]=="BLOCKED"

def test_no_passing_release_even_if_all_readonly_contracted_gates_pass():
    x=gate.report(RLS,AUTH)
    assert x["review_integrity"]=="PASS"
    assert x["release"]=="BLOCKED"
