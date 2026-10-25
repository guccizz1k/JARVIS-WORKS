"""Stage-level signed receipts are necessary, and release never promotes itself."""
import hashlib, hmac, json
from scripts import jw_eight_stage_release_gate as gate

SHA = "f"*40
KEY = b"R"*48

def _receipt(stage):
    payload = {
        "schema":"jw-reviewed-stage-v1", "stage":stage, "sha":SHA,
        "environment":"isolated-https-staging",
        "run_url":"https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/40161163266",
        "controls":list(gate._STAGE_CONTROLS[str(stage)]),
        "reviewer":"independent-reviewer", "verified_at":"2026-10-25T04:00:00Z",
        "measurements":(
            {"material_arithmetic_errors":0,"unreconciled_krw":0} if stage==3 else
            {"document_samples":100,"ground_truth_accuracy":1,"material_arithmetic_errors":0} if stage==5 else
            {"rto_seconds":10,"rpo_seconds":0,"p95_ms":80,"rto_target_seconds":120,
             "rpo_target_seconds":10,"p95_target_ms":250} if stage==7 else {}
        ),
    }
    token = hmac.new(KEY,json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode(),hashlib.sha256).hexdigest()
    return {"payload":payload,"signature":token}

def test_untrusted_or_wrong_sha_never_self_promotes():
    assert gate._verified_stages([_receipt(1)], SHA, None)=={}
    assert gate._verified_stages([_receipt(1)], "0"*40, KEY)=={}
    assert gate._verified_stages([_receipt(1), _receipt(1)], SHA, KEY)=={}
    invalid=_receipt(2)
    invalid["payload"]["controls"].pop()
    assert gate._verified_stages([invalid], SHA, KEY)=={}

def test_pass_capability_is_signature_gated_and_launch_remains_blocked():
    rls={"decision":"INCONCLUSIVE","scope":"REAL_DB_UNKNOWN_SESSION_READONLY",
         "tested_tables":10,"rollback":"PASS","row_rls_proof":"NOT_PROVEN_WITHOUT_POSITIVE_CONTROL",
         "cross_tenant_abc":"NOT_VERIFIED","production_cutover":False}
    auth={"decision":"PASS","authenticated":True,"read_only":True,"production_cutover":False}
    receipts=[_receipt(i) for i in range(1,9)]
    result=gate.report(rls,auth,sha=SHA,receipts=receipts,verification_key=KEY)
    assert [g["status"] for g in result["stages"]]==["PASS"]*8
    assert result["release"]=="BLOCKED" and result["production_deployed"] is False
    partial=gate.report(rls,auth,sha=SHA,receipts=receipts[:7],verification_key=KEY)
    assert partial["stages"][-1]["status"]=="BLOCKED"
    assert gate.report(rls,auth,sha=SHA)["attested_stage_count"]==0

def test_missing_required_numbers_are_blocking():
    for stage,bad_measure in [
        (3,{"material_arithmetic_errors":1,"unreconciled_krw":0}),
        (5,{"document_samples":0,"ground_truth_accuracy":1,"material_arithmetic_errors":0}),
        (7,{"rto_seconds":100,"rpo_seconds":0,"p95_ms":80,"rto_target_seconds":10,"rpo_target_seconds":10,"p95_target_ms":250}),
    ]:
        bad=_receipt(stage)
        bad["payload"]["measurements"]=bad_measure
        bad["signature"]=hmac.new(KEY,json.dumps(bad["payload"],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode(),hashlib.sha256).hexdigest()
        assert gate._verified_stages([bad],SHA,KEY)=={}
