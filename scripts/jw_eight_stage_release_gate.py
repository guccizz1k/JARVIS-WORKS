"""Eight-stage JARVIS WORKS review acceptance; no false release successes.

Every stage is evaluated (PARTIAL or BLOCKED until full product acceptance).
A green review-CI job means the fail-closed *report* was generated, NOT
that the eight launch prerequisites were all met.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path

GATES = (
    ("1","V9.9","real multi-company A/B/C row-level tenant isolation"),
    ("2","V10.0","full PostgreSQL signup/login/logout/MFA/session/auth E2E"),
    ("3","V10.1","quote/order/delivery/invoice/payment lifecycle on real database"),
    ("4","V10.2","real-user bilateral and group messenger+attachments and replay"),
    ("5","V10.3","real document OCR/approval/one-click conversion and accuracy"),
    ("6","V10.4","publicly deployed HTTPS browser cross-device/auth flows"),
    ("7","V10.5","representative migration, restore, concurrent load and RTO/RPO"),
    ("8","V11.0","independent security/owner approval, monitored launch+rollback"),
)



# This key belongs to an independent protected verifier, not review CI.
# A signature attests reviewed external evidence; never infer tests from a claim.
_STAGE_CONTROLS = {"1":["abc_cross_tenant_authenticated_rls","select_insert_update_delete_denials","rpc_attachment_denials","clean_fixture_rollback","real_https_session"],"2":["company_unique_postgres_signup","login_logout_revoke","mfa_recovery_replay","csrf_reset_lockout","browser_postgres_only"],"3":["quote_order_delivery_invoice_payment","approved_actor","zero_krw_reconciliation","idempotency_concurrency","wrong_tenant_durable_rollback"],"4":["multicompany_direct_group","search_membership","attachment_validation","edit_30m_no_delete","websocket_reconnect_dedupe"],"5":["pdf_excel_ground_truth_accuracy","approved_preview_and_conversion","linked_documents","malformed_formula_injection","measured_time_savings"],"6":["approved_https_staging","fastapi_ws_worker","desktop_browsers","http_auth_csrf","safe_secrets"],"7":["representative_restore","migration_no_data_loss","measured_rto_rpo_and_p95","concurrency","failure_injection_rollback"],"8":["independent_security_signoff","owner_final_confirmation","ops_runbook","no_deploy_review_boundary"]}
def _verified_stages(receipts, sha, key):
    import hashlib, hmac, re
    from datetime import datetime, timezone
    if not isinstance(receipts, list) or not isinstance(key, bytes) or len(key) < 32:
        return {}
    if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{40}", sha):
        return {}
    verified = {}
    for record in receipts:
        if not isinstance(record, dict) or set(record) != {"payload", "signature"}:
            return {}
        payload, sig = record["payload"], record["signature"]
        if not isinstance(payload, dict) or not isinstance(sig, str) or not re.fullmatch(r"[a-f0-9]{64}", sig):
            return {}
        required_keys = {"schema", "stage", "sha", "environment", "run_url", "controls", "reviewer", "verified_at", "measurements"}
        if set(payload) != required_keys:
            return {}
        stage = payload["stage"]
        if type(stage) is not int or str(stage) not in _STAGE_CONTROLS or stage in verified:
            return {}
        if payload["schema"] != "jw-reviewed-stage-v1" or payload["sha"] != sha or payload["environment"] != "isolated-https-staging":
            return {}
        url = payload["run_url"]
        prefix = "https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/"
        if not isinstance(url, str) or not url.startswith(prefix) or not re.fullmatch(r"[1-9][0-9]*(?:/attempts/[1-9][0-9]*)?", url[len(prefix):]):
            return {}
        controls = payload["controls"]
        if not isinstance(controls, list) or any(not isinstance(x, str) for x in controls):
            return {}
        if len(controls) != len(set(controls)) or set(controls) != set(_STAGE_CONTROLS[str(stage)]):
            return {}
        if not isinstance(payload["reviewer"], str) or len(payload["reviewer"].strip()) < 3:
            return {}
        measure = payload["measurements"]
        if not isinstance(measure, dict):
            return {}
        if stage == 3 and (type(measure.get("material_arithmetic_errors")) is not int or measure["material_arithmetic_errors"] != 0 or type(measure.get("unreconciled_krw")) is not int or measure["unreconciled_krw"] != 0):
            return {}
        if stage == 5 and (type(measure.get("document_samples")) is not int or measure["document_samples"] < 50 or type(measure.get("ground_truth_accuracy")) not in (int,float) or measure["ground_truth_accuracy"] != 1 or type(measure.get("material_arithmetic_errors")) is not int or measure["material_arithmetic_errors"] != 0):
            return {}
        if stage == 7 and (any(type(measure.get(k)) not in (int,float) or not 0 <= measure[k] < 1e8 for k in ("rto_seconds","rpo_seconds","p95_ms","rto_target_seconds","rpo_target_seconds","p95_target_ms")) or any(measure.get(v,1e12) > measure.get(t,-1) for v,t in (("rto_seconds","rto_target_seconds"),("rpo_seconds","rpo_target_seconds"),("p95_ms","p95_target_ms")))):
            return {}
        try:
            moment = datetime.fromisoformat(payload["verified_at"].replace("Z", "+00:00"))
            if moment.tzinfo is None or moment.astimezone(timezone.utc) > datetime.now(timezone.utc):
                return {}
            canonical = json.dumps(payload, sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
            correct = hmac.new(key, canonical, hashlib.sha256).hexdigest()
        except (TypeError, ValueError, AttributeError):
            return {}
        if not hmac.compare_digest(sig, correct):
            return {}
        verified[stage] = url
    return verified

def report(rls: dict, login: dict, *, sha: str = "NOT_PROVIDED", receipts=None, verification_key: bytes | None = None) -> dict:
    actual_rls = (
        isinstance(rls,dict) and rls.get("decision")=="INCONCLUSIVE"
        and rls.get("scope")=="REAL_DB_UNKNOWN_SESSION_READONLY"
        and rls.get("tested_tables")==10
        and rls.get("rollback")=="PASS"
        and rls.get("row_rls_proof")=="NOT_PROVEN_WITHOUT_POSITIVE_CONTROL"
        and rls.get("cross_tenant_abc")=="NOT_VERIFIED"
        and rls.get("production_cutover") is False
    )
    actual_login = (
        isinstance(login,dict) and login.get("decision")=="PASS"
        and login.get("authenticated") is True
        and login.get("read_only") is True
        and login.get("production_cutover") is False
    )
    certified = _verified_stages(receipts, sha, verification_key)
    stages=[]
    for number,version,name in GATES:
        if number=="1":
            status="PARTIAL" if actual_rls else "BLOCKED"
            evidence=("Real zero-row observations across ten live tables are INCONCLUSIVE for RLS without a positive-control populated fixture; "
                      "valid A/B/C tenant cross-access NOT TESTED on this SHA; separate PR #20 includes manual real DEV DB A/B/C rollback evidence" if actual_rls
                      else "No verified read-only invalid-session RLS receipt")
        elif number=="2":
            status="PARTIAL" if actual_login else "BLOCKED"
            evidence=("Two real role-bound catalog-only logins PASS; auth lifecycle NOT TESTED"
                      if actual_login else "Two real restricted PG role logins not verified")
        elif number=="3":
            status="PARTIAL"
            evidence="Real isolated PG17 login-to-quote proof exists; full persistent trade-to-payment E2E NOT VERIFIED"
        elif number=="4":
            status="PARTIAL"
            evidence="Isolated PG17 HTTPS/WSS browser A/B proof exists; live multiuser/group/attachments NOT VERIFIED"
        elif number=="5":
            status="PARTIAL"
            evidence="Local import/approval/document tests exist; real production OCR accuracy NOT MEASURED"
        elif number=="6":
            status="BLOCKED"
            evidence="Public Render HTTPS transport-only confirmed; DB-backed auth/browser acceptance NOT VERIFIED"
        elif number=="7":
            status="PARTIAL"
            evidence="Synthetic small PG17 13-table restore only; customer-scale migration/RTO/RPO NOT MEASURED"
        else:
            status="BLOCKED"
            evidence="Independent release security review and owner sign-off absent; no deployment"
        n = int(number)
        if n in certified and (n != 8 or all(p in certified for p in range(1,8))):
            status = "PASS"
            evidence = "Independently signed exact-SHA stage controls and external test run: " + certified[n]
        stages.append({"stage":n,"version":version,"requirement":name,
                       "evaluation":"ATTEMPTED","status":status,"evidence":evidence,
                       "complete":status=="PASS","required_controls":_STAGE_CONTROLS[str(n)]})
    assert len(stages)==8 and set(x["stage"] for x in stages)==set(range(1,9))
    assert all(x["evaluation"]=="ATTEMPTED" and x["status"]!="SKIP" for x in stages)
    return {"schema":"jw-eight-stage-v1","commit":sha,
            "release":"BLOCKED","production_deployed":False,
            "review_integrity":"PASS" if actual_rls and actual_login else "BLOCKED",
            "attested_stage_count":sum(x["status"]=="PASS" for x in stages),
            "stages":stages,
            "notes":"Only a separate protected verifier can sign external proof; regular review CI cannot self-approve; launch stays BLOCKED"}


def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--rls",type=Path,required=True)
    parser.add_argument("--auth",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    try:
        result=report(json.loads(args.rls.read_text()),
                      json.loads(args.auth.read_text()),
                      sha=os.getenv("GITHUB_SHA","NOT_PROVIDED"))
        args.out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n")
        print(json.dumps({"release":result["release"],
            "review_integrity":result["review_integrity"],
            "stage_statuses":[x["status"] for x in result["stages"]],
            "phase_count":len(result["stages"])}))
        return 0 if result["review_integrity"]=="PASS" else 3
    except (OSError,ValueError,TypeError,AssertionError):
        print("BLOCKED: required independent review evidence missing or invalid")
        return 3


if __name__=="__main__":
    raise SystemExit(main())
