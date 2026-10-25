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


def report(rls: dict, login: dict, *, sha: str = "NOT_PROVIDED") -> dict:
    actual_rls = (
        isinstance(rls,dict) and rls.get("decision")=="PASS"
        and rls.get("scope")=="REAL_DB_UNKNOWN_SESSION_READONLY"
        and rls.get("tested_tables")==10
        and rls.get("rollback")=="PASS"
        and rls.get("cross_tenant_abc")=="NOT_VERIFIED"
        and rls.get("production_cutover") is False
    )
    actual_login = (
        isinstance(login,dict) and login.get("decision")=="PASS"
        and login.get("authenticated") is True
        and login.get("read_only") is True
        and login.get("production_cutover") is False
    )
    stages=[]
    for number,version,name in GATES:
        if number=="1":
            status="PARTIAL" if actual_rls else "BLOCKED"
            evidence=("Real invalid-session RLS denied across 10 jw_dev tables; "
                      "valid A/B/C tenant cross-access NOT TESTED" if actual_rls
                      else "No verified read-only invalid-session RLS receipt")
        elif number=="2":
            status="PARTIAL" if actual_login else "BLOCKED"
            evidence=("Two real role-bound catalog-only logins PASS; auth lifecycle NOT TESTED"
                      if actual_login else "Two real restricted PG role logins not verified")
        elif number=="3":
            status="PARTIAL"
            evidence="Staged PostgreSQL quote HTTP/reads exist; full live trade-to-payment E2E NOT VERIFIED"
        elif number=="4":
            status="PARTIAL"
            evidence="Synthetic PG17 messenger HTTP/WebSocket tests exist; real-user network E2E NOT VERIFIED"
        elif number=="5":
            status="PARTIAL"
            evidence="Local import/approval/document tests exist; real production OCR accuracy NOT MEASURED"
        elif number=="6":
            status="BLOCKED"
            evidence="No JARVIS WORKS external HTTPS staging deployment confirmed; real browser NOT RUN"
        elif number=="7":
            status="PARTIAL"
            evidence="Synthetic small PG17 13-table restore only; customer-scale migration/RTO/RPO NOT MEASURED"
        else:
            status="BLOCKED"
            evidence="Independent release security review and owner sign-off absent; no deployment"
        stages.append({"stage":int(number),"version":version,"requirement":name,
                       "evaluation":"ATTEMPTED","status":status,"evidence":evidence,
                       "complete":False})
    assert len(stages)==8 and set(x["stage"] for x in stages)==set(range(1,9))
    assert all(x["evaluation"]=="ATTEMPTED" and x["status"]!="SKIP" for x in stages)
    return {"schema":"jw-eight-stage-v1","commit":sha,
            "release":"BLOCKED","production_deployed":False,
            "review_integrity":"PASS" if actual_rls and actual_login else "BLOCKED",
            "stages":stages,
            "notes":"CI report success certifies honest evidence only, NOT all 8 stages complete"}


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
