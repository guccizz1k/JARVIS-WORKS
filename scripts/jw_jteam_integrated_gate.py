"""J team integrated preflight: fail-closed receipts, cost reservation and A/B evidence.
Offline standard library; no provider call, GitHub mutation, deployment or paid CI.
"""
from __future__ import annotations
import argparse
import json
import sqlite3
from pathlib import Path

ROLES=("deputy","deputy_manager","manager","director","jarvis_lead")
TOOLS=("Playwright","axe-core","Ruff","Hypothesis","Schemathesis")
def setup(db):
    db.execute("CREATE TABLE IF NOT EXISTS budget (scope TEXT PRIMARY KEY,cap_krw INTEGER NOT NULL CHECK(cap_krw>0 AND cap_krw<=50000),reserved_krw INTEGER NOT NULL DEFAULT 0 CHECK(reserved_krw>=0),spent_krw INTEGER NOT NULL DEFAULT 0 CHECK(spent_krw>=0))")
    db.execute("CREATE TABLE IF NOT EXISTS reservations (request_id TEXT PRIMARY KEY,scope TEXT NOT NULL,amount_krw INTEGER NOT NULL CHECK(amount_krw>0),status TEXT NOT NULL CHECK(status IN ('RESERVED','UNCERTAIN','SETTLED')))")
    db.commit()
def reserve(db,scope,request_id,amount,cap=50000):
    if not isinstance(amount,int) or isinstance(amount,bool) or amount<=0:raise ValueError("INVALID_RESERVATION")
    if not isinstance(cap,int) or isinstance(cap,bool) or cap<1 or cap>50000:raise ValueError("INVALID_CAP")
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute("INSERT OR IGNORE INTO budget(scope,cap_krw) VALUES(?,?)",(scope,cap))
        row=db.execute("SELECT cap_krw,reserved_krw,spent_krw FROM budget WHERE scope=?",(scope,)).fetchone()
        if row[0]!=cap:raise ValueError("CAP_CONFLICT")
        previous=db.execute("SELECT scope,amount_krw,status FROM reservations WHERE request_id=?",(request_id,)).fetchone()
        if previous:
            if previous[0]!=scope or previous[1]!=amount:raise ValueError("REQUEST_ID_CONFLICT")
            db.commit()
            return previous[2]
        if row[1]+row[2]+amount>cap:raise PermissionError("BUDGET_EXCEEDED")
        db.execute("INSERT INTO reservations VALUES(?,?,?,'RESERVED')",(request_id,scope,amount))
        db.execute("UPDATE budget SET reserved_krw=reserved_krw+? WHERE scope=?",(amount,scope))
        db.commit()
        return "RESERVED"
    except BaseException:
        db.rollback()
        raise
def mark_uncertain(db,request_id):
    with db:
        result=db.execute("UPDATE reservations SET status='UNCERTAIN' WHERE request_id=? AND status='RESERVED'",(request_id,))
        if result.rowcount!=1:raise ValueError("NOT_RESERVABLE")
def validate_receipts(data):
    errors=[]
    if not isinstance(data,dict):return ["NO_RECEIPTS"]
    sha=data.get("sha")
    if not isinstance(sha,str) or len(sha)!=40 or any(c not in "0123456789abcdef" for c in sha):errors.append("INVALID_SHA")
    receipts=data.get("roles")
    if not isinstance(receipts,list) or len(receipts)!=5:return errors+["MISSING_ROLES"]
    if [x.get("role") if isinstance(x,dict) else None for x in receipts]!=list(ROLES):errors.append("ROLE_ORDER")
    sessions=[x.get("provider_response_id") if isinstance(x,dict) else None for x in receipts]
    if not all(isinstance(s,str) and s for s in sessions) or len(set(sessions))!=5:errors.append("SESSION_EVIDENCE")
    if any(not isinstance(x,dict) or x.get("sha")!=sha for x in receipts):errors.append("SHA_MISMATCH")
    if any(not isinstance(x,dict) or x.get("review_status")!="PASS" for x in receipts):errors.append("ROLE_REVIEW_NOT_PASS")
    if not data.get("independent_test_run_id"):errors.append("INDEPENDENT_TEST_NOT_ATTESTED")
    return errors
def ab_report(rows):
    """Require real per-tool baseline/candidate measurements and source evidence."""
    results={}
    for name in TOOLS:
        matching=[x for x in rows if isinstance(x,dict) and x.get("tool")==name]
        if len(matching)!=1:
            results[name]="NOT_RUN"
            continue
        x=matching[0]
        if (x.get("kind")!="MEASURED" or not x.get("baseline_run_id") or not x.get("candidate_run_id")
            or not isinstance(x.get("baseline_errors"),int) or not isinstance(x.get("candidate_errors"),int)
            or x["baseline_errors"]<0 or x["candidate_errors"]<0):
            results[name]="NOT_RUN"
        else:
            results[name]="IMPROVED" if x["candidate_errors"]<x["baseline_errors"] else ("REGRESSED" if x["candidate_errors"]>x["baseline_errors"] else "UNCHANGED")
    return results
def preflight(receipts=None,ab_rows=None):
    problems=validate_receipts(receipts)
    comparison=ab_report(ab_rows or [])
    if any(v=="NOT_RUN" for v in comparison.values()):problems.append("AB_EVIDENCE_MISSING")
    return {"status":"BLOCKED" if problems else "REVIEW_REQUIRED","issues":problems,
            "ab":comparison,"model_execution":"NOT_VERIFIED" if problems else "RECEIPTS_REQUIRE_INDEPENDENT_AUTHENTICATION",
            "paid_calls_performed_by_this_check":0,"release":"BLOCKED"}
def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--receipts",type=Path)
    p.add_argument("--ab",type=Path)
    a=p.parse_args(argv)
    receipts=json.loads(a.receipts.read_text(encoding="utf-8")) if a.receipts else None
    rows=json.loads(a.ab.read_text(encoding="utf-8")) if a.ab else None
    report=preflight(receipts,rows)
    print(json.dumps(report,ensure_ascii=False,indent=2))
    return 3 if report["status"]=="BLOCKED" else 0
if __name__=="__main__":raise SystemExit(main())
