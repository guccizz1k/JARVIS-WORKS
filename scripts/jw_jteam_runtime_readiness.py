"""J team fail-closed runtime readiness and independent receipt checker.
Does not call paid models, install dependencies or mutate repositories.
"""
import argparse
import json
import re
from pathlib import Path
ORDER=("deputy","deputy_manager","manager","director","jarvis_lead")
SHA=re.compile(r"^[a-f0-9]{40}$")
def readiness(config, receipts=None):
    errors=[]
    if config.get("display_name")!="J team" or config.get("harness")!="J1-J6":
        errors.append("TEAM_IDENTITY")
    roles=config.get("roles",[])
    if not isinstance(roles,list) or [r.get("id") for r in roles if isinstance(r,dict)]!=list(ORDER):
        errors.append("ROLE_ORDER")
    if config.get("runtime")!="MODEL_DISPATCH_NOT_CONFIGURED" or config.get("actual_model_session_started") is not False:
        errors.append("UNVERIFIED_RUNTIME_CLAIM")
    if config.get("max_concurrent_subagents",99)>2:
        errors.append("CONCURRENCY")
    if not isinstance(receipts,dict):
        return {"status":"BLOCKED","runtime":"NOT_CONNECTED","independent_review":"NOT_RUN","errors":errors+["NO_RECEIPTS"],"release":"BLOCKED"}
    sha=receipts.get("sha")
    if not isinstance(sha,str) or not SHA.fullmatch(sha):
        errors.append("INVALID_SHA")
    runs=receipts.get("runs",[])
    if not isinstance(runs,list) or [r.get("role") for r in runs if isinstance(r,dict)]!=list(ORDER):
        errors.append("MISSING_ROLE_RUNS")
    else:
        ids=[r.get("session_id") for r in runs]
        if not all(isinstance(i,str) and i.strip() for i in ids) or len(set(ids))!=5:
            errors.append("NONINDEPENDENT_SESSIONS")
        if any(r.get("source_sha")!=sha for r in runs):
            errors.append("SHA_MISMATCH")
        if any(r.get("provider_receipt") in (None,"") for r in runs):
            errors.append("NO_PROVIDER_ATTESTATION")
    return {"status":"BLOCKED" if errors else "REVIEW_REQUIRED","runtime":"NOT_CONNECTED","independent_review":"NOT_ATTESTED","errors":errors,"release":"BLOCKED"}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--team",default="agents/team/jarvis_v1/team.json")
    p.add_argument("--receipts")
    a=p.parse_args()
    config=json.loads(Path(a.team).read_text(encoding="utf-8"))
    receipts=json.loads(Path(a.receipts).read_text(encoding="utf-8")) if a.receipts else None
    result=readiness(config,receipts)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    return 2 if result["status"]=="BLOCKED" else 0
if __name__=="__main__":raise SystemExit(main())
