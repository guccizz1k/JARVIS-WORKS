"""J team OpenAI Responses API runner. Disabled by default; no paid calls without explicit opt-in.
Stdlib-only client. Keep secrets in environment, never in repo or receipts.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

if __package__:
    from .jw_jteam_external_sources import fabric_instructions
else:
    from jw_jteam_external_sources import fabric_instructions

ROLES=("deputy","deputy_manager","manager","director","jarvis_lead")
ROLE_TASKS={
"deputy":"Investigate evidence and source licenses; report alternatives and uncertainty.",
"deputy_manager":"Review product UI/UX, accessibility and usability; cite evidence.",
"manager":"Propose minimal code changes and tests; never claim unexecuted tests passed.",
"director":"Independently challenge code, security, regression and data isolation. Do not trust previous role's assertions.",
"jarvis_lead":"Consolidate all artifacts and blockers into review-only recommendation; never merge or deploy."
}
API_URL="https://api.openai.com/v1/responses"
def require_permission(args,env):
    if not args.execute or env.get("JTEAM_PAID_API_APPROVED")!="YES":
        raise PermissionError("PAID_API_NOT_APPROVED: dry-run only")
    if not env.get("OPENAI_API_KEY"):
        raise PermissionError("OPENAI_API_KEY_MISSING")
    if not env.get("JTEAM_MODEL"):
        raise PermissionError("JTEAM_MODEL_NOT_CONFIGURED")
    if args.max_calls<1 or args.max_calls>5:
        raise ValueError("MAX_CALLS_OUT_OF_RANGE")
    if args.max_output_tokens<32 or args.max_output_tokens>1200:
        raise ValueError("OUTPUT_CAP_OUT_OF_RANGE")
    if not args.budget_krw or args.budget_krw>50000 or args.budget_krw<1:
        raise ValueError("BUDGET_LIMIT_INVALID")
    # This is a user-approved per-run ceiling, not a provider-enforced billing limit.
    # No exchange-rate/token-price attestation => fail closed instead of guessing spend.
    if env.get("JTEAM_PROVIDER_BUDGET_ENFORCED")!="YES":
        raise PermissionError("PROVIDER_BUDGET_GUARD_NOT_ATTESTED")
def request_one(role,task,context,model,key,max_output_tokens):
    payload={"model":model,"instructions":ROLE_TASKS[role]+
        " J1-J6. Read-only. No claims of independent browser execution without proof. Never reveal credentials.\n" + fabric_instructions(role),
        "input":json.dumps({"task":task,"prior_artifacts":context},ensure_ascii=False),
        "max_output_tokens":max_output_tokens,"store":False}
    request=urllib.request.Request(API_URL,data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"},method="POST")
    with urllib.request.urlopen(request,timeout=45) as response:
        data=json.load(response)
    return {"role":role,"response_id":data.get("id"),"model":data.get("model"),
        "output":data.get("output",[]),"usage":data.get("usage",{}),
        "status":data.get("status")}
def main(argv=None,env=None):
    p=argparse.ArgumentParser()
    p.add_argument("--task",required=True)
    p.add_argument("--execute",action="store_true")
    p.add_argument("--max-calls",type=int,default=5)
    p.add_argument("--max-output-tokens",type=int,default=500)
    p.add_argument("--budget-krw",type=int,default=50000)
    p.add_argument("--output",type=Path)
    args=p.parse_args(argv)
    env=os.environ if env is None else env
    if not args.execute:
        print(json.dumps({"team":"J team","mode":"DRY_RUN","model_calls":0,
          "roles":ROLES,"required":["OPENAI_API_KEY","JTEAM_MODEL","JTEAM_PAID_API_APPROVED=YES",
          "JTEAM_PROVIDER_BUDGET_ENFORCED=YES"],"release":"BLOCKED"},ensure_ascii=False))
        return 0
    try:require_permission(args,env)
    except (PermissionError,ValueError) as exc:
        print(json.dumps({"status":"BLOCKED","reason":str(exc),"model_calls":0}))
        return 3
    # Sequential sessions ensure one distinct API response per role; no external tools granted.
    results=[]
    for role in ROLES[:args.max_calls]:
        try:
            item=request_one(role,args.task,results,env["JTEAM_MODEL"],env["OPENAI_API_KEY"],args.max_output_tokens)
        except (urllib.error.URLError,TimeoutError,ValueError) as exc:
            print(json.dumps({"status":"BLOCKED","completed_roles":len(results),"reason":type(exc).__name__}))
            return 4
        results.append(item)
        if item.get("status")!="completed" or not item.get("response_id"):
            print(json.dumps({"status":"BLOCKED","completed_roles":len(results),"reason":"INCOMPLETE_PROVIDER_RESPONSE"}))
            return 5
    report={"team":"J team","mode":"API_EXECUTED","results":results,
      "independent_review":"NOT_ATTESTED","release":"BLOCKED","generated_at":int(time.time())}
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps({"mode":"API_EXECUTED","completed_roles":len(results),
      "response_ids":[r["response_id"] for r in results],"release":"BLOCKED"}))
    return 0
if __name__=="__main__":sys.exit(main())
