"""Offline JARVIS-WORKS team contract checker. No AI model dispatch.

Structural PASS never certifies that five separate AI agents ran, or approves
production deployment, purchases, database migrations or release.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

TEAM = Path("agents/team/jarvis_v1/team.json")
ORDER = ("deputy", "deputy_manager", "manager", "director", "jarvis_lead")


def audit(root: Path) -> list[str]:
    root=Path(root)
    errors=[]
    config=root/TEAM
    if config.is_symlink() or not config.is_file():
        return ["team manifest missing or unsafe"]
    try:
        obj=json.loads(config.read_text(encoding="utf-8"))
    except (UnicodeError,OSError,ValueError):
        return ["team manifest unreadable"]
    if not isinstance(obj,dict):
        return ["team must be JSON object"]
    fields={"schema":"jw-agent-team-v1","team_id":"jarvis-works-one-team",
            "harness":"J1-J6","status":"REVIEW_ONLY",
            "runtime":"MODEL_DISPATCH_NOT_CONFIGURED",
            "single_writer":"jarvis_lead",
            "signoff":"HUMAN_RELEASE_SIGNOFF_REQUIRED"}
    for key,value in fields.items():
        if obj.get(key)!=value:errors.append("unsafe team field: "+key)
    if obj.get("actual_model_session_started") is not False:
        errors.append("unproven team execution claimed")
    if type(obj.get("max_concurrent_subagents")) is not int or not 1<=obj["max_concurrent_subagents"]<=2:
        errors.append("unbounded concurrent agent count")
    caps=obj.get("monthly_caps")
    if (type(caps) is not dict or
        type(caps.get("github_actions_extra_usd")) is not int or caps["github_actions_extra_usd"]!=5 or
        type(caps.get("openai_api_krw")) is not int or caps["openai_api_krw"]!=50000 or
        caps.get("automatic_cloud_spend") is not False or
        caps.get("render_plan_approved") is not False):
        errors.append("unauthorized spending policy")
    protected=obj.get("must_not")
    if type(protected) is not list or not {"main","production","live_db_migrations","unapproved_paid_api"}.issubset(set(protected)):
        errors.append("main/production protection missing")
    roles=obj.get("roles")
    if type(roles) is not list or len(roles)!=5:
        return sorted(set(errors+["expected exactly five roles"]))
    order=[r.get("id") if type(r) is dict else None for r in roles]
    if order!=list(ORDER):errors.append("wrong team roles/order")
    for idx,role in enumerate(roles):
        if type(role) is not dict:
            errors.append("invalid role object")
            continue
        name=role.get("id")
        if name not in ORDER:
            errors.append("unknown role")
            continue
        if role.get("can_commit") is not (name=="jarvis_lead"):
            errors.append("role write boundary violated: "+name)
        if role.get("may_execute_paid_tools") is not False:
            errors.append("paid tool authority granted: "+name)
        deps=role.get("depends_on")
        if type(deps) is not list or len(deps)!=len(set(deps)) or any(x not in ORDER[:idx] for x in deps):
            errors.append("dependency DAG invalid: "+name)
        skills=role.get("skills")
        if type(skills) is not list or not skills:
            errors.append("missing skills: "+name)
        else:
            for skill in skills:
                if type(skill) is not str or "/" in skill or ".." in skill:
                    errors.append("unsafe skill reference: "+name)
                elif not (root/".agents/skills"/skill/"SKILL.md").is_file():
                    errors.append("uninstalled local skill: "+skill)
        prompt=root/"agents/team/jarvis_v1/roles"/(name+".md")
        if prompt.is_symlink() or not prompt.is_file():
            errors.append("role prompt missing/unsafe: "+name)
        else:
            try:
                body=prompt.read_text(encoding="utf-8")
                if any(word not in body for word in ("J1–J6","BLOCKED","PASS","main","review")):
                    errors.append("role policy missing: "+name)
            except (OSError,UnicodeError):
                errors.append("role prompt unreadable: "+name)
    return sorted(set(errors))


def evaluate_receipts(data, sha: str) -> dict:
    """Validate shapes, NEVER award autonomous release or independent review."""
    import re
    result={"team":"jarvis-works-one-team","release":"BLOCKED",
            "team_run":"NOT_ATTESTED","cloud_spend_authorized":False}
    if type(sha) is not str or not re.fullmatch("[a-f0-9]{40}",sha):
        return {**result,"status":"BLOCKED","reason":"EXACT_SHA_REQUIRED"}
    if type(data) is not dict or data.get("sha")!=sha or type(data.get("receipts")) is not list:
        return {**result,"status":"BLOCKED","reason":"MISSING_SAME_SHA_EVIDENCE"}
    receipts=data["receipts"]
    if len(receipts)!=5 or [r.get("role") if type(r) is dict else None for r in receipts]!=list(ORDER):
        return {**result,"status":"BLOCKED","reason":"MISSING_FIVE_ROLE_EVIDENCE"}
    for r in receipts:
        if (r.get("status") not in ("PASS","FAIL","PARTIAL","BLOCKED","NOT RUN")
            or type(r.get("run_ref")) is not str or not r["run_ref"].strip()):
            return {**result,"status":"BLOCKED","reason":"BAD_EVIDENCE_SHAPE"}
    return {**result,"status":"REVIEW_ONLY","reason":"SHAPE_VALID_NEEDS_INDEPENDENT_RUNTIME_PROOF"}


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,required=True)
    args=p.parse_args()
    errors=audit(args.root)
    for issue in errors:print("FAIL:",issue)
    if errors:return 3
    print("PASS: one five-role team config/guards; actual model team NOT RUN; release BLOCKED")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
