"""JARVIS-WORKS eight-stage UI/UX evidence gate. No model execution."""
import argparse
import json
from pathlib import Path
STAGES=[{"id":"site_strategist","owner":"deputy","output":"user_goal_and_primary_action","requires":["primary_action","target_user","success_metric"]},{"id":"reference_hunter","owner":"deputy","output":"reference_analysis","requires":["reference_urls","adopt","reject","rationale"]},{"id":"design_system","owner":"deputy_manager","output":"design_tokens","requires":["colors","type_scale","spacing_scale","contrast_review"]},{"id":"hero_builder","owner":"deputy_manager","output":"first_screen","requires":["headlines","subheadlines","cta","desktop_1440","mobile_390"]},{"id":"section_writer","owner":"deputy_manager","output":"product_copy","requires":["features","evidence_based_claims","faq"]},{"id":"motion_detailer","owner":"manager","output":"motion_and_code","requires":["animations","max_duration_ms","reduced_motion","patch_sha"]},{"id":"performance_checker","owner":"director","output":"independent_browser_evidence","requires":["source_sha","browser_1440","browser_390","lighthouse_report","regression_report","accessibility_report"]},{"id":"launch_manager","owner":"jarvis_lead","output":"prelaunch_review_only","requires":["source_sha","release_checklist","rollback_plan","human_approval_required"]}]
def check(manifest, evidence):
    errors=[]
    if manifest.get("schema")!="jw-design-eight-stage-v1" or manifest.get("harness")!="J1-J6" or manifest.get("team")!="jarvis-works-one-team" or manifest.get("mode")!="REVIEW_ONLY":
        errors.append("unsafe manifest")
    if manifest.get("stages")!=STAGES:
        errors.append("stage contract mismatch")
    constraints=manifest.get("constraints",{})
    if constraints.get("allow_main_merge") is not False or constraints.get("allow_production_deploy") is not False or constraints.get("allow_paid_api") is not False:
        errors.append("release/spend protections missing")
    if type(evidence) is not dict:
        return {"status":"BLOCKED","errors":errors+["evidence must be object"],"stage_status":{}}
    result={}
    for stage in STAGES:
        item=evidence.get(stage["id"])
        missing=[key for key in stage["requires"] if not isinstance(item,dict) or key not in item or item[key] in (None,"",[])]
        result[stage["id"]]={"status":"BLOCKED" if missing else "REVIEW_REQUIRED","missing":missing}
    return {"status":"BLOCKED" if errors or any(x["status"]=="BLOCKED" for x in result.values()) else "REVIEW_REQUIRED",
            "errors":errors,"stage_status":result,"independent_browser_verified":False,"release_authorized":False}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--manifest",type=Path,default=Path("agents/team/jarvis_v1/design_pipeline.json"))
    p.add_argument("--evidence",type=Path,required=True)
    a=p.parse_args()
    report=check(json.loads(a.manifest.read_text(encoding="utf-8")),json.loads(a.evidence.read_text(encoding="utf-8")))
    print(json.dumps(report,ensure_ascii=False,indent=2))
    return 2 if report["status"]=="BLOCKED" else 0
if __name__=="__main__":raise SystemExit(main())
