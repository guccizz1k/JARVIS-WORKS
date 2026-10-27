"""Private universal J team work-order router.

Deterministic *planning only*. Does not execute AI models, publish content,
run code from a task, contact external services, or accept secret credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "agents/team/jarvis_v1/universal_work_order.json"
ROLES = ("deputy", "deputy_manager", "manager", "director", "jarvis_lead")
DOMAINS = ("software", "social_media", "business", "research", "everyday")
STAGES = ("intake", "research", "design", "produce", "independent_review",
          "approval", "authorized_action", "measurement")
TOKEN_PATTERN = re.compile(
    r"(?i)(?:sk-[A-Za-z0-9_-]{12,}|github_pat_|ghp_[A-Za-z0-9]{12,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:password|api[_ -]?key|비밀번호|인증키)\s*[:=])"
)
PROHIBITED_POLICY = {
    "provider_model_calls": "BLOCKED_BY_DEFAULT",
    "external_posting": "REQUIRES_CONNECTED_ACCOUNT_AND_ACTION_APPROVAL",
    "posting_schedule": "REQUIRES_CONNECTED_SCHEDULER_AND_AUTHORIZATION",
    "purchases": "REQUIRES_OWNER_APPROVAL",
    "source_modification": "REQUIRES_ISOLATED_REVIEW_AND_TESTS",
    "private_code_external_upload": "FORBIDDEN",
    "fake_follower_bot_engagement": "FORBIDDEN",
    "platform_account_sale": "POLICY_REVIEW_REQUIRED",
    "owner_only": "NO_PUBLIC_RUNTIME_BY_DEFAULT",
}


FACELESS_POLICY = {
    "user_filming_required": False,
    "user_voice_recording_required": False,
    "user_script_writing_required": False,
    "user_editing_required": False,
    "user_media_assets_required": False,
    "editorial_source": "ORIGINAL_VERIFIABLE_ASSISTANT_CONTENT",
    "media_sources": "OWN_GENERATED_OR_LICENSE_VERIFIED_ONLY",
    "rendering": "FREE_LOCAL_TOOLS_FIRST",
    "user_actions_only": ["ONE_TIME_ACCOUNT_CREATION_OR_OAUTH",
                          "PLATFORM_REQUIRED_PUBLISHING_APPROVAL"],
    "publish_without_authenticated_connection": "FORBIDDEN",
    "publisher_upload_without_owner_authority": "FORBIDDEN",
    "synthetic_realism_disclosure": "WHEN_PLATFORM_REQUIRES",
    "repetitive_low_value_bulk_publishing": "FORBIDDEN",
    "promised_subscribers_or_revenue": "FORBIDDEN",
    "status": "CAPABILITY_SPEC_NOT_END_TO_END_DEPLOYMENT",
}


def read_contract(path: Path = CONTRACT) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32768:
        raise ValueError("UNSAFE_WORK_ORDER_CONTRACT")
    obj = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(obj, dict)
        or obj.get("schema") != "jw-universal-work-order-v1"
        or obj.get("privacy") != "PRIVATE_OWNER_ONLY"
        or obj.get("harness") != ["J1", "J2", "J3", "J4", "J5", "J6"]
        or obj.get("role_order") != list(ROLES)
        or obj.get("default_workflow") != list(STAGES)
        or obj.get("default_domain") != "research"
        or type(obj.get("monthly_extra_cost_preference_krw")) is not int
        or obj["monthly_extra_cost_preference_krw"] != 0
        or obj.get("action_policy") != PROHIBITED_POLICY
        or obj.get("faceless_content_policy") != FACELESS_POLICY):
        raise ValueError("WORK_ORDER_POLICY_MISMATCH")
    domains = obj.get("allowed_domains")
    if not isinstance(domains, dict) or set(domains) != set(DOMAINS):
        raise ValueError("WORK_ORDER_DOMAINS_MISMATCH")
    for name in DOMAINS:
        record = domains[name]
        if not isinstance(record, dict):
            raise ValueError("WORK_ORDER_DOMAIN_FORMAT")
        role_map = record.get("role_focus")
        if not isinstance(role_map, dict) or set(role_map) != set(ROLES):
            raise ValueError("WORK_ORDER_ROLE_FORMAT")
        if any(not isinstance(x, str) or not 5 <= len(x) <= 600 for x in role_map.values()):
            raise ValueError("WORK_ORDER_ROLE_INSTRUCTIONS")
        kw = record.get("keywords")
        if not isinstance(kw, list) or not kw or len(kw) != len(set(kw)):
            raise ValueError("WORK_ORDER_KEYWORDS")
    return obj


def check_instruction(instruction: str) -> str:
    if not isinstance(instruction, str) or not 1 <= len(instruction.strip()) <= 5000:
        raise ValueError("INVALID_INSTRUCTION")
    clean = instruction.strip()
    if TOKEN_PATTERN.search(clean):
        raise PermissionError("POTENTIAL_SECRET_IN_INSTRUCTION")
    return clean


def domain_for(instruction: str, *, domain: str | None = None, config: dict | None = None) -> str:
    obj = read_contract() if config is None else config
    check_instruction(instruction)
    if domain is not None:
        if domain not in DOMAINS:
            raise ValueError("UNSUPPORTED_DOMAIN")
        return domain
    lowered = instruction.casefold()
    counts = {name: sum(1 for keyword in obj["allowed_domains"][name]["keywords"]
                        if keyword.casefold() in lowered) for name in DOMAINS}
    maximum = max(counts.values())
    if maximum == 0:
        return obj["default_domain"]
    # Favor user-visible channel intent when social media and software are co-mentioned.
    ranked = ("social_media", "software", "business", "everyday", "research")
    return next(name for name in ranked if counts[name] == maximum)


def role_guidance(role: str, instruction: str, *, domain: str | None = None,
                  config: dict | None = None) -> str:
    obj = read_contract() if config is None else config
    if role not in ROLES:
        raise ValueError("UNKNOWN_JTEAM_ROLE")
    chosen = domain_for(instruction, domain=domain, config=obj)
    focus = obj["allowed_domains"][chosen]["role_focus"][role]
    from scripts.jw_jteam_contextual_tools import role_guidance as optional_tool_guidance
    tool_guidance = optional_tool_guidance(role)
    social_method = ""
    if chosen == "social_media":
        from scripts.jw_jteam_social_format import role_guidance as format_guidance
        social_method = format_guidance(role)
    return (
        f"JTEAM_DOMAIN={chosen}; J1-J6 role={role}. {focus} "
        "This is advisory text, never authorization to publish, buy, merge, deploy "
        "or call paid models. Show actual evidence vs NOT RUN; no fake followers, "
        "copied or repetitive mass-produced media, unapproved account transfer "
        "or external upload of private source. Independent role-play is not "
        "independent model execution." + social_method + tool_guidance
    )


def _social_format_strategy(instruction: str) -> dict:
    from scripts.jw_jteam_social_format import social_brief
    return social_brief(instruction)


def _advice_for_tools(instruction: str, domain: str) -> dict:
    from scripts.jw_jteam_contextual_tools import recommend
    return recommend(instruction, domain=domain)


def plan(instruction: str, *, domain: str | None = None,
         config: dict | None = None) -> dict:
    obj = read_contract() if config is None else config
    clean = check_instruction(instruction)
    chosen = domain_for(clean, domain=domain, config=obj)
    issues = ["MODEL_DISPATCH_NOT_ATTESTED", "REAL_OUTCOMES_NOT_MEASURED"]
    if chosen == "social_media":
        issues += ["CONNECTED_SOCIAL_ACCOUNT_NOT_VERIFIED",
                   "ORIGINAL_MEDIA_RIGHTS_NOT_VERIFIED",
                   "PUBLISHING_AUTHORIZATION_NOT_VERIFIED"]
        if re.search(r"(인스타|instagram).{0,25}(판매|양도|매매)|"
                     r"(판매|양도|매매).{0,25}(인스타|instagram)", clean, re.I):
            issues.append("INSTAGRAM_ACCOUNT_SALE_POLICY_REVIEW")
    if chosen == "business":
        issues.append("BUSINESS_REVENUE_NOT_MEASURED")
    stages = [{"stage": x, "status": "NOT_RUN"} for x in STAGES]
    return {
        "status": "PLAN_ONLY", "domain": chosen,
        "task_sha256": hashlib.sha256(clean.encode("utf-8")).hexdigest(),
        "privacy": "PRIVATE_OWNER_ONLY",
        "roles": [{"role": name,
                   "focus": obj["allowed_domains"][chosen]["role_focus"][name],
                   "execution_status": "NOT_RUN"} for name in ROLES],
        "stages": stages, "issues": issues,
        "contextual_tool_advice": _advice_for_tools(clean, chosen),
        "social_format_strategy": (
            _social_format_strategy(clean) if chosen == "social_media" else None
        ),
        "approval": "REQUIRED_BEFORE_EXTERNAL_ACTION",
        "user_filming_required": False,
        "user_recording_required": False,
        "user_supplied_media_required": False,
        "media_rendered": False,
        "publication_performed": False, "paid_calls": 0,
        "independent_models_run": 0,
        "release": "BLOCKED",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", required=True)
    parser.add_argument("--domain", choices=DOMAINS)
    args = parser.parse_args(argv)
    try:
        result = plan(args.task, domain=args.domain)
    except (ValueError, PermissionError, OSError):
        print(json.dumps({"status": "BLOCKED", "reason": "UNSAFE_OR_INVALID_ORDER",
                          "paid_calls": 0, "publication_performed": False}))
        return 3
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
