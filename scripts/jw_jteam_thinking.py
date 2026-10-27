"""Evidence-based JARVIS/J TEAM thinking and practice router.

Converts seven user-provided viral prompts into bounded and testable work methods.
No cognitive reprogramming, AI self-training, mind reading or guaranteed outcomes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "agents/team/jarvis_v1/evidence_thinking.json"
DOMAINS = ("software", "social_media", "business", "research", "everyday")
ROLES = ("deputy", "deputy_manager", "manager", "director", "jarvis_lead")
METHODS = ("systems", "learning", "apprenticeship", "reflection", "life_design",
           "leverage", "aspiration")
SENSITIVE = re.compile(r"(?i)(?:sk-[a-z0-9_-]{12,}|github_pat_|"
                       r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
                       r"(?:password|비밀번호|api[_ -]?key|인증키|secret)\s*[:=])")
RECOMMENDED = {"software": "systems", "social_media": "apprenticeship",
               "business": "leverage", "research": "learning",
               "everyday": "reflection"}
METHODOLOGY_NOT_PROOF = "HYPOTHESIS_REQUIRES_MEASURED_RESULTS"


def contract(path: Path = POLICY) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 24000:
        raise ValueError("UNSAFE_THINKING_POLICY")
    data = json.loads(path.read_text(encoding="utf8"))
    if (type(data) is not dict or data.get("schema") != "jw-jarvis-evidence-thinking-v1"
        or data.get("source") != "USER_PROVIDED_SEVEN_AI_TREND_IMAGES_2026_10_27"
        or data.get("status") != "METHOD_GUIDANCE_NOT_COGNITIVE_MODIFICATION"
        or data.get("default_selection") != RECOMMENDED
        or type(data.get("methods")) is not dict or set(data["methods"]) != set(METHODS)
        or data.get("disallowed_claims") != [
           "10x_learning_guarantee", "top_1_percent_in_90_days",
           "ten_years_in_one_year_guarantee", "billionaire_neural_install",
           "personality_or_memory_reprogramming", "mind_reading",
           "guaranteed_wealth_or_health"]
        or any(data.get(k) is not True for k in
          ("evidence_required", "user_autonomy", "no_external_calls",
           "no_private_data_upload", "no_automatic_schedule",
           "no_paid_resources", "no_main_merge"))
        or data.get("scores") != "NOT_MEASURED"
        or data.get("change_control") != "J1_J6_GATE_AND_APPROVAL"):
        raise ValueError("THINKING_POLICY_TAMPERED")
    for name, desc in data["methods"].items():
        if (type(desc) is not dict or set(desc) !=
                {"title", "domains", "actions", "metric"}
            or type(desc["title"]) is not str or not desc["title"]
            or type(desc["actions"]) is not list or len(desc["actions"]) != 4
            or any(type(t) is not str or not t for t in desc["actions"])
            or type(desc["domains"]) is not list or
               not desc["domains"] or not set(desc["domains"]) <= set(DOMAINS)
            or type(desc["metric"]) is not str or not desc["metric"]):
            raise ValueError("THINKING_METHOD_TAMPERED")
    return data


def make_plan(goal: str, *, domain: str = "software",
              method: str | None = None) -> dict:
    policy = contract()
    if type(goal) is not str or not 1 <= len(goal.strip()) <= 5000:
        raise ValueError("INVALID_GOAL")
    if SENSITIVE.search(goal) or "\x00" in goal:
        raise PermissionError("SENSITIVE_GOAL_DENIED")
    if domain not in DOMAINS:
        raise ValueError("UNSUPPORTED_DOMAIN")
    selected = RECOMMENDED[domain] if method is None else method
    if selected not in METHODS or domain not in policy["methods"][selected]["domains"]:
        raise ValueError("INCOMPATIBLE_METHOD_DOMAIN")
    data = policy["methods"][selected]
    return {
        "status": "PLAN_ONLY",
        "goal_digest": hashlib.sha256(goal.strip().encode()).hexdigest(),
        "domain": domain, "method": selected,
        "rationale": data["title"],
        "practice_steps": [{"instruction": action, "execution": "NOT_RUN"}
                           for action in data["actions"]],
        "success_metric": data["metric"],
        "evidence": METHODOLOGY_NOT_PROOF,
        "actual_improvement": "NOT_MEASURED",
        "real_learning": "NOT_ATTESTED",
        "fictitious_speed_claims": False,
        "user_opt_in_for_personal_goals": selected in ("life_design", "aspiration"),
        "user_autonomy": "PRESERVED",
        "independent_models_executed": 0,
        "paid_calls": 0, "external_calls": 0,
        "automatic_schedule": False, "release": "BLOCKED",
    }


def role_guidance(role: str) -> str:
    if role not in ROLES:
        raise ValueError("INVALID_ROLE")
    contract()
    role_tasks = {
        "deputy": "Separate verifiable evidence from viral promises and find systems alternatives.",
        "deputy_manager": "Propose humane, accessible practice or design routines aligned to user's explicit goals.",
        "manager": "Apply concrete exercises or low-risk prototypes; include baseline and reproducible tests.",
        "director": "Reject unmeasured 10x, memory upgrade, personality rewiring and artificial certainty.",
        "jarvis_lead": "Compare outcomes with J1–J6 review, measured costs and rollback before approval."
    }
    return ("JARVIS_SEVEN_METHODS_V136: Select relevant systems thinking, "
            "spaced retrieval, deliberate practice, decision journal, "
            "user-directed life planning, measured leverage or aspirational "
            "behaviors. A prompt cannot install genius, rewrite identity, "
            "guarantee 10x learning or 10 years' results in one. "
            "Record NOT_MEASURED rather than invent results. "
            + role_tasks[role])


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--goal", default=None)
    parser.add_argument("--domain", choices=DOMAINS, default="software")
    parser.add_argument("--method", choices=METHODS)
    args = parser.parse_args(argv)
    if args.check == (args.goal is not None):
        parser.error("choose --check or --goal")
    try:
        result = ({"status": "PASS", "method_count": len(contract()["methods"]),
                   "actual_learning": "NOT_ATTESTED", "release": "BLOCKED"}
                  if args.check else make_plan(args.goal,
                                               domain=args.domain, method=args.method))
    except (ValueError, PermissionError, OSError):
        print(json.dumps({"status": "BLOCKED", "error": "UNSAFE_THINKING_PLAN"}))
        return 3
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
