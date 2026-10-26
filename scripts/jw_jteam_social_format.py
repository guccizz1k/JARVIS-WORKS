"""J TEAM social writing format research/transfer. No API or publishing."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "agents/team/jarvis_v1/social_format_transfer.json"
STEPS = ("cross_market_format_research", "dated_source_validation",
         "target_market_gap", "audience_fit", "original_adaptation",
         "three_post_pilot", "comparative_metrics")
ROLES = ("deputy", "deputy_manager", "manager", "director", "jarvis_lead")
SECRET = re.compile(r"(?i)(?:password|api[_ -]?key|비밀번호)\s*[:=]|"
                    r"sk-[a-z0-9_-]{12,}|github_pat_|-----BEGIN .*PRIVATE KEY-----")
VALIDATED = "NOT_VERIFIED_WITHOUT_INDEPENDENT_SOURCE"

def read_policy(path: Path = POLICY) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16000:
        raise ValueError("UNSAFE_POLICY")
    item = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        "schema": "jw-social-format-transfer-v1",
        "platforms": ["youtube", "instagram"],
        "steps": list(STEPS),
        "format_examples": ["pov", "tier_list"],
        "sample_claims": "UNVERIFIED",
        "min_pilot": 3, "source_not_checked": "HYPOTHESIS_ONLY",
        "no_copy": True, "no_bulk_reuse": True, "no_automatic_posting": True,
        "draft_requires": ["original_hook", "original_script_or_caption",
                           "platform_specific_cta", "format_hypothesis"],
        "proof_status": VALIDATED,
        "budget": "ZERO_EXTRA_SPEND"
    }
    if type(item) is not dict or item != expected:
        raise ValueError("POLICY_TAMPERING_OR_SCHEMA")
    return item

def social_brief(instruction: str, *, examples: list | None = None) -> dict:
    read_policy()
    if type(instruction) is not str or not 1 <= len(instruction.strip()) <= 5000:
        raise ValueError("INVALID_TASK")
    if SECRET.search(instruction):
        raise PermissionError("SECRET_IN_TASK")
    # User screenshots or references are research leads only, not independent proof.
    if examples is not None:
        if type(examples) is not list or len(examples) > 20:
            raise ValueError("INVALID_EXAMPLES")
        for candidate in examples:
            if (type(candidate) is not dict
                or set(candidate) != {"format_id", "source", "views"}
                or candidate["format_id"] not in ("pov", "tier_list", "other")
                or type(candidate["source"]) is not str
                or not 1 <= len(candidate["source"]) <= 500
                or SECRET.search(candidate["source"])
                or type(candidate["views"]) is not int
                or not 0 <= candidate["views"] <= 10**12):
                raise ValueError("UNSAFE_EXAMPLE")
    lower = instruction.casefold()
    platforms = []
    if any(x in lower for x in ("youtube", "유튜브", "쇼츠")):
        platforms.append("youtube")
    if any(x in lower for x in ("instagram", "인스타", "릴스")):
        platforms.append("instagram")
    return {
        "status": "DRAFT_STRATEGY_READY",
        "platforms": platforms or ["youtube", "instagram"],
        "task_sha256": hashlib.sha256(instruction.strip().encode()).hexdigest(),
        "research": [{"step": name, "status": "NOT_RUN"} for name in STEPS],
        "example_count": len(examples or []),
        "source_effectiveness": VALIDATED,
        "formats": ["pov", "tier_list", "other"],
        "original_draft_required": True,
        "separate_platform_copy": True,
        "pilot_posts": 3, "pilot_status": "NOT_RUN",
        "pilot_significance": "EXPLORATORY_NOT_CAUSAL_PROOF",
        "metrics": ["retention", "completion", "shares", "saves",
                    "follows", "clickthrough_when_available"],
        "comparison": "MATCH_OBSERVATION_WINDOW_AND_CHANNEL_BASELINE",
        "publication": "NOT_RUN", "paid_calls": 0, "release": "BLOCKED"
    }

def role_guidance(role: str) -> str:
    if role not in ROLES:
        raise ValueError("INVALID_ROLE")
    read_policy()
    focus = {
        "deputy": "Find independent dated evidence and underserved target-market angle.",
        "deputy_manager": "Choose original POV/ranking/other structure with distinct hook, story and audience fit.",
        "manager": "Write full original draft, platform-specific title, caption and CTA, not copied footage or wording.",
        "director": "Challenge fake success claims, source bias, rights, repetitive templates and metrics.",
        "jarvis_lead": "Offer three original trial posts, measure real outcomes and preserve owner publication approvals."
    }
    return ("MANDATORY_SOCIAL_FORMAT_TRANSFER_V132: For ALL YouTube and Instagram "
            "writing, research proven-adjacent-market structures with dated source "
            "evidence, inspect target-market saturation, adapt structure with genuine "
            "original content and platform-specific CTA. Screenshot figures alone are "
            "UNVERIFIED. Propose a 3-post exploratory test and compare retention, "
            "shares, saves at comparable observation windows, without promising "
            "virality or publishing automatically. " + focus[role])

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--task")
    args = parser.parse_args(argv)
    if args.check == bool(args.task):
        parser.error("choose one mode")
    try:
        response = ({"status": "POLICY_STRUCTURE_PASS",
                     "external_research": "NOT_RUN", "release": "BLOCKED"}
                    if args.check and read_policy() else social_brief(args.task))
    except (ValueError, PermissionError, OSError):
        print(json.dumps({"status": "BLOCKED", "reason": "UNSAFE_INPUT_OR_POLICY"}))
        return 3
    print(json.dumps(response, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
