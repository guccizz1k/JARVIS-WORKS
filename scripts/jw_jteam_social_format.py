"""Social-media proven-format transfer policy for J TEAM, never performance claims.

Offline and deterministic. Produces a research/creation template rather than
inventing metrics, claiming a market gap, publishing or calling AI endpoints.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "agents/team/jarvis_v1/social_market_format.json"
PLATFORMS = ("instagram", "youtube")
FORMATS = ("POV", "TIER_LIST")
ROLES = ("deputy", "deputy_manager", "manager", "director", "jarvis_lead")
PARTS = ("hook", "audience_context", "original_demonstration",
         "distinct_payoff", "caption_and_cta", "rights_and_disclosure")
CHANGES = ("audience_and_problem", "original_examples_and_claims",
           "narrative_visuals_audio")
MEASURES = ("reach", "views", "average_watch_seconds", "completion_rate",
            "saves", "shares", "follows", "profile_clicks")
SECRET = re.compile(
    r"(?i)(?:sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{12,}|github_pat_|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:password|api[_ -]?key|비밀번호|인증키)\s*[:=])"
)


def _safe(value: object, limit: int = 250) -> str:
    if type(value) is not str or not 1 <= len(value.strip()) <= limit:
        raise ValueError("INVALID_FIELD")
    if SECRET.search(value) or any(ord(c) < 32 for c in value):
        raise PermissionError("SECRET_OR_CONTROL_CHARACTER")
    return value.strip()


def load_policy(path: Path = POLICY_PATH) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise ValueError("UNSAFE_SOCIAL_POLICY_PATH")
    obj = json.loads(path.read_text(encoding="utf-8"))
    if (type(obj) is not dict
        or obj.get("schema") != "jw-social-market-format-v1"
        or obj.get("default_for") != list(PLATFORMS)
        or obj.get("formats") != list(FORMATS)
        or obj.get("example_claim_status") != "ILLUSTRATIVE_UNVERIFIED"
        or obj.get("source_policy") != "PRIMARY_METRIC_EVIDENCE_REQUIRED"
        or obj.get("market_gap_policy") != "SEARCH_ABSENCE_IS_NOT_MARKET_PROOF"
        or obj.get("user_assets_policy") != "ORIGINAL_OR_RIGHTS_CLEARED_ONLY"
        or type(obj.get("pilot_posts")) is not int or obj["pilot_posts"] != 3
        or type(obj.get("starter_episodes")) is not int or obj["starter_episodes"] != 7
        or obj.get("change_dimensions") != list(CHANGES)
        or obj.get("content_parts") != list(PARTS)
        or obj.get("measurements") != list(MEASURES)
        or obj.get("release") != "REVIEW_ONLY"
        or obj.get("paid_budget") != "NO_NEW_CHARGES"):
        raise ValueError("SOCIAL_FORMAT_POLICY_TAMPERED")
    return obj


def platforms_for(instruction: str) -> list[str]:
    instruction = _safe(instruction, 5000).casefold()
    chosen = []
    if "인스타" in instruction or "instagram" in instruction or "릴스" in instruction or "reels" in instruction:
        chosen.append("instagram")
    if "유튜브" in instruction or "youtube" in instruction or "쇼츠" in instruction or "shorts" in instruction:
        chosen.append("youtube")
    return chosen or list(PLATFORMS)


def baseline_for(instruction: str) -> dict:
    """Social planning template only; no raw request, made-up market or output metrics."""
    p = load_policy()
    targets = platforms_for(instruction)
    return {
        "schema": p["schema"],
        "platforms": targets,
        "default_format_candidates": list(FORMATS),
        "selected_format": None,
        "source_market_evidence": "NOT_VERIFIED",
        "target_market_gap": "NOT_VERIFIED",
        "selected_source_post": None,
        "three_required_changes": list(CHANGES),
        "content_outline": list(PARTS),
        "format_examples": {
            "POV": "오리지널 체험과 실험을 당사자의 관점에서 보여주기",
            "TIER_LIST": "검증 가능한 기준으로 본인의 자료를 비교·분류하기",
        },
        "pilot": [{"slot": i, "status": "NOT_RUN", "source_url": None,
                   "metrics": {m: None for m in MEASURES}}
                  for i in range(1, p["pilot_posts"] + 1)],
        "first_seven": [{"episode": i, "status": "NOT_DRAFTED",
                         "unique_original_value": "REQUIRED"}
                        for i in range(1, p["starter_episodes"] + 1)],
        "originality_and_rights": "REVIEW_REQUIRED",
        "publication": "NOT_PERFORMED",
        "sales_or_views_guaranteed": False,
        "status": "RESEARCH_REQUIRED",
        "release": "BLOCKED",
        "request_sha256": hashlib.sha256(instruction.strip().encode()).hexdigest(),
    }


def _public_post_url(value: object) -> str:
    url = _safe(value, 1000)
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.username is not None or parts.password is not None:
        raise ValueError("PUBLIC_HTTPS_POST_URL_REQUIRED")
    host = (parts.hostname or "").lower()
    if host not in ("www.youtube.com", "youtube.com", "youtu.be",
                    "www.instagram.com", "instagram.com"):
        raise ValueError("UNKNOWN_POST_HOST")
    if parts.port is not None and parts.port != 443:
        raise ValueError("UNSAFE_PORT")
    if not parts.path or parts.path == "/":
        raise ValueError("POST_PATH_MISSING")
    return url


def record_external_examples(examples: list[dict], target_market: str) -> dict:
    """Collect evidence labels, do not certify posted metrics or transfer potential."""
    _safe(target_market, 120)
    if type(examples) is not list or not 1 <= len(examples) <= 20:
        raise ValueError("INVALID_EXAMPLE_COUNT")
    unique = set()
    selected = []
    for example in examples:
        if type(example) is not dict or set(example) != {
            "platform", "source_market", "post_url", "format", "views", "captured_on"
        }:
            raise ValueError("INVALID_EXAMPLE_SCHEMA")
        platform = example["platform"]
        if platform not in PLATFORMS or example["format"] not in FORMATS:
            raise ValueError("INVALID_FORMAT_OR_PLATFORM")
        market = _safe(example["source_market"], 120)
        url = _public_post_url(example["post_url"])
        hostname = urlsplit(url).hostname.lower()
        if platform == "youtube" and "youtu" not in hostname:
            raise ValueError("SOURCE_PLATFORM_MISMATCH")
        if platform == "instagram" and "instagram" not in hostname:
            raise ValueError("SOURCE_PLATFORM_MISMATCH")
        views = example["views"]
        if type(views) is not int or views < 0 or views > 10**12:
            raise ValueError("INVALID_VIEW_COUNT")
        try:
            date = datetime.date.fromisoformat(_safe(example["captured_on"], 10))
        except ValueError as err:
            raise ValueError("INVALID_CAPTURE_DATE") from err
        if not 2020 <= date.year <= 2035:
            raise ValueError("CAPTURE_DATE_OUT_OF_RANGE")
        if url in unique:
            raise ValueError("DUPLICATE_SOURCE_URL")
        unique.add(url)
        selected.append({
            "source_market": market, "format": example["format"],
            "recorded_views": views, "post_url": url,
            "captured_on": date.isoformat(), "status": "UNVERIFIED_OBSERVATION"
        })
    return {"examples": selected, "target_market": target_market,
            "source_metrics_independently_confirmed": False,
            "transfer_success_proven": False,
            "status": "SOURCE_REVIEW_REQUIRED"}


def whitespace_assessment(searches: list[dict]) -> dict:
    """Three sample searches cannot establish the nonexistence of a market."""
    if type(searches) is not list or len(searches) < 3 or len(searches) > 20:
        raise ValueError("THREE_DISTINCT_SEARCHES_REQUIRED")
    seen = set()
    for item in searches:
        if type(item) is not dict or set(item) != {"query", "platform", "observed_matches"}:
            raise ValueError("INVALID_SEARCH_SCHEMA")
        query = _safe(item["query"], 150).casefold()
        if query in seen or item["platform"] not in PLATFORMS:
            raise ValueError("DUPLICATE_OR_UNSUPPORTED_SEARCH")
        seen.add(query)
        matches = item["observed_matches"]
        if type(matches) is not int or matches < 0:
            raise ValueError("INVALID_SEARCH_COUNT")
    return {"status": "HYPOTHESIS_ONLY",
            "queries_reviewed": len(seen),
            "market_gap_proven": False,
            "warning": "Three platform searches are neither exhaustive nor unbiased."}


def role_instructions(role: str) -> str:
    if role not in ROLES:
        raise ValueError("UNKNOWN_JTEAM_ROLE")
    common = ("DEFAULT SOCIAL FORMAT BASELINE: study an observed format in another "
              "market before selecting POV or TIER_LIST; document dated primary "
              "post links, actual source-market metrics and 3 distinct target "
              "searches. Absence of hits never proves an empty market. "
              "Require 3 material adaptations (audience/problem, original substance, "
              "narrative/visual/audio); prepare 3 original pilot posts and a "
              "7-episode differentiated plan with hook, payoff, caption/CTA, "
              "rights, disclosures and measured retention. All illustrative "
              "view counts are unverified until independently sourced. "
              "No copying, near-duplicate mass production, fabricated traction "
              "or unauthorized posting. Research not completed => NOT_RUN. ")
    assignments = {
        "deputy": "Research: preserve verifiable primary post URLs, dates, audience, original format and alternative hypotheses.",
        "deputy_manager": "Strategy/design: test target-market fit, audience distinction, plan original scripts, hooks and seven differentiated episodes.",
        "manager": "Content creation: draft 3 distinct, original posts with scripts and captions after evidence review, use rights-cleared assets.",
        "director": "QA: challenge unsupported market claims, copied assets, repetitive scripts, missing licenses and invented views or conversion numbers.",
        "jarvis_lead": "Acceptance: require provenance, three meaningful changes, content QA, publishing authorization and real post-ID analytics before adoption.",
    }
    return common + assignments[role]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--demo", choices=["instagram", "youtube"])
    args = parser.parse_args(argv)
    if not args.check and not args.demo:
        parser.error("--check or --demo required")
    try:
        data = load_policy()
        result = {"status": "OFFLINE_FORMAT_BASELINE_PASS",
                  "formats": data["formats"], "pilot_posts": 3,
                  "first_seven": 7, "source_verification": "NOT_RUN",
                  "publication": "NOT_PERFORMED", "release": "BLOCKED"}
        if args.demo:
            result["template"] = baseline_for(args.demo)
    except (PermissionError, OSError, ValueError):
        print(json.dumps({"status": "BLOCKED", "reason": "FORMAT_GUARD_FAILED"}))
        return 3
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
