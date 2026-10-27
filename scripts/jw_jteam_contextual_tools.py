"""J TEAM task-aware shortlist: existing native paths first, no external actions.

No requests, imports of vendor code, browsers, account connections, file transfers,
paid tools, provider model calls or external side effects. Plan-only routing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "agents/team/jarvis_v1/contextual_media_tools.json"
ROLES = ("deputy", "deputy_manager", "manager", "director", "jarvis_lead")
SCHEMA = "jw-jteam-contextual-media-tools-v1"
SERVICES = (
    {"id": "viralityai", "base_url": "https://viralityai.net/", "role": "deputy",
     "access": "HUMAN_MANUAL_ONLY", "license": "TERMS_RESTRICT_AUTOMATION_AND_COMMERCIAL_REUSE",
     "note": "No bot, API, scrape, stored credentials, commercial redistribution without permission"},
    {"id": "delphi", "base_url": "https://delphi.tools/", "role": "deputy_manager",
     "access": "MANUAL_BROWSER_ONLY", "license": "0BSD_WITH_SEPARATELY_LICENSED_COMPONENTS",
     "note": "No automatic file upload, cloning or installing; third-party component licensing check before redistribution"},
)
PRIORITIES = ["EXISTING_TOOL_FIRST", "MANUAL_RESEARCH_OPTIONAL", "DELPHI_BROWSER_FALLBACK"]
FORBIDDEN = ["automated_virality_access", "unapproved_data_transfer",
             "silent_delphi_install", "external_auth_or_account_link",
             "unreviewed_commercial_reuse", "cost_or_subscription",
             "production_deployment", "main_merge", "copy_external_creative_assets"]
SECRET = re.compile(r"(?i)(?:OPENAI_API_KEY|GITHUB_TOKEN|DATABASE_URL|"
                    r"github_pat_|ghp_[A-Za-z0-9]{8,}|sk-[A-Za-z0-9_-]{12,}|"
                    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
                    r"(?:password|api[_ -]?key|비밀번호|secret[_ -]?key|인증키)\s*[:=])")
CONFIDENTIAL = (
    "고객정보", "고객 데이터", "견적서", "거래명세표", "사업자번호",
    "개인정보", "비공개", "운영db", "운영 db", "tenant", "secret",
    "private repo", "database", "dsn", "credential", "토큰", "보안키",
    "사내자료", "내부문서", "고객사",
)
RESEARCH = ("바이럴", "트렌드", "아이디어", "조회수", "영상 포맷",
            "인기 영상", "시장 조사", "소재 추천", "레퍼런스",
            "viral", "trend", "format", "content ideas")
SUBTITLE = ("자막", "srt", "vtt", "subtitle", "받아쓰기")
FRAMES = ("프레임", "장면 추출", "컷 추출", "frame extract")
CROP = ("크롭", "영상 비율", "9:16", "세로영상", "세로 영상",
        "영상 사이즈", "crop", "리사이즈", "resize")
BACKGROUND = ("배경 제거", "누끼", "background remove", "투명 배경")
COLORS = ("색상 대비", "명암 대비", "색상 추출", "팔레트",
          "contrast checker", "palette")
TOOLS = ("도구", "tool", "디자인", "이미지", "영상", "pdf", "개발", "코드")
PLATFORMS = ("인스타", "유튜브", "릴스", "쇼츠", "instagram", "youtube",
             "reels", "shorts")


def read_contract(path: Path = MANIFEST) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise ValueError("UNSAFE_ROUTING_CONTRACT")
    data = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        "schema": SCHEMA, "harness": [f"J{i}" for i in range(1, 7)],
        "execution": "RECOMMEND_ONLY_NO_EXTERNAL_TOOL_EXECUTION",
        "services": list(SERVICES), "priorities": PRIORITIES,
        "forbidden": FORBIDDEN, "confidentiality": "RESTRICTED_DATA_LOCAL_ONLY",
        "require_review": "J1_J6_5_GATES_AND_HUMAN_EXTERNAL_ACTION_APPROVAL",
        "spent_usd": 0,
    }
    if type(data) is not dict or data != expected:
        raise ValueError("TOOL_ROUTING_POLICY_CHANGED")
    return data


def _task(text: str) -> str:
    if type(text) is not str or not 1 <= len(text.strip()) <= 5000:
        raise ValueError("INVALID_TASK")
    if SECRET.search(text):
        raise PermissionError("SECRET_BEARING_TASK_BLOCKED")
    if "\x00" in text:
        raise PermissionError("BINARY_TASK_BLOCKED")
    return text.casefold()


def _matches(text: str, phrases: tuple[str, ...]) -> bool:
    return any(p in text for p in phrases)


def recommend(instruction: str, *, domain: str | None = None) -> dict:
    """Select guidance, never invoke services. Exact scopes are hard coded."""
    read_contract()
    lower = _task(instruction)
    if domain is not None and domain not in (
        "software", "social_media", "business", "research", "everyday"):
        raise ValueError("UNKNOWN_DOMAIN")
    confidential = _matches(lower, CONFIDENTIAL)
    social = domain == "social_media" or _matches(lower, PLATFORMS)
    wants_research = social and _matches(lower, RESEARCH)
    media = social or _matches(lower, TOOLS)
    selections: list[dict] = []

    def add(tool: str, operation: str, rank: str, why: str) -> None:
        if any(e["tool"] == tool and e["operation"] == operation for e in selections):
            return
        selections.append({
            "tool": tool, "operation": operation, "priority": rank,
            "reason": why, "status": "NOT_RUN",
            "executed": False, "account_connected": False,
        })

    if confidential:
        add("existing_local_jteam", "protected_data_processing", "FIRST",
            "Confidential task: only already-authorized project-local tools")
    else:
        if wants_research:
            add("existing_public_research", "cross_market_source_validation", "FIRST",
                "Validate dated primary-platform sources before any viral claims")
            add("viralityai", "manual_trend_reference", "OPTIONAL_MANUAL",
                "Human-only inspiration; terms prohibit automated access and broad commercial reuse")
        if _matches(lower, SUBTITLE) and media:
            add("existing_whisper_ffmpeg", "subtitle_and_transcript", "FIRST",
                "Reuse existing transcription/video pipeline before considering alternatives")
            add("delphi", "manual_auto_subtitle", "OPTIONAL_MANUAL",
                "Browser-only fallback; verify file sensitivity and output quality")
        if _matches(lower, FRAMES) and media:
            add("existing_ffmpeg", "frame_extract", "FIRST",
                "Existing FFmpeg already supports frame extraction")
            add("delphi", "manual_frame_extractor", "OPTIONAL_MANUAL",
                "Optional manual visual extraction when native path unavailable")
        if _matches(lower, CROP) and media:
            add("existing_ffmpeg", "resize_or_social_crop", "FIRST",
                "Use existing FFmpeg sizing before external/manual services")
            add("delphi", "manual_social_media_cropper", "OPTIONAL_MANUAL",
                "Manual cropper only for approved non-confidential assets")
        if _matches(lower, BACKGROUND) and media:
            add("existing_project_image_pipeline", "background_removal_check", "FIRST",
                "Reuse existing image workflow if already implemented and verified")
            add("delphi", "manual_background_remover", "OPTIONAL_MANUAL",
                "Browser option, no automatic model download or asset transfer")
        if _matches(lower, COLORS) and media:
            add("existing_design_qa", "contrast_palette_check", "FIRST",
                "Preserve existing design tokens and UI test gates")
            add("delphi", "manual_contrast_palette", "OPTIONAL_MANUAL",
                "Browser contrast/palette checks require independent QA evidence")
    return {
        "schema": SCHEMA,
        "status": "ROUTING_ONLY",
        "task_sha256": hashlib.sha256(instruction.strip().encode("utf-8")).hexdigest(),
        "data_scope": "RESTRICTED_LOCAL_ONLY" if confidential else "NO_EXTERNAL_DATA_SUBMITTED",
        "selected": selections,
        "sources_used": 0, "external_calls": 0,
        "files_uploaded": 0, "vendor_tools_installed": 0,
        "subscriptions_started": 0, "cost_usd": 0,
        "licenses": "REVIEW_REQUIRED_BEFORE_EMBEDDING",
        "publication": "NOT_RUN",
        "release": "BLOCKED",
    }


def role_guidance(role: str) -> str:
    if role not in ROLES:
        raise ValueError("UNKNOWN_ROLE")
    read_contract()
    tasks = {
        "deputy": "Research public original sources first; ViralityAI is HUMAN_MANUAL_ONLY and source claims remain unverified until checked.",
        "deputy_manager": "Use existing design and media paths first; Delphi is optional MANUAL_BROWSER_ONLY for non-confidential assets.",
        "manager": "Do not install Delphi source or auto-run third-party web tools. Reuse tested FFmpeg, Whisper and established code.",
        "director": "Reject scraped ViralityAI, commercial license violations, private data exposure, unlicensed assets, fake metrics and skipped gates.",
        "jarvis_lead": "Route optional tools only as advisory plans; preserve J1–J6 approvals, no paid spend, upload, deployment or publication.",
    }
    return ("MANDATORY_CONTEXTUAL_TOOLS_V133: select tools by task, no blanket "
            "activation, existing paths first, external vendor links are manual "
            "references only. " + tasks[role])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--task")
    parser.add_argument("--domain", choices=("software", "social_media",
                                             "business", "research", "everyday"))
    args = parser.parse_args(argv)
    if args.check == bool(args.task):
        parser.error("specify --check or --task")
    try:
        result = (
            {"status": "CONTEXTUAL_ROUTER_CONTRACT_PASS",
             "vendor_calls": 0, "release": "BLOCKED"}
            if args.check and read_contract()
            else recommend(args.task, domain=args.domain)
        )
    except (ValueError, PermissionError, OSError):
        print(json.dumps({"status": "BLOCKED", "reason": "UNSAFE_ROUTING_REQUEST",
                          "vendor_calls": 0}, sort_keys=True))
        return 3
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
