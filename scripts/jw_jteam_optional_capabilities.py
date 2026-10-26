"""Review-only capability bridges for the five-role J TEAM; no implicit downloads/network."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "agents/team/jarvis_v1/capability_routing.json"
NAMES = ("Penpot", "Whisper", "Ollama", "n8n")
SKILLS = ("jt-design-system-bridge", "jt-audio-research",
          "jt-local-model-evaluation", "jt-workflow-adapter")
OWNERS = ("deputy_manager", "deputy", "manager", "jarvis_lead")
RUNTIMES = ("EXPORTED_TOKENS_ONLY", "TRANSCRIPT_VALIDATION_ONLY",
            "OPT_IN_LOOPBACK_SYNTHETIC_ONLY", "OPT_IN_LOOPBACK_EVENT_ONLY")
SAFE_KEY = re.compile(r"^[a-z][a-z0-9_.-]{1,79}$")
SAFE_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,79}$")
SECRET = re.compile(
    r"(?i)(?:OPENAI_API_KEY|GITHUB_TOKEN|DATABASE_URL|github_pat_|ghp_|"
    r"sk-[A-Za-z0-9_-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:password|api[_ -]?key|비밀번호)\s*[:=])"
)


def _safe_text(value: object, limit: int = 2000) -> str:
    if type(value) is not str or not 1 <= len(value.strip()) <= limit:
        raise ValueError("INVALID_TEXT")
    if SECRET.search(value) or any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise PermissionError("SECRET_OR_CONTROL_CHARACTER")
    return value


def inspect_manifest(path: Path = MANIFEST) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise ValueError("UNSAFE_CAPABILITY_MANIFEST")
    obj = json.loads(path.read_text(encoding="utf-8"))
    if (type(obj) is not dict
        or obj.get("schema") != "jw-jteam-optional-capabilities-v1"
        or obj.get("harness") != ["J1", "J2", "J3", "J4", "J5", "J6"]
        or obj.get("mode") != "OFFLINE_FIRST_REVIEW_ONLY"
        or obj.get("external_network") != "DENY_BY_DEFAULT"
        or obj.get("integration_owner") != "jarvis_lead"
        or obj.get("no_existing_tool_replacement") is not True
        or any(obj.get(x) is not True for x in
               ("no_auto_install", "no_auto_model_download", "no_public_url",
                "no_provider_secret", "no_production_deploy"))
        or type(obj.get("actions_extra_usd_limit")) is not int
        or obj["actions_extra_usd_limit"] != 5
        or type(obj.get("openai_monthly_krw_limit")) is not int
        or obj["openai_monthly_krw_limit"] != 50000):
        raise ValueError("CAPABILITY_POLICY_MISMATCH")
    rows = obj.get("capabilities")
    if type(rows) is not list or len(rows) != 4:
        raise ValueError("CAPABILITY_COUNT")
    for i, row in enumerate(rows):
        if (type(row) is not dict or row.get("name") != NAMES[i]
            or row.get("skill") != SKILLS[i] or row.get("owner") != OWNERS[i]
            or row.get("status") != "OFF_BY_DEFAULT"
            or row.get("runtime") != RUNTIMES[i]
            or not isinstance(row.get("source"), str)
            or not row["source"].startswith("https://github.com/")
            or not isinstance(row.get("license_review"), str)):
            raise ValueError("UNSAFE_CAPABILITY_ROUTE")
    return obj


def penpot_token_diff(design: dict, implementation: dict) -> dict:
    """Compare sanitized offline token exports; not a pixel or accessibility PASS."""
    def normalize(obj: object) -> dict:
        if type(obj) is not dict or not 1 <= len(obj) <= 200:
            raise ValueError("INVALID_TOKEN_SET")
        clean = {}
        for key, value in obj.items():
            if type(key) is not str or not SAFE_KEY.fullmatch(key):
                raise ValueError("INVALID_TOKEN_NAME")
            if type(value) not in (str, int, float):
                raise ValueError("INVALID_TOKEN_VALUE")
            if type(value) is float and not math.isfinite(value):
                raise ValueError("INVALID_TOKEN_VALUE")
            if type(value) is str:
                _safe_text(value, 120)
            clean[key] = value
        return clean
    left, right = normalize(design), normalize(implementation)
    mismatches = sorted(k for k in left.keys() | right.keys()
                        if left.get(k) != right.get(k) or (k in left) != (k in right))
    return {"status": "TOKEN_MATCH_ONLY" if not mismatches else "TOKEN_DRIFT",
            "checked": len(left.keys() | right.keys()),
            "mismatched": mismatches, "browser_visual_proof": "NOT_RUN",
            "penpot_mcp_session": "NOT_CONNECTED", "release": "BLOCKED"}


def whisper_transcript_gate(segments: list) -> dict:
    """Validate a local Whisper-style transcript, not audio recognition accuracy."""
    if type(segments) is not list or not 1 <= len(segments) <= 500:
        raise ValueError("INVALID_SEGMENTS")
    end_of_last = 0.0
    digest = hashlib.sha256()
    for seg in segments:
        if type(seg) is not dict or set(seg) != {"start", "end", "text"}:
            raise ValueError("INVALID_SEGMENT_FIELDS")
        start, end = seg["start"], seg["end"]
        if (type(start) not in (int, float) or type(end) not in (int, float)
            or not math.isfinite(start) or not math.isfinite(end)
            or start < end_of_last or end <= start or end > 21600):
            raise ValueError("INVALID_TIMESTAMPS")
        text = _safe_text(seg["text"], 1200)
        end_of_last = float(end)
        digest.update(json.dumps([start, end, text], ensure_ascii=False).encode())
    return {"status": "TRANSCRIPT_STRUCTURE_PASS", "segments": len(segments),
            "content_sha256": digest.hexdigest(),
            "audio_recognition_accuracy": "NOT_MEASURED",
            "whisper_runtime": "NOT_CONNECTED", "release": "BLOCKED"}


def ollama_loopback_probe(model: str, instruction: str, *,
                          approved: bool = False, synthetic: bool = False,
                          transport=None) -> dict:
    """One bounded explicit local request; never an independent model quality PASS."""
    if approved is not True or synthetic is not True:
        raise PermissionError("EXPLICIT_SYNTHETIC_LOCAL_APPROVAL_REQUIRED")
    if type(model) is not str or not SAFE_MODEL.fullmatch(model):
        raise ValueError("UNSAFE_MODEL_NAME")
    prompt = _safe_text(instruction, 1000)
    payload = json.dumps({"model": model, "stream": False,
                          "messages": [{"role": "user", "content": prompt}],
                          "options": {"num_predict": 128}}, ensure_ascii=False).encode()
    request = urllib.request.Request(
        "http://127.0.0.1:11434/api/chat", data=payload,
        headers={"Content-Type": "application/json"}, method="POST")
    opener = urllib.request.urlopen if transport is None else transport
    with opener(request, timeout=4) as response:
        raw = response.read(16385)
    if len(raw) > 16384:
        raise ValueError("OVERSIZED_LOCAL_RESPONSE")
    result = json.loads(raw)
    answer = result.get("message", {}).get("content") if type(result) is dict else None
    if type(answer) is not str:
        raise ValueError("INVALID_MODEL_RESPONSE")
    _safe_text(answer, 12000)
    return {"status": "LOCAL_RESPONSE_UNVERIFIED",
            "response_sha256": hashlib.sha256(answer.encode()).hexdigest(),
            "model_calls": 1, "independent_review": "NOT_RUN",
            "comparative_quality": "NOT_MEASURED", "release": "BLOCKED"}


def n8n_review_event(event: str, fields: dict, *,
                     approved: bool = False, dispatch: bool = False,
                     transport=None) -> dict:
    """Plan by default; dispatch only a synthetic review event on loopback."""
    if event not in ("review_requested", "ci_finished") or type(fields) is not dict:
        raise ValueError("UNSUPPORTED_EVENT")
    if set(fields) != {"sha", "run_id", "status"}:
        raise ValueError("UNSAFE_EVENT_FIELDS")
    if (type(fields["sha"]) is not str
        or not re.fullmatch(r"[a-f0-9]{40}", fields["sha"])
        or type(fields["run_id"]) is not int or not 0 < fields["run_id"] < 10**15
        or fields["status"] not in ("PASS", "PARTIAL", "FAIL", "BLOCKED")):
        raise ValueError("UNSAFE_EVENT_VALUES")
    if not dispatch:
        return {"status": "EVENT_PLAN_ONLY", "event": event,
                "sent": False, "release": "BLOCKED"}
    if approved is not True:
        raise PermissionError("EXPLICIT_LOCAL_EVENT_APPROVAL_REQUIRED")
    body = json.dumps({"event": event, **fields}, separators=(",", ":")).encode()
    request = urllib.request.Request(
        "http://127.0.0.1:5678/webhook/jteam-review-only",
        data=body, headers={"Content-Type": "application/json"}, method="POST")
    opener = urllib.request.urlopen if transport is None else transport
    with opener(request, timeout=4) as response:
        status = response.getcode()
        if response.read(4097) and status not in (200, 201, 202, 204):
            raise ValueError("N8N_BAD_RESPONSE")
    if status not in (200, 201, 202, 204):
        raise ValueError("N8N_HTTP_FAILED")
    return {"status": "LOCAL_EVENT_SENT_UNVERIFIED_DOWNSTREAM",
            "sent": True, "external_actions_verified": False,
            "release": "BLOCKED"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if not args.check:
        parser.error("only --check is safe by default")
    try:
        contract = inspect_manifest()
    except (OSError, ValueError, PermissionError):
        print(json.dumps({"status": "BLOCKED", "reason": "CAPABILITY_CONTRACT_FAILED"}))
        return 3
    print(json.dumps({"status": "OFFLINE_SKILL_ROUTING_PASS",
                      "names": [x["name"] for x in contract["capabilities"]],
                      "external_tools_installed": False,
                      "real_ollama_calls": 0,
                      "penpot_connected": False, "whisper_transcribed": False,
                      "n8n_events_sent": 0, "release": "BLOCKED"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
