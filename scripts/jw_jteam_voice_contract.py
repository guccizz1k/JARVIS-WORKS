"""Fail-closed Korean dual-character voice casting gate for J team Reels."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAST_PATH = ROOT / "agents/team/jarvis_v1/creator/voice_cast_pengpeng_gomi.json"
SPEAKERS = ("pengpeng", "gomi")
EXPECTED_SEX = {"pengpeng": "female", "gomi": "male"}
EXPECTED_NAME = {"pengpeng": "펭펭", "gomi": "고미"}


def load_cast(path: Path = CAST_PATH) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16000:
        raise ValueError("UNSAFE_VOICE_CAST")
    data = json.loads(path.read_text(encoding="utf-8"))
    if type(data) is not dict or data.get("schema") != "jw-creator-dual-korean-voices-v1":
        raise ValueError("BAD_VOICE_CAST_SCHEMA")
    if data.get("locale") != "ko-KR" or set(data.get("cast", {})) != set(SPEAKERS):
        raise ValueError("BAD_KOREAN_SPEAKERS")
    for speaker in SPEAKERS:
        value = data["cast"][speaker]
        if value.get("name") != EXPECTED_NAME[speaker] or value.get("voice_gender") != EXPECTED_SEX[speaker]:
            raise ValueError("WRONG_CHARACTER_VOICE")
    if data.get("single_voice_for_both") is not False:
        raise ValueError("SHARED_VOICE_FORBIDDEN")
    if data.get("publish_status") != "BLOCKED_UNTIL_TWO_VOICES_VERIFIED":
        raise ValueError("UNSAFE_PUBLISH_STATUS")
    lines = data.get("dialogue")
    if type(lines) is not list or len(lines) < 6:
        raise ValueError("INVALID_DIALOGUE")
    if set(line.get("speaker") for line in lines) != set(SPEAKERS):
        raise ValueError("MISSING_SPEAKER")
    for line in lines:
        if type(line) is not dict or type(line.get("text")) is not str or not 2 <= len(line["text"]) <= 180:
            raise ValueError("INVALID_LINE")
        if not re.search(r"[가-힣]", line["text"]):
            raise ValueError("KOREAN_LINE_REQUIRED")
    return data


def require_distinct_verified_voices(cast: dict, voices: dict) -> None:
    """Gate before rendering/publishing; unverified provider/language => reject."""
    for speaker in SPEAKERS:
        selection = voices.get(speaker)
        if type(selection) is not dict:
            raise PermissionError("VOICE_NOT_SELECTED")
        if selection.get("verified_korean_naturalness") is not True:
            raise PermissionError("KOREAN_VOICE_UNVERIFIED")
        if selection.get("voice_gender") != EXPECTED_SEX[speaker]:
            raise PermissionError("WRONG_VOICE_GENDER")
        if not isinstance(selection.get("voice_id"), str) or not selection["voice_id"].strip():
            raise PermissionError("INVALID_VOICE_ID")
        if not isinstance(selection.get("audio_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", selection["audio_sha256"]):
            raise PermissionError("NO_AUDIO_EVIDENCE")
    if voices["pengpeng"]["voice_id"] == voices["gomi"]["voice_id"]:
        raise PermissionError("DUPLICATE_VOICE_ID")
    if voices["pengpeng"]["audio_sha256"] == voices["gomi"]["audio_sha256"]:
        raise PermissionError("DUPLICATE_AUDIO")
    if cast["publish_status"] != "BLOCKED_UNTIL_TWO_VOICES_VERIFIED":
        raise PermissionError("INVALID_CAST_POLICY")
