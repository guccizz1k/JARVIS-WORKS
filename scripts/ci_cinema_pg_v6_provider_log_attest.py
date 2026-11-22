#!/usr/bin/env python3
"""Validate a separately retrieved Supabase server-side authentication denial.

This is an INDEPENDENT historical provider-log attestation, not a replacement
for the original pinned runner, and not a provider-signed log receipt.
No database mutation, role activation or backup occurs here.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence/jarvisworks/v6_20261122_server_login_refusal.json"
PROJECT = "rvymwwzclagvljnofyss"
BACKUP_SHA = "175fb490bc2a3236db4d14026c5ca9c2f268729a"
ROLE = "jw_backup_ro"

class ProviderProofBlocked(Exception):
    pass


def instant(s: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise ValueError("not a UTC time")
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, AttributeError):
        raise ProviderProofBlocked("invalid_provider_event_time") from None


def verify_snapshot(snapshot: dict) -> dict:
    """Fail closed for altered identity, invalid ordering, missing events or
    any status other than a server-side 28000 explicit role login denial."""
    if not isinstance(snapshot, dict):
        raise ProviderProofBlocked("invalid_evidence_structure")
    expected = {
        "schema": "jarvis-works.v6.provider-auth-refusal-evidence.v1",
        "project_id": PROJECT,
        "project_name": "jarvis-works-dev",
        "db_name": "postgres",
        "pg_version_num": 170011,
        "original_backup_run_sha": BACKUP_SHA,
        "original_runner_verdict": "BLOCKED",
        "cryptographically_provider_signed": False,
    }
    for key, value in expected.items():
        if type(snapshot.get(key)) is not type(value) or snapshot.get(key) != value:
            raise ProviderProofBlocked("source_identity_or_verdict_mismatch")
    if "Supabase connected query_logs" not in snapshot.get("source", ""):
        raise ProviderProofBlocked("source_is_not_provider_log")
    bounds = snapshot.get("log_query_window_utc")
    if not isinstance(bounds, dict):
        raise ProviderProofBlocked("invalid_event_window")
    start, end = instant(bounds.get("start")), instant(bounds.get("end"))
    if (start != instant("2026-11-22T14:15:00Z")
            or end != instant("2026-11-22T14:22:00Z")):
        raise ProviderProofBlocked("unexpected_event_window")
    events = snapshot.get("log_events")
    if not isinstance(events, list) or len(events) != 2:
        raise ProviderProofBlocked("event_count_mismatch")
    killed, denied = events
    if not isinstance(killed, dict) or not isinstance(denied, dict):
        raise ProviderProofBlocked("invalid_provider_event")
    common = {"source": "postgres_logs", "user": ROLE, "severity": "FATAL"}
    for e in events:
        if any(e.get(key) != val for key,val in common.items()):
            raise ProviderProofBlocked("event_identity_mismatch")
        if not isinstance(e.get("session_id"), str) or len(e["session_id"]) < 8:
            raise ProviderProofBlocked("event_session_missing")
    if (killed.get("sqlstate") != "57P01"
        or killed.get("message") != "terminating connection due to administrator command"
        or denied.get("sqlstate") != "28000"
        or denied.get("message") != 'role "jw_backup_ro" is not permitted to log in'
        or killed["session_id"] == denied["session_id"]):
        raise ProviderProofBlocked("real_authentication_refusal_not_proven")
    t1, t2 = instant(killed.get("timestamp")), instant(denied.get("timestamp"))
    if not (start <= t1 < t2 <= end and t2 - t1 <= timedelta(seconds=1)):
        raise ProviderProofBlocked("event_sequence_mismatch")
    role = snapshot.get("catalog_observation")
    expected_role = {
        "role": ROLE, "can_login": False, "password_expired": True,
        "active_sessions": 0, "bypassrls": True, "superuser": False,
        "createrole": False, "createdb": False, "replication": False,
        "connection_limit": 2,
    }
    if not isinstance(role, dict):
        raise ProviderProofBlocked("role_catalog_missing")
    for key,value in expected_role.items():
        if type(role.get(key)) is not type(value) or role.get(key) != value:
            raise ProviderProofBlocked("role_catalog_mismatch")
    return {
        "source": "SUPABASE_PROVIDER_LOG_SNAPSHOT",
        "provider_signed": False,
        "event_utc": t2.isoformat(),
        "sqlstate": "28000",
        "role": ROLE,
        "server_refusal": "explicit_role_login_prohibited",
        "retained_original_verdict": "BLOCKED",
    }


def verify_saved() -> dict:
    if EVIDENCE.is_symlink() or not EVIDENCE.is_file():
        raise ProviderProofBlocked("evidence_missing")
    if EVIDENCE.stat().st_size > 12_000:
        raise ProviderProofBlocked("evidence_size_unexpected")
    return verify_snapshot(json.loads(EVIDENCE.read_text(encoding="utf-8")))


def main():
    try:
        from scripts import ci_cinema_pg_v6_owner_readonly as pin
        pin.verify_sources()
        verify_saved()
        print("V6_PROVIDER_LOG_HISTORICAL_AUTH_REFUSAL_PASS")
        print("ORIGINAL_B2_B3_BLOCKED_RECEIPT_UNCHANGED")
        print("PROVIDER_LOG_NOT_CRYPTOGRAPHICALLY_SIGNED")
        return 0
    except BaseException as exc:
        allowed = {
            "invalid_provider_event_time", "invalid_evidence_structure",
            "source_identity_or_verdict_mismatch", "source_is_not_provider_log",
            "invalid_event_window", "unexpected_event_window",
            "event_count_mismatch", "invalid_provider_event",
            "event_identity_mismatch", "event_session_missing",
            "real_authentication_refusal_not_proven", "event_sequence_mismatch",
            "role_catalog_missing", "role_catalog_mismatch",
            "evidence_missing", "evidence_size_unexpected",
        }
        label = str(exc) if isinstance(exc, ProviderProofBlocked) else type(exc).__name__
        print("V6_PROVIDER_LOG_ATTESTATION_BLOCKED",
              label if label in allowed else type(exc).__name__)
        return 2
    finally:
        print("NO_DB_CHANGE_NO_BACKUP")
if __name__ == "__main__":
    raise SystemExit(main())
