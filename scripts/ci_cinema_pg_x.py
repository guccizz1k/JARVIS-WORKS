#!/usr/bin/env python3
"""Safely resume *only* the existing marked, disposable local PG17 restore target.

No Supabase network calls, no new database/container, no secret output.
Only after proving the original localhost-bound container + its exact private
marker may the existing encrypted backup restoration run. Supports Codespaces
resuming from a stopped Docker daemon. No production operations.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.ci_cinema_pg_m import read_private_target
from scripts.ci_cinema_pg_r import CONTAINER, LOCAL_PORT
from scripts.pg_backup_v223 import BackupError, verify_ephemeral_target

PG_PORT = "5432/tcp"
DOCKER_TIMEOUT = 12

def docker(*args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True,
                              timeout=DOCKER_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackupError("BLOCKED_LOCAL_DOCKER_UNAVAILABLE") from None

def verified_container(info: dict) -> bool:
    """Only our exact localhost disposable PG17 target; never touch other containers."""
    if not isinstance(info, dict):
        return False
    cfg = info.get("Config") or {}
    host = info.get("HostConfig") or {}
    ports = host.get("PortBindings") or {}
    binds = ports.get(PG_PORT)
    state = info.get("State") or {}
    return (
        info.get("Name") == "/" + CONTAINER
        and cfg.get("Image") == "postgres:17"
        and isinstance(binds, list)
        and len(binds) == 1
        and binds[0] == {"HostIp": "127.0.0.1", "HostPort": str(LOCAL_PORT)}
        and (host.get("RestartPolicy") or {}).get("Name") in ("no", "")
        and host.get("Privileged") is False
        and host.get("PublishAllPorts") is False
        and not state.get("Dead", False)
        and not state.get("Removing", False)
    )

def inspect_target() -> dict:
    result = docker("inspect", "--type", "container", CONTAINER)
    if result.returncode:
        raise BackupError("BLOCKED_ORIGINAL_RESTORE_CONTAINER_MISSING")
    try:
        data = json.loads(result.stdout)
        if not isinstance(data, list) or len(data) != 1:
            raise ValueError("unexpected Docker inspect shape")
        info = data[0]
    except (ValueError, TypeError, KeyError):
        raise BackupError("BLOCKED_CONTAINER_INSPECTION_INVALID") from None
    if not verified_container(info):
        raise BackupError("BLOCKED_CONTAINER_IDENTITY_OR_LOCAL_PORT_MISMATCH")
    return info

def connect_marked(dsn: str, token: str) -> bool:
    import psycopg
    try:
        with psycopg.connect(dsn, connect_timeout=3) as conn:
            verify_ephemeral_target(conn, token)
        return True
    except BackupError:
        raise
    except (psycopg.OperationalError, OSError):
        return False

def ensure_local_target() -> None:
    if os.environ.get("CODESPACES") != "true":
        raise BackupError("BLOCKED_APPROVED_CODESPACE_REQUIRED")
    # Parse PRIVATE secret file without ever printing or writing its contents.
    cfg = read_private_target()
    info = inspect_target()
    if not info.get("State", {}).get("Running"):
        result = docker("start", CONTAINER)
        if result.returncode:
            raise BackupError("BLOCKED_EXISTING_TARGET_START_FAILED")
        print("PASS_EXISTING_DISPOSABLE_TARGET_STARTED")
    else:
        print("PASS_EXISTING_DISPOSABLE_TARGET_RUNNING")
    # A stopped Codespace can require a short startup, bounded to 24 seconds.
    for _ in range(8):
        if connect_marked(cfg["JW_PG_TARGET_ADMIN_DSN"],
                          cfg["JW_PG_TARGET_EPHEMERAL_TOKEN"]):
            print("PASS_EXISTING_PG17_TARGET_MARKER_VERIFIED")
            return
        time.sleep(3)
    raise BackupError("BLOCKED_EXISTING_PG17_NOT_REACHABLE")

def main() -> int:
    try:
        ensure_local_target()
    except Exception as e:
        # Failure details may contain sensitive DSNs: output ONLY stable status codes.
        label = str(e) if isinstance(e, BackupError) else "UNEXPECTED_" + type(e).__name__
        if not label.startswith(("BLOCKED_", "FAIL_", "UNEXPECTED_")):
            label = "BLOCKED_UNKNOWN_LOCAL_TARGET_FAILURE"
        print("LOCAL_RESTORE_TARGET=" + label)
        print("SOURCE_DB_NOT_CONTACTED")
        return 2
    from scripts.ci_cinema_pg_w import main as restore
    return restore()

if __name__ == "__main__":
    sys.exit(main())
