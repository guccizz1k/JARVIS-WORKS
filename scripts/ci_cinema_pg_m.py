#!/usr/bin/env python3
"""Mark the approved disposable local PostgreSQL 17 restore target. No source DB access."""
from __future__ import annotations

import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.ci_cinema_pg_r import SECRET_FILE
from scripts.pg_backup_v223 import (
    BackupError,
    evaluate_target_facts,
    fetch_target_facts,
    provision_ephemeral_marker,
    verify_ephemeral_target,
)

_ALLOWED = {
    "JW_PG_TARGET_ADMIN_DSN",
    "JW_PG_TARGET_EPHEMERAL_TOKEN",
    "JW_PG_CI_ALLOW",
}


def read_private_target(path: Path = SECRET_FILE) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("local target configuration unavailable")
    st = path.stat()
    if st.st_mode & 0o077 or st.st_uid != os.getuid():
        raise ValueError("local target configuration permissions unsafe")
    parsed: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"export ([A-Z_]+)='([^']+)'", line)
        if not match or match.group(1) not in _ALLOWED or match.group(1) in parsed:
            raise ValueError("invalid target configuration")
        parsed[match.group(1)] = match.group(2)
    if set(parsed) != _ALLOWED:
        raise ValueError("incomplete target configuration")
    if parsed["JW_PG_CI_ALLOW"] != "ONLY_EPHEMERAL_LOCAL_DATABASE":
        raise ValueError("target guard disabled")
    dsn = parsed["JW_PG_TARGET_ADMIN_DSN"]
    from scripts.pg_backup_v223 import parse_dsn
    opts = parse_dsn(dsn)
    if (opts["host"], opts["port"], opts["dbname"], opts["user"]) != (
        "127.0.0.1", "55432", "postgres", "postgres"
    ):
        raise ValueError("target must be local 127.0.0.1:55432/postgres")
    if len(parsed["JW_PG_TARGET_EPHEMERAL_TOKEN"]) < 32:
        raise ValueError("target token too short")
    return parsed


def main() -> int:
    if os.getenv("CODESPACES") != "true":
        print("BLOCKED: mark only in approved Codespaces")
        return 2
    try:
        import psycopg
        cfg = read_private_target()
        dsn, token = cfg["JW_PG_TARGET_ADMIN_DSN"], cfg["JW_PG_TARGET_EPHEMERAL_TOKEN"]
        with psycopg.connect(dsn, connect_timeout=5) as conn:
            facts = fetch_target_facts(conn)
            # Fail closed if another operator already placed a different marker.
            if "jw_ephemeral_marker" in (facts.get("databases") or []):
                verify_ephemeral_target(conn, token)
                print("PASS: disposable PG17 marker already verified")
                return 0
            failures = evaluate_target_facts(facts, token, require_marker=False)
            if failures:
                raise ValueError("local target not provably empty: " + ",".join(failures))
        provision_ephemeral_marker(dsn, token)
        with psycopg.connect(dsn, connect_timeout=5) as conn:
            verify_ephemeral_target(conn, token)
        print("PASS: disposable PostgreSQL 17 marker created and verified")
        print("LOCAL_RESTORE_MARKED_ONLY: no Supabase connection, C change or backup executed")
        return 0
    except (OSError, ValueError, BackupError, psycopg.Error) as exc:
        # Never print error contents or DSNs, which may contain credentials.
        print("BLOCKED: local restore target marker check failed (" + type(exc).__name__ + ")")
        return 2


if __name__ == "__main__":
    sys.exit(main())
