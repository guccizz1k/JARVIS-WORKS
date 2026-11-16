#!/usr/bin/env python3
"""Prove the <=5-hour SQL limit on a disposable PostgreSQL 17 server ONLY.

No Supabase contact, no real credentials, no remote role change.
Do not run this against a production or development database.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROLE = "jw_backup_ro"
EXPIRED = "2026-11-11 09:00:00+09"
SQLS = (
    ROOT / "scripts/review/cinema_pg_v223_backup_role_renew_20261111.sql",
    ROOT / "scripts/review/cinema_pg_v223_backup_role_temporary_login_20261111.sql",
)


def exec_psql(*, statement: str | None = None, file: Path | None = None,
              until: str | None = None) -> subprocess.CompletedProcess[str]:
    if (statement is None) == (file is None):
        raise RuntimeError("one SQL source required")
    args = ["psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-d", "postgres"]
    if until is not None:
        args += ["-v", "valid_until=" + until]
    if statement is not None:
        args += ["-c", statement]
    else:
        args += ["-f", str(file)]
    return subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)


def sql(statement: str) -> str:
    result = exec_psql(statement=statement)
    if result.returncode:
        raise AssertionError("disposable SQL query failed")
    return result.stdout.strip()


def timestamp(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%d %H:%M:%S+00")


def facts() -> str:
    return sql("SELECT (CASE WHEN rolcanlogin THEN '1' ELSE '0' END) || '|' || "
               "COALESCE(rolvaliduntil::text,'NULL') FROM pg_roles "
               "WHERE rolname='jw_backup_ro'")


def reset() -> None:
    sql("ALTER ROLE jw_backup_ro NOLOGIN VALID UNTIL '2000-01-01 00:00:00+00'")


def run_case(source: Path, directory: Path) -> int:
    original = source.read_text(encoding="utf-8")
    if original.count(EXPIRED) != 4 or original.count("interval ''5 hours''") != 1:
        raise AssertionError("source SQL is not pinned to exactly one 5-hour check")
    test_path = directory / source.name
    test_path.write_text(original.replace(EXPIRED, timestamp(timedelta(hours=24))), encoding="utf-8")
    test_path.chmod(0o600)

    checks = 0
    reset()
    initial = facts()

    # A request beyond five hours must be rejected by PostgreSQL itself,
    # without changing rolcanlogin or the existing expiry.
    too_long = exec_psql(file=test_path, until=timestamp(timedelta(hours=5, minutes=5)))
    if too_long.returncode == 0 or facts() != initial:
        raise AssertionError("server accepted >5h or changed role before rejecting")
    checks += 1

    # A request within five hours but beyond the specific absolute owner
    # deadline must also fail atomically.
    short_path = directory / ("short-" + source.name)
    short_path.write_text(
        original.replace(EXPIRED, timestamp(timedelta(hours=2))), encoding="utf-8"
    )
    short_path.chmod(0o600)
    past_owner_limit = exec_psql(file=short_path, until=timestamp(timedelta(hours=4)))
    if past_owner_limit.returncode == 0 or facts() != initial:
        raise AssertionError("server bypassed the absolute owner deadline")
    checks += 1

    # The historical approval has expired; the original file itself must
    # remain fail closed without writing even in this disposable database.
    expired = exec_psql(file=source, until=timestamp(timedelta(hours=1)))
    if expired.returncode == 0 or facts() != initial:
        raise AssertionError("expired approval was accepted")
    checks += 1

    # An omitted variable must fail closed.
    missing = exec_psql(file=test_path)
    if missing.returncode == 0 or facts() != initial:
        raise AssertionError("missing psql variable was accepted")
    checks += 1

    # A strictly sub-five-hour window must work in the disposable test DB.
    valid = exec_psql(file=test_path, until=timestamp(timedelta(hours=4, minutes=50)))
    if valid.returncode != 0:
        raise AssertionError("valid sub-five-hour test window rejected")
    expected_login = source.name.endswith("temporary_login_20261111.sql")
    current = facts()
    if not current.startswith(("1|" if expected_login else "0|")) or current == initial:
        raise AssertionError("server success state is wrong")
    checks += 1
    reset()
    if facts() != initial:
        raise AssertionError("synthetic account was not returned to NOLOGIN")
    checks += 1
    return checks


def main() -> int:
    if not (
        os.environ.get("JW_CINEMA_PG_DISPOSABLE") == "1"
        and os.environ.get("PGHOST") == "127.0.0.1"
        and os.environ.get("PGPORT") == "5435"
        and os.environ.get("PGUSER") == "postgres"
        and os.environ.get("PGPASSWORD") == "ci-only-v223-preflight"
        and sql("SHOW server_version_num").startswith("17")
    ):
        raise SystemExit("BLOCKED: requires the pinned throw-away PG17 CI service")
    if sql("SELECT count(*) FROM pg_roles WHERE rolname='jw_backup_ro'") != "0":
        raise SystemExit("BLOCKED: existing role, never overwrite or drop it")
    created = False
    try:
        sql("CREATE ROLE jw_backup_ro NOLOGIN NOINHERIT NOBYPASSRLS NOSUPERUSER "
            "NOCREATEROLE NOCREATEDB NOREPLICATION")
        created = True
        with tempfile.TemporaryDirectory(prefix="jw-v223-5h-") as temp:
            count = sum(run_case(path, Path(temp)) for path in SQLS)
        print(f"PASS_V223_5H_DB_SERVER_LIMIT checks={count} failures=0 synthetic_only=true")
        return 0
    finally:
        if created:
            reset()
            sql("DROP ROLE jw_backup_ro")


if __name__ == "__main__":
    raise SystemExit(main())
