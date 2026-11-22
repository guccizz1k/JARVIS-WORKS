#!/usr/bin/env python3
"""2026-11-22 owner-only B2/B3 launcher. Never alter the 17-Nov driver.

Run ONLY in a clean, separately reviewed Codespace checkout of this branch.
The original engine owns backup, restore, and mandatory NOLOGIN cleanup.
No credentials or SQL values are printed.
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from scripts import ci_cinema_pg_v223_owner_live_20261117 as old

ROOT = Path(__file__).resolve().parents[1]
BASE = "6333b20dc77ae62d8325f47af38c30c71ecd941c"
BRANCH = "review/jw-b2b3-approval-20261122"
END = datetime(2026, 11, 22, 20, 50, 58, tzinfo=ZoneInfo("Asia/Seoul"))
SQL_PATH = "scripts/review/cinema_pg_v223_backup_role_20261122.sql"
DRIVER_PATH = "scripts/ci_cinema_pg_v223_owner_live_20261122.py"
TEST_PATH = "tests/test_cinema_pg_v223_owner_live_20261122.py"
NEW = frozenset((SQL_PATH, DRIVER_PATH, TEST_PATH))


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                            text=True, timeout=35, check=False)
    if result.returncode:
        raise old.Blocked("git_integrity_check_failed")
    return result.stdout.strip()


def check_sources() -> None:
    if os.environ.get("CODESPACES") != "true":
        raise old.Blocked("approved_codespace_required")
    if git("branch", "--show-current") != BRANCH:
        raise old.Blocked("wrong_review_branch")
    if git("rev-parse", "HEAD") != git("rev-parse", "refs/remotes/origin/" + BRANCH):
        raise old.Blocked("remote_sha_mismatch_fetch_first")
    git("merge-base", "--is-ancestor", BASE, "HEAD")
    if set(git("diff", "--name-only", BASE, "HEAD").splitlines()) != NEW:
        raise old.Blocked("unexpected_source_changes")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise old.Blocked("dirty_checkout")
    for path in old.SOURCE_PINNED:
        if git("rev-parse", "HEAD:" + path) != git("rev-parse", BASE + ":" + path):
            raise old.Blocked("protected_engine_blob_changed")
    for path in NEW:
        if git("hash-object", path) != git("rev-parse", "HEAD:" + path):
            raise old.Blocked("new_review_file_not_exact_head")
    sql = (ROOT / SQL_PATH).read_text(encoding="utf-8")
    if (sql.count("2026-11-22 20:50:58+09") != 1
            or "interval ''5 hours''" not in sql
            or "ALTER ROLE jw_backup_ro VALID UNTIL :'valid_until' LOGIN" not in sql
            or "BEGIN;" not in sql or "COMMIT;" not in sql):
        raise old.Blocked("role_sql_contract_invalid")


def expiry_value(at: datetime | None = None) -> str:
    current = (at or datetime.now(timezone.utc)).astimezone(END.tzinfo)
    if current >= END:
        raise old.Blocked("owner_approval_window_expired")
    until = min(END, current + timedelta(hours=4, minutes=59))
    if until <= current:
        raise old.Blocked("owner_approval_window_expired")
    return until.strftime("%Y-%m-%d %H:%M:%S+09")


def main() -> int:
    # Override only the date-scoped approval policy and source pin. Keep all
    # original backup/restore, credential, TLS, role, and cleanup implementations.
    old.check_sources = check_sources
    old.expiry_value = expiry_value
    old.ROLE_SQL = ROOT / SQL_PATH
    # Existing evidence directory is private; receipts retain original naming
    # but are not accepted as current-SHA independent acceptance without review.
    return old.main()


if __name__ == "__main__":
    raise SystemExit(main())
