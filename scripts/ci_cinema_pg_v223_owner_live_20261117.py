#!/usr/bin/env python3
"""Owner-only 2026-11-17 P1->P0 B2/B3 driver. Do not use expired 11-Nov approvals.

No live source mutation except the explicitly approved, short-lived LOGIN/VALID
UNTIL on existing jw_backup_ro, followed by mandatory NOLOGIN/session termination.
Actual pg_dump + encrypted independent PG17 restore are delegated to the PINNED
existing scripts.pg_backup_v223 engine. Never print DSNs, keys or row data.

The ``closed`` action performs only authentication-refusal/catalog checks;
it never activates or revokes a role and never invokes backup/restore.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from scripts import ci_cinema_pg_v223_codespace_run as existing
from scripts.ci_cinema_pg_s import load_dashboard_ca
from scripts.ci_cinema_pg_u import read_password_file
from scripts.pg_backup_v223 import load_key

ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "f6bd82cfeb127025aa35bbf591b3b984cc947716"
BRANCH = "review/jw-v223-72h-approval-20261117"
KST = ZoneInfo("Asia/Seoul")
OWNER_DEADLINE = datetime(2026, 11, 20, 16, 0, tzinfo=KST)
MAX_WINDOW = timedelta(hours=4, minutes=59)
ROLE_SQL = ROOT / "scripts/review/cinema_pg_v223_backup_role_20261117.sql"
# Reviewed constraint-deparser correction; every other protected engine stays
# at BASE_SHA. These are exact blobs, not a path-only exemption.
REVIEWED_BACKUP_FIX_BLOBS = {
    'scripts/pg_backup_v223.py':'d6578569100f88c7d2d3f493fdb06bbe3374c64f',
    'scripts/ci_cinema_pg_guard.py':'2805ab4be2fb22221d96752fc4316af50b0bb653',
    'scripts/ci_cinema_pg_v223_codespace_run.py':'220df3d99d78ccb37bac1185b847eb06944850bd',
}
# Only these paths may differ from the latest already reviewed/CI-passing code.
ALLOWED_NEW = frozenset({
    "scripts/review/cinema_pg_v223_backup_role_20261117.sql",
    "scripts/ci_cinema_pg_v223_owner_live_20261117.py",
    "tests/test_cinema_pg_v223_owner_live_20261117.py",
    ".github/workflows/jw-cinema-pg-v223-owner-live-20261117.yml",
    "scripts/ci_cinema_pg_v223_owner_worktree_20261117.py",
    "scripts/ci_cinema_pg_v223_codespace_run.py",
    'scripts/pg_backup_v223.py',
    'scripts/ci_cinema_pg_guard.py',
    'tests/test_cinema_pg_v223_constraint_canonical.py',
    'tests/test_cinema_pg_v223_acl_canonical.py',
    'scripts/ci_cinema_pg_v223_constraint_gate.py',
    '.github/workflows/jw-v223-jarvis-operational-20261116.yml',
})
SOURCE_PINNED = (
    "scripts/pg_backup_v223.py",
    "tests/test_v223_pg_backup.py",
    "scripts/ci_cinema_pg_guard.py",
    "scripts/ci_cinema_pg_v223_codespace_run.py",
    "scripts/ci_cinema_pg_m.py",
    "scripts/ci_cinema_pg_r.py",
    "scripts/ci_cinema_pg_q.py",
    "scripts/ci_cinema_pg_s.py",
    "scripts/ci_cinema_pg_u.py",
    "scripts/review/cinema_pg_v223_backup_role_revoke.sql",
)


class Blocked(Exception):
    pass


def git(*args: str) -> str:
    completed = subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                               text=True, timeout=35, check=False)
    if completed.returncode:
        raise Blocked("git_integrity_check_failed")
    return completed.stdout.strip()


def check_sources() -> None:
    """Prove the new driver/SQL didn't modify any original engine/UI/database."""
    if os.environ.get("CODESPACES") != "true":
        raise Blocked("approved_codespace_required")
    # A detached checkout is supported ONLY when it is the exact current
    # remote review SHA and its worktree is clean. This enables a temporary
    # worktree without deleting or stashing the owner\u0027s existing files.
    if git("branch", "--show-current") not in (BRANCH, ""):
        raise Blocked("wrong_review_branch")
    head = git("rev-parse", "HEAD")
    if git("rev-parse", "refs/remotes/origin/" + BRANCH) != head:
        raise Blocked("remote_sha_mismatch_fetch_first")
    git("merge-base", "--is-ancestor", BASE_SHA, "HEAD")
    changed = set(git("diff", "--name-only", BASE_SHA, "HEAD").splitlines())
    if not changed or not changed <= ALLOWED_NEW:
        raise Blocked("unexpected_changes_to_original_source")
    dirty = git("status", "--porcelain", "--untracked-files=all").splitlines()
    # Historically the owner's downloaded CA exists as this exact untracked path.
    if any(line != "?? .github/supabase-root-2021.cer" for line in dirty):
        raise Blocked("uncommitted_or_unexpected_file")
    for path in SOURCE_PINNED:
        expected = REVIEWED_BACKUP_FIX_BLOBS.get(path)
        if expected is None:
            expected = git("rev-parse", BASE_SHA + ":" + path)
        if git("rev-parse", "HEAD:" + path) != expected:
            raise Blocked("protected_engine_blob_changed")
    for path in changed:
        if git("hash-object", path) != git("rev-parse", "HEAD:" + path):
            raise Blocked("review_file_not_exact_head")
    text = ROLE_SQL.read_text(encoding="utf-8")
    if (text.count("2026-11-20 16:00:00+09") != 1
        or "interval ''5 hours''" not in text
        or "ALTER ROLE jw_backup_ro VALID UNTIL :'valid_until' LOGIN" not in text
        or "BEGIN;" not in text or "COMMIT;" not in text):
        raise Blocked("role_sql_contract_invalid")



def inspect_source_pin() -> int:
    """Offline, non-mutating diagnostics; NEVER authorizes check/run/closed."""
    checks = (
        ("CODESPACE", lambda: os.environ.get("CODESPACES") == "true"),
        ("REVIEW_BRANCH", lambda: git("branch", "--show-current") in (BRANCH, "")),
        ("REMOTE_SHA", lambda: git("rev-parse", "HEAD") ==
         git("rev-parse", "refs/remotes/origin/" + BRANCH)),
        ("BASE_ANCESTRY", lambda: git("merge-base", "--is-ancestor", BASE_SHA, "HEAD") == ""),
        ("ALLOWED_PATHS", lambda: bool(
            (paths := set(git("diff", "--name-only", BASE_SHA, "HEAD").splitlines()))
            and paths <= ALLOWED_NEW)),
        ("CLEAN_WORKTREE", lambda: all(
            line == "?? .github/supabase-root-2021.cer"
            for line in git("status", "--porcelain", "--untracked-files=all").splitlines())),
        ("PINNED_BLOBS", lambda: all(
            git("rev-parse", "HEAD:" + path) ==
            (REVIEWED_BACKUP_FIX_BLOBS.get(path) or git("rev-parse", BASE_SHA + ":" + path))
            for path in SOURCE_PINNED)),
        ("REVIEW_FILES", lambda: all(
            git("hash-object", path) == git("rev-parse", "HEAD:" + path)
            for path in git("diff", "--name-only", BASE_SHA, "HEAD").splitlines())),
        ("ROLE_SQL_CONTRACT", lambda: (
            ROLE_SQL.read_text(encoding="utf-8").count("2026-11-20 16:00:00+09") == 1
            and "interval ''5 hours''" in ROLE_SQL.read_text(encoding="utf-8")
            and "ALTER ROLE jw_backup_ro VALID UNTIL :'valid_until' LOGIN" in
            ROLE_SQL.read_text(encoding="utf-8"))),
    )
    failures = 0
    for name, predicate in checks:
        try:
            valid = bool(predicate())
        except Exception:
            valid = False
        print(("PASS " if valid else "BLOCKED ") + "SOURCE_PIN_" + name)
        failures += not valid
    print("NO_ROLE_CHANGE_NO_BACKUP")
    return 2 if failures else 0


def expiry_value(at: datetime | None = None) -> str:
    current = (at or datetime.now(timezone.utc)).astimezone(KST)
    if current >= OWNER_DEADLINE:
        raise Blocked("owner_approval_window_expired")
    until = min(OWNER_DEADLINE, current + MAX_WINDOW)
    if until <= current:
        raise Blocked("owner_approval_window_expired")
    return until.strftime("%Y-%m-%d %H:%M:%S+09")


def check_live_admin_state() -> None:
    """Read-only management-plane role check; never print DSN or PG error text."""
    import psycopg
    with psycopg.connect(os.environ["JW_PG_ADMIN_DSN"], connect_timeout=8) as c:
        c.execute("SET TRANSACTION READ ONLY")
        who = c.execute(
            "SELECT current_user,current_database(),current_setting('server_version_num')::int"
        ).fetchone()
        if who != ("postgres", "postgres", who[2]) or not (170000 <= who[2] < 180000):
            raise Blocked("wrong_admin_database_or_pg_version")
        role = c.execute(
            "SELECT rolcanlogin,rolvaliduntil <= now(),rolbypassrls,rolsuper,rolcreaterole,"
            "rolcreatedb,rolreplication,rolconnlimit FROM pg_roles WHERE rolname='jw_backup_ro'"
        ).fetchone()
        if role != (False, True, True, False, False, False, False, 2):
            raise Blocked("backup_role_attrs_not_safe")
        sessions = c.execute(
            "SELECT count(*) FROM pg_stat_activity WHERE usename='jw_backup_ro'"
        ).fetchone()[0]
        if sessions != 0:
            raise Blocked("backup_role_sessions_not_zero")
        tables = c.execute(
            "SELECT count(*),count(*) FILTER (WHERE has_table_privilege('jw_backup_ro',c.oid,'SELECT')) "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p')"
        ).fetchone()
        if tables != (65,65):
            raise Blocked("not_all_65_tables_readable")
        can_write = c.execute(
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p') "
            "AND (has_table_privilege('jw_backup_ro',c.oid,'INSERT') "
            "OR has_table_privilege('jw_backup_ro',c.oid,'UPDATE') "
            "OR has_table_privilege('jw_backup_ro',c.oid,'DELETE') "
            "OR has_table_privilege('jw_backup_ro',c.oid,'TRUNCATE'))"
        ).fetchone()[0]
        if can_write:
            raise Blocked("backup_role_can_write")


def verify_local_disposable_started() -> None:
    """Verify and restart ONLY the known owner-local PG17 if it was stopped.

    The original mobile readiness helper verifies Docker name, postgres:17
    image and strict 127.0.0.1:55432 mapping before any start. Never replace,
    recreate or reset a target, and never contact the source database here.
    """
    from scripts.ci_cinema_pg_go import ensure_local_docker_daemon, start_verified_disposable
    ensure_local_docker_daemon()
    if not start_verified_disposable():
        raise Blocked("approved_local_pg17_container_unavailable")


def preflight() -> None:
    # Emit fixed stage labels, not raw exceptions (which can embed a DSN,
    # password, host or file path). This prevents another opaque BLOCKED report.
    for label, check in (
        ("SOURCE_PIN", check_sources),
        ("APPROVAL_WINDOW", expiry_value),
        ("TOOLS", existing.check_tools),
        ("PRIVATE_INPUTS", existing.check_private_inputs),
        ("AES_KEY", load_key),
        ("CA_TLS", load_dashboard_ca),
        ("BACKUP_AUTH", read_password_file),
        # A Codespace can suspend an already-verified Docker container between
        # owner interactions. The target identity is checked BEFORE restarting.
        ("LOCAL_PG17_DOCKER", verify_local_disposable_started),
        ("LOCAL_PG17_TARGET", existing.stage_target),
        ("ADMIN_READONLY", check_live_admin_state),
    ):
        try:
            check()
        except Exception:
            raise Blocked("PREFLIGHT_" + label) from None


def check_closed_read_only() -> int:
    """Verify closure independently; never activate/revoke a role or run backup.

    Approval-window checks apply to activation, not to this bounded read-only
    authentication refusal + catalog verification. Keep source/private/TLS pins.
    """
    for label,check in (('SOURCE_PIN',check_sources),
                        ('PRIVATE_INPUTS',existing.check_private_inputs),
                        ('CA_TLS',load_dashboard_ca),('BACKUP_AUTH',read_password_file),
                        ('PROOF',existing.stage_prove_closed)):
        try:
            check()
        except Exception as error:
            code=label
            if label=='PROOF' and isinstance(error,existing.Blocked):
                message=str(error)
                if message.startswith('NEW LOGIN STILL WORKS'):
                    code='NEW_LOGIN_ACCEPTED'
                elif message.startswith('role not closed:'):
                    code='CATALOG_NOT_CLOSED'
                elif message.startswith('new_login_refusal_not_verified:'):
                    reason = message.partition('reason=')[2].partition(';')[0]
                    code = {
                        'network_failure': 'NETWORK_FAILURE',
                        'tls_failure': 'TLS_FAILURE',
                        'timeout': 'TIMEOUT',
                        'bad_credentials': 'BAD_CREDENTIALS',
                        'auth_unverified': 'AUTH_REFUSAL_UNVERIFIED',
                        'unknown': 'AUTH_REFUSAL_UNVERIFIED',
                    }.get(reason, 'AUTH_REFUSAL_UNVERIFIED')
                    # Emit only fixed reason labels, never libpq error text or secrets.
                    print('DIAGNOSTIC ROLE_CLOSURE_REASON_'+{
                        'network_failure': 'NETWORK',
                        'tls_failure': 'TLS',
                        'timeout': 'TIMEOUT',
                        'bad_credentials': 'BAD_CREDENTIALS',
                        'auth_unverified': 'AUTH_UNVERIFIED',
                        'unknown': 'UNKNOWN',
                    }.get(reason, 'UNKNOWN'))
            print('BLOCKED ROLE_CLOSURE_'+code)
            print('NO_ROLE_CHANGE_NO_BACKUP')
            return 2
    print('PASS ROLE_CLOSED_AND_NEW_LOGIN_REFUSED_READONLY')
    print('NO_ROLE_CHANGE_NO_BACKUP')
    return 0


def run_live() -> int:
    attempted = False
    passed = True
    results: dict[str, str] = {}
    try:
        try:
            preflight()
            print("PASS P1_ALL_PREFLIGHT_AND_LIVE_ADMIN_READONLY")
        except BaseException as err:
            print("BLOCKED " + (str(err) if isinstance(err, Blocked) else "PRE_ROLE_PREFLIGHT_UNEXPECTED_" + type(err).__name__))
            return 2
        # B2/B3 entry has a second no-charge, owner-present and date-limited approval.
        if not sys.stdin.isatty():
            print("BLOCKED OWNER_TTY_REQUIRED")
            return 2
        print("Verify Codespaces costs are zero and the owner approved backup access today.")
        if input("Type YES to run encrypted B2/B3 and auto-revoke the role: ").strip() != "YES":
            print("BLOCKED OWNER_LIVE_CONFIRMATION_REQUIRED")
            return 2
        expiry = expiry_value()
        attempted = True  # set BEFORE calling psql (server commit may precede client failure)
        try:
            done = existing.psql("JW_PG_ADMIN_DSN", ROLE_SQL, {"valid_until": expiry})
            if done.returncode != 0:
                raise Blocked("role_activation_uncertain")
            results["temporary_login"] = "PASS"
            print("PASS TEMPORARY_BOUNDED_LOGIN")
            existing.stage_login()
            results["restricted_tls_login"] = "PASS"
            print("PASS RESTRICTED_TLS_LOGIN")
            existing.stage_backup()
            results["real_encrypted_backup_independent_restore"] = "PASS"
            print("PASS REAL_ENCRYPTED_BACKUP_AND_INDEPENDENT_RESTORE")
        except BaseException as err:
            passed = False
            print("BLOCKED B2_B3_STAGE_" + type(err).__name__)
    finally:
        if attempted:
            try:
                existing.stage_revoke()
                results["revoke"] = "PASS"
                print("PASS NOLOGIN_REVOKE_APPLIED")
            except BaseException as err:
                passed = False
                print("URGENT NOLOGIN_REVOKE_NOT_VERIFIED_" + type(err).__name__)
            try:
                existing.stage_prove_closed()
                results["closed_verified"] = "PASS"
                print("PASS ROLE_CLOSED_AND_NEW_LOGIN_REFUSED")
            except BaseException as err:
                passed = False
                print("URGENT ROLE_CLOSURE_NOT_VERIFIED_" + type(err).__name__)
            # Save result as private file, never overwrite previous evidence.
            directory = existing.SUMMARY_FILE.parent
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            path = directory / ("owner_b2b3_20261117_" + stamp + ".json")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"verdict": "PASS" if passed and len(results)==5 else "BLOCKED",
                           "stages": results, "sha": git("rev-parse", "HEAD")}, f)
    good = passed and len(results)==5
    print("B2_B3_" + ("PASS" if good else "BLOCKED"))
    return 0 if good else 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("check", "run", "closed", "inspect"))
    args = parser.parse_args()
    if args.action == 'inspect':
        return inspect_source_pin()
    if args.action == 'closed':
        return check_closed_read_only()
    if args.action == "run":
        try:
            return run_live()
        except BaseException as err:
            print("BLOCKED OWNER_LAUNCHER_" + type(err).__name__)
            return 2
    try:
        preflight()
        print("P1_READINESS_PASS; NO_ROLE_CHANGE_NO_BACKUP_YET")
        return 0
    except BaseException as err:
        print("BLOCKED " + (str(err) if isinstance(err, Blocked) else "P1_PREFLIGHT_UNEXPECTED_" + type(err).__name__))
        print("NO_ROLE_CHANGE_NO_BACKUP")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
