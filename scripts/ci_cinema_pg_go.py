#!/usr/bin/env python3
"""Owner Codespace B2/B3 readiness: ONE safe mobile command, NO live source writes.

    python3 -m scripts.ci_cinema_pg_go

The owner has an untracked .github/supabase-root-2021.cer. Preserve it and the
strict original launcher guard: run the exact-HEAD checks in a fresh, temporary
Git worktree on a new local branch. This entry point NEVER renews the role,
contacts the live Supabase database or starts the backup. It never prints a
password, DSN, encryption key, or protected file contents.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = "refs/remotes/origin/review/jw-v223-b-renew-20261110"
PINNED_BASE = "6a1e993194e1fbe1f9cbb5f1571bc7bf85157b32"
SAFE_UNTRACKED = frozenset({".github/supabase-root-2021.cer"})
MAX_SECONDS = 160
CONTAINER = "jw-v223-restore"


def command(*argv: str, cwd: Path = ROOT, timeout: int = 40) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False)


def git(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess:
    return command("git", *args, cwd=cwd)


def classify_checkout_status(lines: str) -> str:
    """No ignored/tracked changes or unexpected untracked code, ever."""
    for entry in lines.splitlines():
        if entry.startswith("?? ") and entry[3:] in SAFE_UNTRACKED:
            continue
        return "UNEXPECTED_WORKTREE_CHANGE"
    return "OK"


def validate_owner_checkout() -> str:
    if os.environ.get("CODESPACES") != "true":
        raise ValueError("CODESPACE_REQUIRED")
    top = git("rev-parse", "--show-toplevel")
    if top.returncode or Path(top.stdout.strip()).resolve() != ROOT.resolve():
        raise ValueError("WRONG_REPOSITORY")
    st = git("status", "--porcelain", "--untracked-files=all")
    if st.returncode or classify_checkout_status(st.stdout) != "OK":
        raise ValueError("UNEXPECTED_WORKTREE_CHANGE")
    head = git("rev-parse", "HEAD")
    remote = git("rev-parse", UPSTREAM)
    branch = git("branch", "--show-current")
    if head.returncode or remote.returncode or branch.returncode:
        raise ValueError("GIT_REFERENCE_MISSING")
    if branch.stdout.strip() != "jwb":
        raise ValueError("WRONG_LOCAL_BRANCH")
    if head.stdout.strip() != remote.stdout.strip():
        raise ValueError("UPDATE_NEEDED_GIT_PULL_FF_ONLY")
    if git("merge-base", "--is-ancestor", PINNED_BASE, "HEAD").returncode:
        raise ValueError("PROTECTED_BASELINE_MISSING")
    return head.stdout.strip()


def ensure_local_docker_daemon() -> None:
    """Codespace-local Docker service only; never touch remote services."""
    if os.environ.get("CODESPACES") != "true":
        return
    if command("docker", "info", "--format", "{{.ServerVersion}}", timeout=8).returncode == 0:
        return
    # Idempotent service start, no apt installs, no new Docker containers.
    command("sudo", "-n", "service", "docker", "start", timeout=40)


def start_verified_disposable() -> bool:
    """May start ONLY the already-created, localhost-only, known PG17 container."""
    # Never accept an unrelated process on port 55432 as the approved target.
    # Validate Docker identity first even if pg_isready reports ready.
    # Never create, delete, reconfigure or publish a container. Stop if its
    # identity/port binding cannot be proven from read-only docker inspect.
    inspect = command("sudo", "-n", "docker", "inspect", CONTAINER, timeout=15)
    if inspect.returncode:
        return False
    try:
        found = json.loads(inspect.stdout)
        if len(found) != 1:
            return False
        obj = found[0]
        bindings = obj["HostConfig"]["PortBindings"]["5432/tcp"]
        if (obj["Name"] != "/" + CONTAINER or obj["Config"]["Image"] != "postgres:17"
                or bindings != [{"HostIp": "127.0.0.1", "HostPort": "55432"}]):
            return False
    except (KeyError, TypeError, ValueError, IndexError):
        return False
    if not obj["State"].get("Running", False):
        if command("sudo", "-n", "docker", "start", CONTAINER, timeout=30).returncode:
            return False
    # PostgreSQL 17 may need time for initdb and its first server restart.
    # Never interpret a running Docker daemon as a healthy PostgreSQL server.
    # The container must already exist with the exact approved local identity.
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if command("pg_isready", "-h", "127.0.0.1", "-p", "55432", timeout=6).returncode == 0:
            return True
        state = command("sudo", "-n", "docker", "inspect", "--format",
                        "{{.State.Running}}", CONTAINER, timeout=8)
        # An exited container cannot become ready by waiting. Fail closed;
        # preserve its filesystem/volume and do not attempt replacement.
        if state.returncode or state.stdout.strip().lower() != "true":
            return False
        time.sleep(1)
    return False


def diagnose_live_admin_login() -> str:
    """Read-only source check. Return fixed codes, never raw DB errors or secrets."""
    if os.environ.get("JW_OWNER_NO_CHARGE_VERIFIED") != "1":
        return "NO_CHARGE_NOT_CONFIRMED"
    try:
        import psycopg
        with psycopg.connect(os.environ["JW_PG_ADMIN_DSN"], connect_timeout=10) as conn:
            row = conn.execute(
                "SELECT current_user, current_database(), "
                "current_setting('server_version_num')::int, "
                "(SELECT (NOT rolcanlogin) AND rolvaliduntil <= " 
                "TIMESTAMPTZ '2026-11-11 09:00:00+09' "
                "AND NOT EXISTS (SELECT 1 FROM pg_stat_activity "
                "WHERE usename='jw_backup_ro') FROM pg_roles "
                "WHERE rolname='jw_backup_ro')"
            ).fetchone()
        if not row:
            return "EMPTY_IDENTITY_RESULT"
        if row[0] != "postgres":
            return "WRONG_ADMIN_ROLE"
        if row[1] != "postgres":
            return "WRONG_DATABASE"
        if not 170000 <= row[2] < 180000:
            return "WRONG_PG_VERSION"
        if row[3] is None:
            return "BACKUP_ROLE_NOT_FOUND_OR_UNSAFE_STATE"
        if row[3] is not True:
            return "BACKUP_ROLE_ACTIVE_OR_OUTSIDE_APPROVAL"
        return "PASS"
    except KeyError:
        return "ADMIN_DSN_MISSING"
    except Exception as exc:
        # SQLSTATE is a bounded protocol identifier, not an error message.
        state = getattr(exc, "sqlstate", None)
        if state == "28P01":
            return "PASSWORD_AUTH_REJECTED"
        if state == "28000":
            return "ROLE_AUTH_REJECTED"
        if state == "42501":
            return "INSUFFICIENT_PRIVILEGE"
        if state in ("3D000", "42P01", "42703"):
            return "DATABASE_SCHEMA_MISMATCH"
        if state in ("08001", "08006", "08004", "08000"):
            return "CONNECTION_REJECTED"
        if isinstance(exc, (TimeoutError, ConnectionError, OSError)):
            return "NETWORK_OR_TLS_FAILURE"
        return "DB_CONNECT_OR_QUERY_FAILURE"


def check_live_admin_login() -> bool:
    return diagnose_live_admin_login() == "PASS"


def private_blocker_codes(environ: dict | None = None) -> list[str]:
    """Identify private preflight blockers without ever printing secret values.

    Only emits fixed identifiers. Does NOT connect to a database, mutate files,
    echo credentials or log a traceback. This is diagnostic only and must NEVER
    replace the launcher's fail-closed check_private_inputs() enforcement.
    """
    import stat
    from urllib.parse import parse_qs, urlsplit
    from scripts import ci_cinema_pg_v223_codespace_run as runner
    from scripts.pg_backup_v223 import BackupError, parse_dsn

    env = os.environ if environ is None else environ
    codes: list[str] = []
    for name in runner.SECRET_ENV:
        if not env.get(name):
            codes.append("MISSING_" + name)

    for name, file in (
        ("BACKUP_AUTH", runner.CREDS),
        ("APPROVED_CA", runner.CERT_FILE),
        ("LOCAL_TARGET", runner.SECRET_FILE),
    ):
        try:
            if file.is_symlink() or not file.is_file():
                codes.append(name + "_FILE_MISSING_OR_LINK")
            elif file.stat().st_uid != os.getuid() or file.stat().st_mode & (
                stat.S_IRWXG | stat.S_IRWXO
            ):
                codes.append(name + "_FILE_PERMISSIONS")
        except (OSError, ValueError):
            codes.append(name + "_FILE_UNREADABLE")

    raw = env.get("JW_PG_ADMIN_DSN", "")
    if not raw:
        return codes
    # A literal placeholder may contain square brackets, which urlsplit can
    # reject before it reaches credential parsing. Classify it first.
    if any(marker in raw for marker in (
        "[YOUR-PASSWORD]", "[YOUR_PASSWORD]", "[YOUR-DB-PASSWORD]"
    )):
        codes.append("ADMIN_DSN_PASSWORD_MISSING_OR_PLACEHOLDER")
        return codes
    try:
        pieces = urlsplit(raw)
    except (TypeError, ValueError, UnicodeError):
        codes.append("ADMIN_DSN_URL_MALFORMED")
        return codes
    if pieces.fragment:
        codes.append("ADMIN_DSN_UNENCODED_HASH")
    # The shared parser raises its own BackupError on unsupported scheme or
    # absent hostname. Do not misreport these predictable input errors as an
    # unexpected parser crash; inspect only structural fields, never values.
    if pieces.scheme not in ("postgresql", "postgres"):
        codes.append("ADMIN_DSN_SCHEME")
        return codes
    try:
        hostname = pieces.hostname
    except (ValueError, TypeError):
        codes.append("ADMIN_DSN_URL_MALFORMED")
        return codes
    if not hostname:
        codes.append("ADMIN_DSN_HOST_MISSING")
        return codes
    try:
        parsed = parse_dsn(raw)
        qs = parse_qs(pieces.query, keep_blank_values=True)
    except BackupError:
        codes.append("ADMIN_DSN_STRUCTURE_REJECTED")
        return codes
    except (TypeError, ValueError, UnicodeError, KeyError, IndexError):
        codes.append("ADMIN_DSN_URL_MALFORMED")
        return codes
    except Exception:
        # Unexpected decoder failure; do not expose exception text.
        codes.append("ADMIN_DSN_PARSE_UNEXPECTED")
        return codes
    if parsed["sslmode"] != "verify-full":
        codes.append("ADMIN_DSN_SSLMODE")
    if parsed["sslrootcert"] != str(runner.CERT_FILE):
        codes.append("ADMIN_DSN_CA_PATH")
    if set(qs) != {"sslmode", "sslrootcert"} or any(len(v) != 1 for v in qs.values()):
        codes.append("ADMIN_DSN_QUERY_PARAMS")
    if not parsed["password"] or parsed["password"] in (
        "[YOUR-PASSWORD]", "[YOUR_PASSWORD]", "[YOUR-DB-PASSWORD]"
    ):
        codes.append("ADMIN_DSN_PASSWORD_MISSING_OR_PLACEHOLDER")

    approved_direct = parsed["host"] == f"db.{runner.PROJECT_REF}.supabase.co"
    approved_pooler = parsed["host"] == runner.HOST
    if not (approved_direct or approved_pooler):
        codes.append("ADMIN_DSN_HOST")
    expected_user = "postgres" if approved_direct else f"postgres.{runner.PROJECT_REF}"
    if parsed["user"] != expected_user:
        codes.append("ADMIN_DSN_USER")
    if parsed["port"] != str(runner.PORT):
        codes.append("ADMIN_DSN_PORT")
    if parsed["dbname"] != "postgres":
        codes.append("ADMIN_DSN_DATABASE")

    return list(dict.fromkeys(codes))


def inner(expect_sha: str, *, execute_live: bool = False) -> int:
    """Runs only inside the verified isolated checkout; does not contact Supabase."""
    from scripts import ci_cinema_pg_v223_codespace_run as runner
    from scripts import ci_cinema_pg_m as target
    from scripts import ci_cinema_pg_q as credentials
    from scripts import ci_cinema_pg_s as ca
    from scripts.pg_backup_v223 import load_key

    ensure_local_docker_daemon()
    try:
        runner.verify(expect_sha, need_private=False)
    except Exception:
        print("BLOCKED SHA_GUARD_TOOLS_OR_APPROVAL_WINDOW")
        return 2
    print("PASS EXACT_SHA_PROTECTED_GUARD_AND_TOOLS")

    checks = (
        ("PRIVATE_FILES_AND_ADMIN_DSN", runner.check_private_inputs),
        ("AES_256_GCM_KEY_LENGTH", load_key),
        ("TARGET_CONFIG_LOCAL_ONLY", target.read_private_target),
        ("SIGNED_SUPABASE_CA", ca.load_dashboard_ca),
    )
    blocked = False
    for label, func in checks:
        try:
            func()
        except Exception:
            print("BLOCKED " + label)
            if label == "PRIVATE_FILES_AND_ADMIN_DSN":
                for code in private_blocker_codes() or ["PRIVATE_INPUTS_UNCLASSIFIED"]:
                    print("BLOCKED PRIVATE_CAUSE_" + code)
            blocked = True
        else:
            print("PASS " + label)

    try:
        obj = json.loads(credentials.CREDS.read_text(encoding="utf-8"))
        if set(obj) != {"role", "password", "verifier"} or obj["role"] != credentials.ROLE:
            raise ValueError("credential structure mismatch")
        if not secrets.compare_digest(
            obj["verifier"],
            credentials.make_verifier(obj["password"], credentials.decode_salt(obj["verifier"]))
        ):
            raise ValueError("credential verification mismatch")
    except Exception:
        print("BLOCKED BACKUP_ROLE_AUTH_VERIFIER")
        blocked = True
    else:
        print("PASS BACKUP_ROLE_AUTH_VERIFIER")

    # Only the owner's LOCAL disposable database is queried, no Supabase.
    if start_verified_disposable():
        print("PASS LOCAL_PG17_READY")
        try:
            runner.stage_target()  # verifies marker/emptiness, or marks only an empty disposable DB
        except Exception:
            print("BLOCKED LOCAL_PG17_MARKER_OR_EMPTY")
            blocked = True
        else:
            print("PASS LOCAL_PG17_MARKER_VERIFIED")
    else:
        print("BLOCKED LOCAL_PG17_NOT_READY")
        blocked = True

    if blocked:
        print("B2_B3_NOT_RUN; NO_SUPABASE_DB_ACTION")
        print("PRIVATE_READINESS_BLOCKED")
        return 2
    print("PRIVATE_READINESS_PASS")
    if not execute_live:
        print("B2_B3_NOT_RUN; NO_SUPABASE_DB_ACTION")
        print("BILLING_AND_LIVE_SOURCE_AUTH_NOT_VERIFIED")
        return 0

    # TTY confirmation in the parent is required; never infer free usage from
    # a free Render service or from this repository's Actions usage.
    live_result = diagnose_live_admin_login()
    if live_result != "PASS":
        print("BLOCKED LIVE_ADMIN_READONLY_AUTH_OR_ROLE_STATE")
        print("BLOCKED LIVE_CAUSE_" + live_result)
        print("B2_B3_NOT_RUN; NO_SUPABASE_DB_CHANGE")
        return 2
    print("PASS LIVE_ADMIN_READONLY_AUTH_AND_DISABLED_ROLE")
    # Invoke the EXISTING hardened public entrypoint, including its two
    # confirmation gates. The runner writes only its owner-protected summary.
    import contextlib
    import io
    if runner.APPROVAL_COMMENT != "6755130318":
        print("BLOCKED APPROVAL_PIN_MISMATCH")
        return 2
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            old_stamp = runner.SUMMARY_FILE.stat().st_mtime_ns if runner.SUMMARY_FILE.exists() else -1
            code = runner.main([
                "all", "--expect-sha", expect_sha,
                "--confirm-approval", "6755130318", "--confirm-no-charge"
            ])
        # Never accept a prior run's report if a new run failed before writing.
        new_stamp = runner.SUMMARY_FILE.stat().st_mtime_ns
        if new_stamp <= old_stamp:
            raise ValueError("no current report")
        report = json.loads(runner.SUMMARY_FILE.read_text(encoding="utf-8"))
        if report.get("expect_sha") != expect_sha or (code and report.get("B2_B3") == "PASS"):
            raise ValueError("stale/mismatched run report")
    except Exception:
        print("BLOCKED OWNER_RUNNER_UNEXPECTED_FAILURE")
        print("VERIFY_ROLE_REVOCATION_MANUALLY")
        return 2
    for label, details in report.get("stages", {}).items():
        if label in {"target_ready", "renew", "live_login", "backup_restore_compare", "revoke", "prove_closed"}:
            print("STAGE " + label + " " + str(details.get("status", "NOT_RUN")))
    if report.get("stages", {}).get("renew", {}).get("status") == "PASS":
        closed = (report.get("stages", {}).get("revoke", {}).get("status") == "PASS"
                  and report.get("stages", {}).get("prove_closed", {}).get("status") == "PASS")
        if not closed:
            print("URGENT_ROLE_REVOCATION_NOT_VERIFIED")
    print("B2_B3_" + str(report.get("B2_B3", "BLOCKED_OR_FAIL")))
    return code


def outer(*, execute_live: bool = False) -> int:
    """Isolate the owner's untracked certificate without deleting or ignoring it."""
    try:
        head = validate_owner_checkout()
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        code = str(exc) if isinstance(exc, ValueError) else "LOCAL_GIT_UNAVAILABLE"
        print("BLOCKED " + code)
        print("B2_B3_NOT_RUN; NO_SUPABASE_DB_ACTION")
        return 2

    if execute_live:
        # A dedicated action, separate from owner approval of DB changes, is
        # required to attest that the current Codespaces session remains
        # inside the owner's no-charge quota.
        if not sys.stdin.isatty():
            print("BLOCKED BILLING_CONFIRMATION_REQUIRES_OWNER_TTY")
            return 2
        print("Check your GitHub Codespaces billing usage. Type YES only if the")
        print("current session will incur NO charge; otherwise enter anything else.")
        if input("No-charge verified? YES: ").strip() != "YES":
            print("BLOCKED NO_CHARGE_NOT_CONFIRMED")
            return 2

    branch = "jw-b-audit-" + secrets.token_hex(6)
    parent = Path(tempfile.mkdtemp(prefix="jw-b-verify-", dir="/tmp"))
    linked = False
    try:
        created = git("worktree", "add", "--quiet", "-b", branch, str(parent), head)
        if created.returncode:
            print("BLOCKED CANNOT_MAKE_ISOLATED_WORKTREE")
            return 2
        linked = True
        env = dict(os.environ)
        if execute_live:
            env["JW_OWNER_NO_CHARGE_VERIFIED"] = "1"
        check = subprocess.run(
            [sys.executable, "-m", "scripts.ci_cinema_pg_go",
             "_inner_run" if execute_live else "_inner", head],
            cwd=parent, env=env, text=True, capture_output=True, check=False,
            timeout=None if execute_live else MAX_SECONDS
        )
        # The inner process outputs an allowlisted set of constant state labels
        # only. Do not echo arbitrary subprocess stderr.
        for line in check.stdout.splitlines():
            if line.startswith(("PASS ", "BLOCKED ", "PRIVATE_READINESS_", "B2_B3_NOT_RUN;",
                                "B2_B3_", "STAGE ", "URGENT_", "VERIFY_ROLE_",
                                "BILLING_AND_")):
                print(line)
        if check.returncode and not any(line.startswith("BLOCKED ") for line in check.stdout.splitlines()):
            print("BLOCKED PRIVATE_PREFLIGHT_PROCESS")
        return 0 if check.returncode == 0 else 2
    except (OSError, subprocess.TimeoutExpired):
        print("BLOCKED TEMPORARY_CHECK_FAILURE")
        if execute_live:
            print("URGENT_ROLE_REVOCATION_NOT_VERIFIED")
        return 2
    finally:
        if linked:
            removed = git("worktree", "remove", str(parent))
            if removed.returncode:
                print("BLOCKED TEMPORARY_WORKTREE_CLEANUP")
                return 2
            branch_cleanup = git("branch", "-D", branch)
            if branch_cleanup.returncode:
                print("BLOCKED TEMPORARY_BRANCH_CLEANUP")
                return 2
        if not parent.exists() or not any(parent.iterdir()):
            try:
                parent.rmdir()
            except OSError:
                pass


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) == 2 and argv[0] in ("_inner", "_inner_run") and len(argv[1]) == 40:
        return inner(argv[1], execute_live=argv[0] == "_inner_run")
    if argv == ["run"]:
        return outer(execute_live=True)
    if argv:
        print("BLOCKED UNKNOWN_ARGUMENTS")
        return 2
    return outer()


if __name__ == "__main__":
    raise SystemExit(main())
