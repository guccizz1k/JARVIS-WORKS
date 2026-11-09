#!/usr/bin/env python3
"""V22.3 Track B (issue #140): the ONE owner-run, fail-closed procedure for the real B2/B3 inside the owner's Codespace.

Claude Code cannot run this for the owner: creating a Codespace does not give a Claude session access to it (the session's
GitHub API 403 is a permission boundary). The owner opens the Codespace and runs the short commands below; nothing here reads or
prints a secret, and no stage touches a database before every check has passed.

  python3 -m scripts.ci_cinema_pg_v223_codespace_run verify --expect-sha <40-hex>        # no secrets, no database
  python3 -m scripts.ci_cinema_pg_v223_codespace_run all    --expect-sha <40-hex> \
          --confirm-approval 6729950127 --confirm-no-charge                               # the single approved run

Stages of ``all`` (strict order; any failure stops the next stage, and the revoke stage ALWAYS runs once the renewal started):
  verify -> disposable restore target ready -> renew (VALID UNTIL, expiry only) -> live restricted login -> encrypted backup -> isolated PG17 restore + signature
  comparison -> revoke (NOLOGIN, sessions ended) -> proof that new logins are refused and active sessions are 0.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import ci_cinema_pg_guard as guard  # noqa: E402
from scripts import ci_cinema_pg_v223_codespace_check as preflight  # noqa: E402
from scripts.ci_cinema_pg_q import CREDS, ROLE  # noqa: E402
from scripts.ci_cinema_pg_r import SECRET_FILE  # noqa: E402
from scripts.ci_cinema_pg_s import CERT_FILE, HOST, PORT  # noqa: E402
from scripts.pg_backup_v223 import parse_dsn, pg_env  # noqa: E402

APPROVAL_COMMENT = "6729950127"                       # issue #140 conditional approval the owner confirms on the command line
APPROVED_LIMIT = datetime(2026, 11, 10, 9, 0, tzinfo=ZoneInfo("Asia/Seoul"))
MAX_WINDOW = timedelta(hours=23)                       # below the renew SQL's own 24 h rule: Python's clock runs before the server's
PROJECT_REF = "rvymwwzclagvljnofyss"
EXPECTED_TABLES = 65
POSTAB_FINGERPRINT_DEFAULT = "d3e6284dfbd277b43041052ea8f927ca"   # scripts/ci_cinema_pg_w.py POSTAB_FINGERPRINT; env overrides
RENEW_SQL = ROOT / "scripts/review/cinema_pg_v223_backup_role_renew_proposal.sql"
REVOKE_SQL = ROOT / "scripts/review/cinema_pg_v223_backup_role_revoke.sql"
SECRET_ENV = ("JW_PG_ADMIN_DSN", "JW_PG_BACKUP_KEY")  # Codespaces secrets; names only are ever printed
BACKUP_DIR = Path.home() / ".local" / "share" / "jw-v223-restore" / "backups"
SUMMARY_FILE = BACKUP_DIR.parent / "last_run_summary.json"
# Everything that must be byte-identical to the checked-out commit (and, for the backup tool and its test, to the guard's pins).
PINNED_PATHS = (
    "scripts/pg_backup_v223.py", "tests/test_v223_pg_backup.py", "scripts/ci_cinema_pg_guard.py",
    "scripts/review/cinema_pg_v223_backup_role_renew_proposal.sql", "scripts/review/cinema_pg_v223_backup_role_revoke.sql",
    "scripts/ci_cinema_pg_v223_codespace_bootstrap.py", "scripts/ci_cinema_pg_v223_codespace_check.py",
    "scripts/ci_cinema_pg_v223_codespace_run.py", "scripts/ci_cinema_pg_r.py", "scripts/ci_cinema_pg_m.py",
    "scripts/ci_cinema_pg_q.py", "scripts/ci_cinema_pg_s.py", "scripts/ci_cinema_pg_u.py",
)
SHA_RE = re.compile(r"[0-9a-f]{40}")
BACKUP_COMMAND = [sys.executable, "-m", "scripts.pg_backup_v223", "run"]   # the pinned engine; a gate may substitute a stand-in
BACKUP_TIMEOUT_S = 3600
ERROR_LOG = BACKUP_DIR.parent / "last_backup_error.log"                    # owner-only (0600) scrubbed diagnostic; never printed
REVOKE_ATTEMPTS = 3
RETRY_PAUSE_S = 5
LOGIN_SSLMODE = "verify-full"


class Blocked(Exception):
    """A stage refused to run. The message never contains a secret."""


class Ambiguous(Blocked):
    """The renewal may or may not have reached the database: the role must be closed again to be safe."""


def secret_values(environ: dict | None = None) -> list[str]:
    """Every secret this procedure can hold, in raw and URL-quoted form, for scrubbing text that is not ours."""
    from urllib.parse import quote
    env = os.environ if environ is None else environ
    found: set[str] = set()
    for name in ("JW_PG_BACKUP_KEY", "JW_PG_TARGET_EPHEMERAL_TOKEN"):
        if env.get(name):
            found.add(env[name])
    for name in ("JW_PG_ADMIN_DSN", "JW_PG_SOURCE_DSN", "JW_PG_TARGET_ADMIN_DSN"):
        dsn = env.get(name, "")
        if dsn:
            found.add(dsn)
            try:
                found.add(parse_dsn(dsn)["password"])
            except Exception:
                pass
    try:
        found.add(json.loads(CREDS.read_text(encoding="utf-8"))["password"])
    except Exception:
        pass
    found.update(quote(value, safe="") for value in list(found))
    return sorted((v for v in found if len(v) >= 6), key=len, reverse=True)


def scrub(text: str, environ: dict | None = None) -> str:
    """Remove known secret values and any URL credentials / password settings from text that came from another program."""
    out = text or ""
    for value in secret_values(environ):
        out = out.replace(value, "***")
    out = re.sub(r"(?i)([a-z][a-z0-9+.-]*://)[^/\s@]*@", r"\1***@", out)
    out = re.sub(r"(?i)\b(password|passwd|pwd|key|token|secret)\s*[=:]\s*\S+", r"\1=***", out)
    return out


def classify_login_failure(exc: BaseException) -> str:
    """``auth_rejected`` only when the SERVER answered the login with an authentication/authorization refusal.
    DNS, TCP, TLS, timeouts and anything unrecognised are ``transport_or_unknown`` and prove nothing about the role."""
    state = getattr(exc, "sqlstate", None)
    if isinstance(state, str) and state.startswith("28"):
        return "auth_rejected"
    text = str(exc).lower()
    if "fatal:" in text:
        after = text.split("fatal:", 1)[1]
        if any(mark in after for mark in ("not permitted to log in", "password authentication failed", "authentication failed")):
            return "auth_rejected"
    return "transport_or_unknown"


def now() -> datetime:
    return datetime.now(timezone.utc)


def git(*args: str) -> str:
    done = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=60, check=False)
    if done.returncode:
        raise Blocked("git " + args[0] + " failed")
    return done.stdout.strip()


# ---------------------------------------------------------------- checks (no database, no secrets)
def check_commit(expect_sha: str) -> dict:
    if not SHA_RE.fullmatch(expect_sha or ""):
        raise Blocked("--expect-sha must be the 40-hex commit SHA reported in issue #140")
    head = git("rev-parse", "HEAD")
    if head != expect_sha:
        raise Blocked(f"checked-out commit {head[:12]} is not the reported final commit {expect_sha[:12]}")
    if git("status", "--porcelain"):
        raise Blocked("the work tree has uncommitted or untracked changes")
    return {"head": head}


def check_pins() -> dict:
    """Backup tool, its test, the guard, both role SQL files and the Codespace scripts: one commit, one set, no mixing."""
    for path in PINNED_PATHS:
        if not (ROOT / path).is_file() or git("hash-object", path) != git("rev-parse", f"HEAD:{path}"):
            raise Blocked("pinned file missing or different from the commit: " + path)
    for path, pinned in guard.APPROVED_V223_BACKUP_BLOBS.items():
        if (ROOT / path).is_file() and git("hash-object", path) != pinned:
            raise Blocked("guard pin mismatch (the guard and the file come from different commits): " + path)
    code = "\n".join(line for line in RENEW_SQL.read_text().splitlines() if not line.lstrip().startswith("--"))
    if code.count("2026-11-10 09:00:00+09") != 1 or "7 days" in code:
        raise Blocked("renew SQL does not carry the approved absolute limit exactly once")
    done = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/ci_cinema_pg_guard.py")], cwd=ROOT,
                          capture_output=True, text=True, timeout=120, check=False)
    if done.returncode:
        raise Blocked("protected-source guard failed (full git history is required; do not use a shallow clone)")
    return {"files": len(PINNED_PATHS), "guard": "PASS"}


def check_tools() -> dict:
    status = preflight.check()
    missing = [name for name, ok in status.items() if not ok]
    if missing:
        raise Blocked("tooling not ready: " + ", ".join(missing))
    return status


def check_window(at: datetime | None = None) -> dict:
    at = at or now()
    if at >= APPROVED_LIMIT:
        raise Blocked("the owner approval ended at 2026-11-10 09:00:00+09; ask for a new approval, never extend")
    return {"now_kst": at.astimezone(ZoneInfo("Asia/Seoul")).strftime("%Y-%m-%d %H:%M:%S"),
            "minutes_left": int((APPROVED_LIMIT - at).total_seconds() // 60)}


def check_private_inputs(environ: dict | None = None) -> dict:
    env = os.environ if environ is None else environ
    missing = [name for name in SECRET_ENV if not env.get(name)]
    for label, path in (("backup_role_auth_file", CREDS), ("supabase_ca_file", CERT_FILE), ("restore_target_file", SECRET_FILE)):
        if path.is_symlink() or not path.is_file():
            missing.append(label)
        elif path.stat().st_uid != os.getuid() or path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            missing.append(label + "_permissions")
    if missing:
        raise Blocked("missing or unsafe private inputs (names only): " + ", ".join(missing))
    dsn = parse_dsn(env["JW_PG_ADMIN_DSN"])
    if dsn["sslmode"] != "verify-full" or not dsn["sslrootcert"]:
        raise Blocked("JW_PG_ADMIN_DSN must use sslmode=verify-full with sslrootcert")
    # The checked, owner-only CA file must also be the CA actually used by
    # the privileged connection, not a separate arbitrary trust root.
    if dsn["sslrootcert"] != str(CERT_FILE):
        raise Blocked("JW_PG_ADMIN_DSN must bind sslrootcert to the approved owner-only CA file")
    # psql is driven from the parsed fields above, but the closure proof hands the RAW URL to psycopg/libpq: a query parameter such as
    # host=, hostaddr=, port=, user=, dbname=, options= or a repeated sslmode= would let the connection differ from what was validated.
    from urllib.parse import parse_qs, urlsplit
    params = parse_qs(urlsplit(env["JW_PG_ADMIN_DSN"]).query, keep_blank_values=True)
    if set(params) != {"sslmode", "sslrootcert"} or any(len(values) != 1 for values in params.values()):
        raise Blocked("JW_PG_ADMIN_DSN may carry exactly one sslmode and one sslrootcert parameter and nothing else")
    if not dsn["password"]:
        raise Blocked("JW_PG_ADMIN_DSN must carry the admin password in the URL")
    # Exact endpoint binding is mandatory BEFORE the privileged renew SQL.
    # A substring match on the project ref can be forged by a hostile host or
    # username; neither DNS/TLS nor a matching ref fragment proves DB identity.
    direct = (dsn["host"] == f"db.{PROJECT_REF}.supabase.co"
              and dsn["user"] == "postgres")
    pooler = (dsn["host"] == HOST
              and dsn["user"] == f"postgres.{PROJECT_REF}")
    if (not (direct or pooler) or dsn["port"] != str(PORT)
            or dsn["dbname"] != "postgres"):
        raise Blocked("JW_PG_ADMIN_DSN does not exactly match approved project host, port, database and admin role")
    return {"secret_names_present": list(SECRET_ENV), "files_ok": 3}


def verify(expect_sha: str, *, need_private: bool = True) -> dict:
    if os.environ.get("CODESPACES") != "true":
        raise Blocked("run this only inside the owner's Codespace")
    report = {"commit": check_commit(expect_sha)["head"], "pins": check_pins(), "window": check_window()}
    check_tools()
    report["tools"] = "PASS"
    if need_private:
        report["private_inputs"] = check_private_inputs()
    return report


# ---------------------------------------------------------------- stages (database)
def renew_value(at: datetime | None = None) -> str:
    at = at or now()
    until = min(APPROVED_LIMIT, at + MAX_WINDOW)
    if until <= at:
        raise Blocked("no renewal window is left before 2026-11-10 09:00:00+09")
    return until.astimezone(ZoneInfo("Asia/Seoul")).strftime("%Y-%m-%d %H:%M:%S+09")


def psql(dsn_env: str, sql_file: Path, variables: dict[str, str]) -> subprocess.CompletedProcess:
    """psql with the credentials in libpq environment variables only: nothing secret reaches argv or any log."""
    cmd = ["psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"]
    for key, value in variables.items():
        cmd += ["-v", f"{key}={value}"]
    cmd += ["-f", str(sql_file)]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False,
                          env=pg_env(parse_dsn(os.environ[dsn_env])))


def stage_target() -> dict:
    """The disposable local PG17 restore target must be up, empty and marked BEFORE the role is renewed (no Supabase contact)."""
    import contextlib
    import io
    from scripts import ci_cinema_pg_m as marker
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = marker.main()
    if code != 0:
        first = (out.getvalue().strip().splitlines() or ["no output"])[0][:160]
        raise Blocked("disposable PG17 restore target not ready (if the container is stopped: docker start jw-v223-restore): " + first)
    return {"restore_target": "up_marked_and_empty"}


def stage_renew(on_attempt=None) -> dict:
    """``on_attempt`` fires immediately BEFORE the privileged psql starts: from then on the server may have committed the change
    even if the client reports a failure, so the caller must close the role whatever happens next."""
    value = renew_value()                       # a Blocked here means nothing was sent to any database
    if on_attempt is not None:
        on_attempt()
    try:
        done = psql("JW_PG_ADMIN_DSN", RENEW_SQL, {"valid_until": value})
    except subprocess.TimeoutExpired:
        raise Ambiguous("renewal timed out, state unknown: the revoke stage will close the role")
    except OSError:
        raise Ambiguous("renewal could not be started, state unknown: the revoke stage will close the role")
    if done.returncode:
        category = ("approval window closed" if "closed" in done.stderr else
                    "limit rule" if "renewal window" in done.stderr else "database or connection error")
        raise Ambiguous(f"renewal reported failure (exit {done.returncode}, {category}); the server may still have applied it, "
                        "the revoke stage will close the role")
    return {"valid_until": value}


def read_password() -> str:
    obj = json.loads(CREDS.read_text(encoding="utf-8"))
    if set(obj) != {"role", "password", "verifier"} or obj["role"] != ROLE:
        raise Blocked("unexpected backup-role credential file format")
    return obj["password"]


def source_dsn() -> str:
    from urllib.parse import quote
    return (f"postgresql://{quote(ROLE + '.' + PROJECT_REF, safe='.')}:{quote(read_password(), safe='')}@{HOST}:{PORT}/postgres"
            f"?sslmode=verify-full&sslrootcert={quote(str(CERT_FILE), safe='/')}")


def stage_login() -> dict:
    from scripts import ci_cinema_pg_u as live
    import io
    import contextlib
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = live.main()
    if code != 0 or "SOURCE_AUTH_ONLY_PASS" not in out.getvalue():
        raise Blocked("restricted login or privilege check failed: " + out.getvalue().strip().splitlines()[0][:160])
    return {"login": "PASS", "tables_expected": EXPECTED_TABLES}


def backup_env() -> dict:
    from scripts.ci_cinema_pg_m import read_private_target
    target = read_private_target()
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update(target)
    env.update({
        "JW_PG_SOURCE_DSN": source_dsn(), "JW_PG_REAL_SOURCE": "1", "JW_PG_SCHEMA": "jw_dev",
        "JW_PG_EXPECT_SOURCE_HOST": HOST, "JW_PG_EXPECT_SOURCE_PORT": str(PORT), "JW_PG_EXPECT_PROJECT_REF": PROJECT_REF,
        "JW_PG_EXPECT_DBNAME": "postgres", "JW_PG_EXPECT_ROLE": ROLE,
        "JW_PG_EXPECT_SCHEMA_FINGERPRINT": os.environ.get("JW_PG_EXPECT_SCHEMA_FINGERPRINT") or POSTAB_FINGERPRINT_DEFAULT,
        "TMPDIR": str(BACKUP_DIR),            # the encrypted archive stays in this private 0700 folder, not in /tmp
    })
    return env


def evaluate_summary(summary: dict) -> list[str]:
    """Names of failed conditions only. PASS needs every one of them."""
    failures = []
    if summary.get("verdict") != "PASS":
        failures.append("verdict")
    if summary.get("tables") != EXPECTED_TABLES:
        failures.append("tables_not_65")
    if summary.get("signature_mismatches") != []:
        failures.append("signature_mismatches")
    for key in ("restore_verified", "source_identity_verified", "source_role_least_privilege", "snapshot_consistent",
                "target_proven_ephemeral", "wrong_key_rejected", "decrypt_sha256_matches", "partial_dump_restore_rejected",
                "tamper_rejected", "truncation_rejected"):
        if summary.get(key) is not True:
            failures.append(key)
    if summary.get("source_is_real_dev_db") is not True:
        failures.append("not_real_source")
    return failures


def write_error_log(done: subprocess.CompletedProcess, environ: dict | None = None) -> str:
    """Independently scrubbed diagnostic for the owner, mode 0600, never printed, never put into the summary."""
    body = "\n".join(("exit_code=" + str(done.returncode), "--- stdout (tail) ---", scrub(done.stdout or "", environ)[-2000:],
                      "--- stderr (tail) ---", scrub(done.stderr or "", environ)[-2000:]))
    ERROR_LOG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    ERROR_LOG.unlink(missing_ok=True)
    fd = os.open(ERROR_LOG, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(body)
    return str(ERROR_LOG)


def stage_backup() -> dict:
    env = backup_env()
    try:
        done = subprocess.run(BACKUP_COMMAND, cwd=ROOT, env=env, capture_output=True, text=True,
                              timeout=BACKUP_TIMEOUT_S, check=False)
    except subprocess.TimeoutExpired:
        raise Blocked("backup tool timed out")
    try:
        summary = json.loads(done.stdout)
        if not isinstance(summary, dict):
            raise ValueError
    except ValueError:
        # Nothing the child printed is trusted: the report carries only the exit code and a pointer to the scrubbed private log.
        raise Blocked(f"backup tool produced no usable summary (exit code {done.returncode}); scrubbed owner-only log: {write_error_log(done, env)}")
    failed = evaluate_summary(summary)
    if done.returncode or failed:
        detail = f"; scrubbed owner-only log: {write_error_log(done, env)}" if done.returncode else ""
        raise Blocked("backup/restore verification failed: " + ", ".join(failed or ["exit_code"]) + detail)
    keep = {k: summary.get(k) for k in ("verdict", "tables", "signature_sha256", "timings_s", "server_version", "dump_bytes")}
    return {**keep, "archive_dir": str(BACKUP_DIR)}


def stage_revoke() -> dict:
    """Idempotent: retried because the same outage that broke the renewal may also break the first revoke attempt."""
    for attempt in range(1, REVOKE_ATTEMPTS + 1):
        try:
            if psql("JW_PG_ADMIN_DSN", REVOKE_SQL, {}).returncode == 0:
                return {"revoke": "applied", "attempts": attempt}
        except (subprocess.TimeoutExpired, OSError):
            pass
        if attempt < REVOKE_ATTEMPTS:
            time.sleep(RETRY_PAUSE_S)
    raise Blocked("REVOCATION FAILED: run the revoke SQL by hand now (NOLOGIN may or may not be in place)")


def login_kwargs() -> dict:
    kwargs = {"host": HOST, "port": PORT, "dbname": "postgres", "user": f"{ROLE}.{PROJECT_REF}", "password": read_password(),
              "sslmode": LOGIN_SSLMODE, "connect_timeout": 8}
    if LOGIN_SSLMODE == "verify-full":
        kwargs["sslrootcert"] = str(CERT_FILE)
    return kwargs


def stage_prove_closed() -> dict:
    """Measured, not assumed. Closed needs ALL of: the server rejects a new login (an authentication refusal, not a DNS/TCP/TLS
    failure), the admin sees ``rolcanlogin`` false, and zero sessions for the role."""
    import psycopg
    refusal, attempts = "none", 0
    for attempts in range(1, REVOKE_ATTEMPTS + 1):
        try:
            with psycopg.connect(**login_kwargs()):
                raise Blocked("NEW LOGIN STILL WORKS after revocation")
        except Blocked:
            raise
        except psycopg.Error as exc:
            refusal = classify_login_failure(exc)
        if refusal == "auth_rejected":
            break
        time.sleep(RETRY_PAUSE_S)
    with psycopg.connect(os.environ["JW_PG_ADMIN_DSN"], connect_timeout=8, autocommit=True) as conn:
        sessions = conn.execute("SELECT count(*) FROM pg_stat_activity WHERE usename = %s", (ROLE,)).fetchone()[0]
        can_login = conn.execute("SELECT rolcanlogin FROM pg_roles WHERE rolname = %s", (ROLE,)).fetchone()[0]
    if sessions != 0 or can_login:
        raise Blocked(f"role not closed: sessions={sessions} can_login={can_login}")
    if refusal != "auth_rejected":
        raise Blocked("new_login_refusal_not_verified: the login attempt failed for a network/TLS/unknown reason, not because the "
                      f"server rejected the role ({attempts} attempts); the role looks closed from the admin side only")
    return {"new_login_refused": True, "refusal": refusal, "active_sessions": 0, "rolcanlogin": False}


def run_all(expect_sha: str) -> tuple[int, dict]:
    result: dict = {"expect_sha": expect_sha, "stages": {}}
    renewed = False

    def stage(name: str, fn) -> None:
        try:
            result["stages"][name] = {"status": "PASS", **fn()}
        except Blocked as exc:
            result["stages"][name] = {"status": "BLOCKED", "reason": scrub(str(exc))}
            raise
        except Exception as exc:                   # the text of a driver error may hold a DSN: record the class only
            result["stages"][name] = {"status": "BLOCKED", "reason": "unexpected " + type(exc).__name__}
            raise Blocked("unexpected " + type(exc).__name__)

    try:
        result["verify"] = verify(expect_sha)
        stage("target_ready", stage_target)

        def mark_attempted() -> None:
            nonlocal renewed
            renewed = True        # set BEFORE the privileged subprocess: the server may commit and the client still report failure

        stage("renew", lambda: stage_renew(mark_attempted))
        stage("live_login", stage_login)
        stage("backup_restore_compare", stage_backup)
    except Blocked as exc:
        result["blocked"] = scrub(str(exc))
    finally:
        if renewed:
            for name, fn in (("revoke", stage_revoke), ("prove_closed", stage_prove_closed)):
                try:
                    stage(name, fn)
                except Blocked as exc:
                    result["blocked"] = (result.get("blocked", "") + " | " + scrub(str(exc))).strip(" |")
    required = {"target_ready", "renew", "live_login", "backup_restore_compare", "revoke", "prove_closed"}
    passed = (not result.get("blocked") and required <= set(result["stages"])
              and all(v["status"] == "PASS" for v in result["stages"].values()))
    result["B2_B3"] = "PASS" if passed else "BLOCKED_OR_FAIL"
    return (0 if passed else 2), result


def write_summary(result: dict) -> None:
    SUMMARY_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(SUMMARY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(result, out, indent=2, sort_keys=True)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="ci_cinema_pg_v223_codespace_run")
    parser.add_argument("command", choices=("verify", "all"))
    parser.add_argument("--expect-sha", required=True)
    parser.add_argument("--confirm-approval", default="")
    parser.add_argument("--confirm-no-charge", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            report = verify(args.expect_sha, need_private=False)
            print(json.dumps(report, indent=2, sort_keys=True))
            print("VERIFY_ONLY_PASS: no secret read, no database contacted, real backup NOT RUN")
            return 0
        if args.confirm_approval != APPROVAL_COMMENT or not args.confirm_no_charge:
            raise Blocked("both --confirm-approval " + APPROVAL_COMMENT + " and --confirm-no-charge are required (Codespaces usage was checked as free)")
        code, result = run_all(args.expect_sha)
        write_summary(result)
        print(json.dumps(result, indent=2, sort_keys=True))
        print("B2_B3_" + result["B2_B3"])
        return code
    except Blocked as exc:
        print("BLOCKED: " + scrub(str(exc)), file=sys.stderr)
        print("NO_DATABASE_ACTION_TAKEN")      # every Blocked reaching here was raised before any stage ran
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
