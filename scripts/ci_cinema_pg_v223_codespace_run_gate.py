#!/usr/bin/env python3
"""V22.3 Track B (issue #140): real-driver negative gate for the owner-run Codespace launcher's three safety rules.

Runs the REAL launcher stages (psql for renew/revoke, psycopg for the closure proof) against a disposable local PostgreSQL 17 with
the Supabase-shaped admin of the other gates. Only the stages that need the real Supabase project or the pinned backup engine are
replaced (verify, restore target, restricted login, and - where stated - the backup subprocess). Nothing here touches Supabase.

  JW_CINEMA_PG_DISPOSABLE=1 PGHOST=127.0.0.1 PGPORT=… PGUSER=postgres PGPASSWORD=… \
      python3 -m scripts.ci_cinema_pg_v223_codespace_run_gate [--allow-pg16-local]

  CR.01 the server COMMITS the renewal but the client reports failure -> the role is still revoked and proven closed, never PASS
  CR.02 a transient failure of the first revoke attempt is retried until NOLOGIN is in place
  CR.03 a deliberate NOLOGIN rejection by the server is recognised as an authentication refusal by the real driver
  CR.04 refused connection, DNS failure, TLS failure and a connect timeout are NOT accepted as a login refusal
  CR.05 a role that can still log in is reported as a failure
  CR.06 DSN / password / key printed by a failing backup subprocess never reaches stdout, stderr, the summary, or any file but a 0600 log
  CR.07 a failure before the privileged command (no renewal window left) sends nothing to any database and revokes nothing
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import ci_cinema_pg_sql_gate as gate  # noqa: E402
from scripts import ci_cinema_pg_v223_backup_role_c_gate as cg  # noqa: E402
from scripts import ci_cinema_pg_v223_backup_role_renew_gate as rg  # noqa: E402
from scripts import ci_cinema_pg_v223_codespace_run as run  # noqa: E402
from scripts import ci_cinema_pg_v223_preflight_gate as pf  # noqa: E402

ADMIN = pf.SIM_ADMIN
ROLE = run.ROLE
EXPECTED = [f"CR.0{i}" for i in range(1, 8)]
results: list[tuple[str, bool, str]] = []

SHIM = r'''#!/usr/bin/env python3
import os, subprocess, sys
args = sys.argv[1:]
kind = "renew" if any("temporary-login.sql" in a or "backup_role_temporary_login_" in a for a in args) else "revoke" if any("backup_role_revoke" in a for a in args) else "other"
with open(os.environ["JW_SHIM_LOG"], "a") as log:
    log.write(kind + "\n")
mode = os.environ.get("JW_SHIM_MODE", "")
counter = os.environ["JW_SHIM_LOG"] + ".revoke-failed"
if mode == "fail_first_revoke" and kind == "revoke" and not os.path.exists(counter):
    open(counter, "w").close()
    sys.stderr.write("connection to server lost\n")      # nothing was sent: a transient outage
    sys.exit(2)
done = subprocess.run([os.environ["JW_REAL_PSQL"], *args], capture_output=True, text=True)
sys.stdout.write(done.stdout)
if mode == "fail_after_commit" and kind == "renew" and done.returncode == 0:
    # the real psql has committed; the client now reports a failure that carries a secret, as a dropped connection or a crash can
    sys.stderr.write("server closed the connection unexpectedly " + os.environ["JW_SHIM_LEAK"] + "\n")
    sys.exit(1)
sys.stderr.write(done.stderr)
sys.exit(done.returncode)
'''


def rec(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail[:400])


def scalar(db: str, sql: str) -> str:
    return pf.scalar(db, sql)


def role_facts(db: str) -> dict:
    return {"can_login": scalar(db, f"SELECT rolcanlogin FROM pg_roles WHERE rolname='{ROLE}'"),
            "sessions": scalar(db, f"SELECT count(*) FROM pg_stat_activity WHERE usename='{ROLE}'"),
            "valid_until_in_future": scalar(db, f"SELECT rolvaliduntil > now() FROM pg_roles WHERE rolname='{ROLE}'")}


def reset_role(db: str, password: str) -> None:
    """The live starting point: NOLOGIN role, known password, expired."""
    pf.psql(db, sql=f"ALTER ROLE {ROLE} NOLOGIN PASSWORD '{password}' VALID UNTIL '2000-01-01 00:00:00+00'")


class Env:
    """Everything the launcher reads, pointed at the disposable server; restored on exit."""

    def __init__(self, db: str, password: str, admin_password: str, workdir: Path):
        self.db, self.password, self.admin_password, self.workdir = db, password, admin_password, workdir
        self.log = workdir / "psql-calls.log"
        self.host, self.port = os.environ["PGHOST"], os.environ["PGPORT"]
        self.stack = contextlib.ExitStack()
        self.admin_dsn = f"postgresql://{ADMIN}:{quote(admin_password, safe='')}@{self.host}:{self.port}/{db}"

    def login_kwargs(self, **override) -> dict:
        base = {"host": self.host, "port": int(self.port), "dbname": self.db, "user": ROLE, "password": self.password,
                "sslmode": "prefer", "connect_timeout": 3}
        return {**base, **override}

    def __enter__(self):
        limit = rg.stamp(timedelta(hours=48))
        win = self.workdir / "temporary-login.sql"
        win.write_text(run.TEMP_LOGIN_SQL.read_text(encoding="utf-8").replace("2026-11-11 09:00:00+09", limit), encoding="utf-8")
        creds = self.workdir / "backup_role_auth.json"
        creds.write_text(json.dumps({"role": ROLE, "password": self.password, "verifier": "x"}))
        shim_dir = self.workdir / "shim"
        shim_dir.mkdir(exist_ok=True)
        (shim_dir / "psql").write_text(SHIM)
        (shim_dir / "psql").chmod(0o700)
        self.log.write_text("")
        real = subprocess.run(["which", "psql"], capture_output=True, text=True).stdout.strip()
        enter = self.stack.enter_context
        enter(patch.dict(os.environ, {"JW_PG_ADMIN_DSN": self.admin_dsn, "PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}",
                                      "JW_REAL_PSQL": real, "JW_SHIM_LOG": str(self.log), "JW_SHIM_MODE": "",
                                      "JW_SHIM_LEAK": "leak-never-" + secrets.token_hex(6)}))
        enter(patch.object(run, "APPROVED_LIMIT", datetime.now(ZoneInfo("Asia/Seoul")) + timedelta(hours=48)))
        enter(patch.object(run, "TEMP_LOGIN_SQL", win))
        enter(patch.object(run, "CREDS", creds))
        enter(patch.object(run, "login_kwargs", lambda: self.login_kwargs()))
        enter(patch.object(run, "RETRY_PAUSE_S", 0))
        enter(patch.object(run, "SUMMARY_FILE", self.workdir / "private" / "last_run_summary.json"))
        enter(patch.object(run, "ERROR_LOG", self.workdir / "private" / "last_backup_error.log"))
        return self

    def __exit__(self, *exc):
        self.stack.close()
        return False

    def calls(self) -> list[str]:
        return [line for line in self.log.read_text().splitlines() if line in ("renew", "revoke")]

    def mode(self, name: str):
        return patch.dict(os.environ, {"JW_SHIM_MODE": name})


def stand_in_stages(backup: bool = True):
    """Stages that need the real Supabase project or the owner's private files; everything else stays real."""
    stand_ins = dict(verify=lambda sha, **kw: {"stand_in": "verify"}, stage_target=lambda: {"stand_in": "target"},
                     stage_login=lambda: {"stand_in": "login"})
    if backup:
        stand_ins["stage_backup"] = lambda: {"stand_in": "backup"}
    return patch.multiple(run, **stand_ins)


def transport_failures(env: Env, tls_off: bool) -> dict[str, dict]:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
    variants = {"connection_refused": {"port": dead_port},
                "dns_failure": {"host": "no-such-host.invalid"},
                "tls_verification_cannot_start": {"sslmode": "verify-full", "sslrootcert": "/nonexistent/ca.crt"}}
    if tls_off:
        variants["tls_required_but_server_has_none"] = {"sslmode": "require"}
    return variants


def main_phase() -> None:
    db = None
    work = Path(tempfile.mkdtemp(prefix="jwcr_"))
    try:
        db = cg.fresh()
        applied = cg.run_c(db, ADMIN)
        pw, admin_pw = "ci-only-" + secrets.token_hex(12), pf.PASSWORDS[ADMIN]
        pf.psql("postgres", sql=f"GRANT pg_signal_backend TO {ADMIN}")
        reset_role(db, pw)
        tls_off = scalar(db, "SHOW ssl") == "off"
        sink = socket.socket()
        sink.bind(("127.0.0.1", 0))
        sink.listen(8)          # accepts TCP in the kernel backlog and never answers: a connect that can only time out
        stalled_port = sink.getsockname()[1]
        print(f"setup: change C applied={applied.returncode == 0} ssl_off_on_server={tls_off}")

        with Env(db, pw, admin_pw, work) as env:
            # CR.01 ----------------------------------------------------------------------------------------------
            reset_role(db, pw)
            leak = os.environ["JW_SHIM_LEAK"]
            with env.mode("fail_after_commit"), stand_in_stages():
                code, result = run.run_all("0" * 40)
            facts = role_facts(db)
            stages = result["stages"]
            rec("CR.01_server_commits_renewal_but_client_reports_failure_role_is_still_revoked_and_proven_closed_never_pass",
                code == 2 and result["B2_B3"] == "BLOCKED_OR_FAIL" and stages["renew"]["status"] == "BLOCKED"
                and stages["revoke"]["status"] == "PASS" and stages["prove_closed"]["status"] == "PASS"
                and env.calls() == ["renew", "revoke"] and facts["valid_until_in_future"] == "t"      # the renewal really was applied
                and facts["can_login"] == "f" and facts["sessions"] == "0" and leak not in json.dumps(result),
                json.dumps({"code": code, "calls": env.calls(), "facts": facts, "stages": {k: v["status"] for k, v in stages.items()}}))

            # CR.02 ----------------------------------------------------------------------------------------------
            reset_role(db, pw)
            env.log.write_text("")
            Path(str(env.log) + ".revoke-failed").unlink(missing_ok=True)
            renewed = run.stage_renew()
            with env.mode("fail_first_revoke"):
                revoked = run.stage_revoke()
            rec("CR.02_a_failed_first_revoke_attempt_is_retried_until_nologin_is_in_place",
                revoked == {"revoke": "applied", "attempts": 2} and env.calls() == ["renew", "revoke", "revoke"]
                and role_facts(db)["can_login"] == "f" and "valid_until" in renewed, f"{revoked} {env.calls()} {role_facts(db)}")

            # CR.03 ----------------------------------------------------------------------------------------------
            try:
                proof = run.stage_prove_closed()
                detail = ""
            except run.Blocked as exc:
                proof, detail = {}, str(exc)
            rec("CR.03_real_server_rejection_of_a_nologin_role_is_recognised_as_an_authentication_refusal",
                proof.get("refusal") == "auth_rejected" and proof.get("new_login_refused") is True
                and proof.get("active_sessions") == 0 and proof.get("rolcanlogin") is False, detail)

            # CR.04 ----------------------------------------------------------------------------------------------
            seen, bad = {}, []
            variants = transport_failures(env, tls_off)
            variants["connect_timeout"] = {"port": stalled_port, "connect_timeout": 2}
            for name, override in variants.items():
                with patch.object(run, "login_kwargs", lambda override=override: env.login_kwargs(**override)):
                    try:
                        run.stage_prove_closed()
                        seen[name] = "ACCEPTED_AS_PROOF"
                    except run.Blocked as exc:
                        seen[name] = "not_verified" if "new_login_refusal_not_verified" in str(exc) else "other:" + str(exc)[:80]
                try:
                    import psycopg
                    psycopg.connect(**env.login_kwargs(**override)).close()
                except psycopg.Error as exc:
                    seen[name] += "/" + run.classify_login_failure(exc)
                except Exception as exc:
                    seen[name] += "/" + type(exc).__name__
            bad = [k for k, v in seen.items() if v != "not_verified/transport_or_unknown"]
            rec("CR.04_refused_dns_tls_and_timeout_failures_are_not_accepted_as_a_login_refusal_while_the_role_is_closed",
                not bad and role_facts(db)["can_login"] == "f", json.dumps(seen))

            # CR.05 ----------------------------------------------------------------------------------------------
            pf.psql(db, sql=f"ALTER ROLE {ROLE} LOGIN VALID UNTIL '{rg.stamp(timedelta(hours=2))}'")
            try:
                run.stage_prove_closed()
                still = "ACCEPTED"
            except run.Blocked as exc:
                still = str(exc)
            rec("CR.05_a_role_that_can_still_log_in_is_reported_as_a_failure", "STILL WORKS" in still, still[:200])

            # CR.06 ----------------------------------------------------------------------------------------------
            reset_role(db, pw)
            env.log.write_text("")
            key = "K" * 43 + "="
            leak_text = (f"Traceback: could not connect using {env.admin_dsn} and {env.admin_dsn.replace('postgresql', 'postgres', 1)}; "
                         f"password={pw}; raw {pw}; quoted {quote(pw, safe='')}; key={key}; "
                         f"url postgresql://other:unlisted-secret-91@elsewhere/db; admin {admin_pw}")
            script = "import sys; sys.stderr.write(%r); sys.stdout.write('crash ' + %r); sys.exit(1)" % (leak_text, leak_text)
            out, err = io.StringIO(), io.StringIO()
            with stand_in_stages(backup=False), \
                    patch.object(run, "BACKUP_COMMAND", [sys.executable, "-c", script]), \
                    patch.object(run, "backup_env", lambda: {**os.environ, "JW_PG_BACKUP_KEY": key}), \
                    patch.dict(os.environ, {"JW_PG_BACKUP_KEY": key}), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = run.main(["all", "--expect-sha", "0" * 40, "--confirm-approval", run.APPROVAL_COMMENT, "--confirm-no-charge"])
            blobs = {"stdout": out.getvalue(), "stderr": err.getvalue()}
            for path in work.rglob("*"):
                if path.is_file() and path.name not in ("psql", "backup_role_auth.json") and not path.name.endswith(".revoke-failed"):
                    blobs[str(path.relative_to(work))] = path.read_text(errors="replace")
            needles = (pw, quote(pw, safe=""), key, admin_pw, "unlisted-secret-91", env.admin_dsn)
            leaked = sorted({name for name, text in blobs.items() for needle in needles if needle in text})
            log_path = run.ERROR_LOG
            facts = role_facts(db)
            rec("CR.06_failing_backup_subprocess_secrets_never_reach_stdout_stderr_summary_or_logs_and_the_role_is_closed",
                code == 2 and not leaked and log_path.exists() and stat.S_IMODE(log_path.stat().st_mode) == 0o600
                and "B2_B3_BLOCKED_OR_FAIL" in out.getvalue() and "B2_B3_PASS" not in out.getvalue()
                and env.calls() == ["renew", "revoke"] and facts["can_login"] == "f" and facts["sessions"] == "0",
                json.dumps({"code": code, "leaked_in": leaked, "calls": env.calls(), "facts": facts}))

            # CR.07 ----------------------------------------------------------------------------------------------
            reset_role(db, pw)
            env.log.write_text("")
            before = role_facts(db)
            with patch.object(run, "APPROVED_LIMIT", datetime.now(ZoneInfo("Asia/Seoul")) - timedelta(minutes=1)), stand_in_stages():
                code, result = run.run_all("0" * 40)
            rec("CR.07_no_renewal_window_left_sends_nothing_to_any_database_and_revokes_nothing",
                code == 2 and env.calls() == [] and role_facts(db) == before and "renew" in result["stages"]
                and "revoke" not in result["stages"] and "prove_closed" not in result["stages"],
                json.dumps({"code": code, "calls": env.calls(), "stages": list(result["stages"])}))
        sink.close()
    finally:
        if db:
            pf.cleanup(db)
            cg.drop_everything()


def main() -> int:
    gate.local_server_or_die()
    server = pf.scalar("postgres", "SHOW server_version_num")
    if not server.isdigit() or (int(server) < 170000 and "--allow-pg16-local" not in sys.argv):
        print("BLOCKED: PostgreSQL 17 required (pass --allow-pg16-local for supplemental local evidence)")
        return 2
    if os.environ.get("PGHOST", "").startswith("/"):
        print("BLOCKED: this gate needs a TCP+password server (the login checks are meaningless on a trust socket)")
        return 2
    try:
        import psycopg  # noqa: F401
    except ImportError:
        print("BLOCKED: psycopg is required (requirements-postgres-check.txt): the closure proof must use the real driver")
        return 2
    pf.cleanup(None)
    cg.drop_everything()
    main_phase()
    failed = [n for n, ok, _ in results if not ok]
    names = [re.match(r"CR\.\d+", n).group(0) for n, _, _ in results]
    ok = not failed and names == EXPECTED
    print(json.dumps({"server_version_num": server, "total": len(results), "expected": len(EXPECTED), "failed": failed}))
    print(("PASS" if ok else "FAIL") + f": {len(results)} checks, {len(failed)} failed, expected exactly {len(EXPECTED)}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
