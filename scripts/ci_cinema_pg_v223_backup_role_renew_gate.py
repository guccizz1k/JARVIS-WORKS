#!/usr/bin/env python3
"""V22.3 Track B (issue #140, B1): gate for RENEWING the expired jw_backup_ro with the proposal file, and for revoking it.
psql client + standard library only; disposable local server (TCP, SCRAM) only. Reuses the change-C gate's fixtures.

  JW_CINEMA_PG_DISPOSABLE=1 PGHOST=127.0.0.1 PGPORT=… PGUSER=postgres PGPASSWORD=… \
      python3 -m scripts.ci_cinema_pg_v223_backup_role_renew_gate [--allow-pg16-local]

What is proven (on the server it ran on; PG17 is the target, PG16 is supplemental evidence):
  * an expired role cannot log in; the renew file, run by the Supabase-shaped admin, restores login with the SAME password;
  * renewal changes ONLY the expiry: role attributes, password verifier, connection limit, role settings, memberships and
    every table/sequence ACL are identical before and after; the backup tool's rules and the preflight still accept the role;
  * the renew file refuses a past window, a window beyond 7 days, a missing variable and a missing role, each without any change;
  * the revoke file stops new logins at once and ends open sessions; a later renewal does NOT silently re-enable LOGIN;
  * the existing rollback SQL still removes a renewed role and returns the database to the pre-C fingerprint.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import ci_cinema_pg_sql_gate as gate  # noqa: E402
from scripts import ci_cinema_pg_v223_backup_role_c_gate as cg  # noqa: E402
from scripts import ci_cinema_pg_v223_preflight_gate as pf  # noqa: E402

RENEW = ROOT / "scripts" / "review" / "cinema_pg_v223_backup_role_renew_proposal.sql"
REVOKE = ROOT / "scripts" / "review" / "cinema_pg_v223_backup_role_revoke.sql"
ADMIN = pf.SIM_ADMIN
EXPECTED = [f"RN.0{i}" for i in range(1, 9)]
results: list[tuple[str, bool, str]] = []

# everything about the role except its expiry; the password verifier is compared, never printed
FACTS_NO_EXPIRY = ("SELECT md5(concat_ws('|', a.rolcanlogin, a.rolbypassrls, a.rolsuper, a.rolcreatedb, a.rolcreaterole, "
                   "a.rolreplication, a.rolconnlimit, coalesce(r.rolconfig::text,''), coalesce(a.rolpassword,'<none>'), a.rolinherit)) "
                   "FROM pg_authid a JOIN pg_roles r ON r.oid = a.oid WHERE a.rolname='jw_backup_ro'")
ACL_ENTRIES = ("SELECT coalesce(string_agg(c.relname||':'||a.privilege_type, ',' ORDER BY c.relname, a.privilege_type), '') "
               "FROM pg_class c, aclexplode(c.relacl) a WHERE c.relnamespace='jw_dev'::regnamespace "
               "AND a.grantee='jw_backup_ro'::regrole")
VALID_UNTIL = "SELECT rolvaliduntil::text FROM pg_roles WHERE rolname='jw_backup_ro'"


def rec(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail[:300])


def state(db: str) -> tuple[str, str, str, str]:
    return (pf.scalar(db, FACTS_NO_EXPIRY), pf.scalar(db, ACL_ENTRIES), pf.scalar(db, cg.ADMIN_MEMBERSHIPS), pf.scalar(db, cg.FP))


def renew(db: str, valid_until: str | None, *, file: Path = RENEW) -> subprocess.CompletedProcess:
    if valid_until is None:                       # the variable is deliberately absent
        cmd = ["psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-d", db, "-U", ADMIN, "-f", str(file)]
        env = dict(os.environ, PGPASSWORD=pf.PASSWORDS[ADMIN])
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
    return cg.run_c(db, ADMIN, file=file, valid_until=valid_until)


def main_phase() -> None:
    db = None
    try:
        db = cg.fresh()
        base_fp = pf.scalar(db, cg.FP)
        applied = cg.run_c(db, ADMIN)
        pw = secrets.token_hex(16)
        pf.PASSWORDS["jw_backup_ro"] = pw
        pf.psql(db, user=ADMIN, sql=f"ALTER ROLE jw_backup_ro PASSWORD '{pw}'")
        pf.psql(db, user=ADMIN, sql="ALTER ROLE jw_backup_ro VALID UNTIL '2000-01-01 00:00:00+00'")   # the live situation: expired
        expired = cg.login_ok(db, "jw_backup_ro")
        before = state(db)
        rec("RN.01_premise_expired_role_with_password_cannot_log_in",
            applied.returncode == 0 and expired.returncode != 0 and "authentication failed" in expired.stderr
            and pf.scalar(db, "SELECT rolvaliduntil < now() FROM pg_roles WHERE rolname='jw_backup_ro'") == "t", expired.stderr[-120:])

        done = renew(db, cg.until(2))
        back = cg.login_ok(db, "jw_backup_ro", "SHOW default_transaction_read_only")
        rec("RN.02_renew_file_restores_login_with_the_same_password_and_stays_read_only",
            done.returncode == 0 and back.returncode == 0 and back.stdout.strip() == "on"
            and pf.scalar(db, "SELECT rolvaliduntil > now() FROM pg_roles WHERE rolname='jw_backup_ro'") == "t",
            f"{done.stderr[-160:]} {back.stderr[-80:]}")

        after = state(db)
        rec("RN.03_renewal_changes_only_the_expiry_attributes_password_acl_memberships_fingerprint_equal",
            before == after, f"facts={before[0] == after[0]} acl={before[1] == after[1]} mem={before[2] == after[2]} fp={before[3] == after[3]}")

        bk = pf.preflight(db, ADMIN)[0]["candidates"]["backup_role"]
        rec("RN.04_backup_tool_rules_and_preflight_still_accept_the_renewed_role",
            bk["violations"] == [] and pf.tool_violations(db, "jw_backup_ro") == [] and bk["tables_unreadable"] == 0
            and bk["tables_writable"] == 0 and bk["connection_limit"] == 2, json.dumps(bk)[:200])

        # refusals: each leaves the expiry and everything else exactly as it was
        keep_until, keep_state = pf.scalar(db, VALID_UNTIL), state(db)
        refusals = {"past": renew(db, "2000-01-01 00:00:00+00"),
                    "too_far": renew(db, cg.until(30)),
                    "missing_variable": renew(db, None)}
        unchanged = pf.scalar(db, VALID_UNTIL) == keep_until and state(db) == keep_state
        pf.psql(db, user=ADMIN, file=cg.ROLLBACK_SQL)
        no_role = renew(db, cg.until(2))
        rec("RN.05_refuses_past_window_beyond_seven_days_missing_variable_and_missing_role_without_any_change",
            all(p.returncode != 0 for p in refusals.values()) and unchanged
            and "renewal window" in refusals["past"].stderr and "renewal window" in refusals["too_far"].stderr
            and no_role.returncode != 0 and "does not exist" in no_role.stderr
            and pf.scalar(db, "SELECT count(*) FROM pg_roles WHERE rolname='jw_backup_ro'") == "0",
            " | ".join(f"{k}:{p.returncode}:{p.stderr[-70:]}" for k, p in refusals.items()) + f" | role:{no_role.stderr[-70:]}")

        text, rtext = RENEW.read_text(), REVOKE.read_text()
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("--"))
        rec("RN.06_renew_file_is_one_transaction_one_alter_and_has_no_password_dsn_grant_or_ddl",
            code.count("ALTER ROLE") == 1 and "VALID UNTIL :'valid_until'" in code and "BEGIN;" in code and "COMMIT;" in code
            and not re.search(r"(?i)\b(password|grant|revoke|create|drop)\b|postgres(?:ql)?://", code)
            and not re.search(r"(?i)password\s*['\"]|postgres(?:ql)?://|secret|token", rtext), "")

        # revoke: needs a fresh C, an open session, and pg_signal_backend for the admin (the observed admin has it)
        cg.run_c(db, ADMIN)
        pf.psql(db, user=ADMIN, sql=f"ALTER ROLE jw_backup_ro PASSWORD '{pw}'")
        pf.psql("postgres", sql=f"GRANT pg_signal_backend TO {ADMIN}")
        holder = subprocess.Popen(["psql", "-X", "-q", "-d", db, "-U", "jw_backup_ro", "-c", "SELECT pg_sleep(30)"],
                                  env=dict(os.environ, PGPASSWORD=pw), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        opened = pf.scalar(db, "SELECT count(*) FROM pg_stat_activity WHERE usename='jw_backup_ro'")
        rv = cg.run_c(db, ADMIN, file=REVOKE)
        try:
            holder.wait(timeout=20)
        except subprocess.TimeoutExpired:
            holder.kill()
        gone = pf.scalar(db, "SELECT count(*) FROM pg_stat_activity WHERE usename='jw_backup_ro'")
        blocked = cg.login_ok(db, "jw_backup_ro")
        rec("RN.07_revoke_stops_new_logins_and_ends_open_sessions_and_renewal_does_not_reenable_login",
            int(opened) >= 1 and rv.returncode == 0 and gone == "0" and blocked.returncode != 0
            and "not permitted to log in" in blocked.stderr
            and renew(db, cg.until(2)).returncode == 0 and cg.login_ok(db, "jw_backup_ro").returncode != 0
            and pf.psql(db, user=ADMIN, sql="ALTER ROLE jw_backup_ro LOGIN").returncode == 0
            and cg.login_ok(db, "jw_backup_ro").returncode == 0,
            f"opened={opened} gone={gone} rc={rv.returncode} {rv.stderr[-100:]} {blocked.stderr[-80:]}")

        # the test-only membership must be gone again before the pre-C fingerprint is compared (the fingerprint covers memberships)
        pf.psql("postgres", sql=f"REVOKE pg_signal_backend FROM {ADMIN}")
        rb = pf.psql(db, user=ADMIN, file=cg.ROLLBACK_SQL)
        left = pf.scalar(db, "SELECT (SELECT count(*) FROM pg_roles WHERE rolname='jw_backup_ro')"
                             "+(SELECT count(*) FROM pg_shdepend d JOIN pg_roles r ON r.oid=d.refobjid WHERE r.rolname='jw_backup_ro')")
        rec("RN.08_existing_rollback_sql_removes_the_renewed_role_and_restores_the_pre_C_fingerprint",
            rb.returncode == 0 and left == "0" and pf.scalar(db, cg.FP) == base_fp, f"{rb.stderr[-120:]} left={left}")
    finally:
        pf.psql("postgres", sql=f"REVOKE pg_signal_backend FROM {ADMIN}")
        cg.drop_everything()
        pf.cleanup(db)


def main() -> int:
    gate.local_server_or_die()
    server = pf.scalar("postgres", "SHOW server_version_num")
    if not server.isdigit() or (int(server) < 170000 and "--allow-pg16-local" not in sys.argv):
        print("BLOCKED: PostgreSQL 17 required (pass --allow-pg16-local for supplemental local evidence)")
        return 2
    if os.environ.get("PGHOST", "").startswith("/"):
        print("BLOCKED: this gate needs a TCP+password server (the login checks are meaningless on a trust socket)")
        return 2
    pf.cleanup(None)
    cg.drop_everything()
    main_phase()
    failed = [n for n, ok, _ in results if not ok]
    names = [re.match(r"RN\.\d+", n).group(0) for n, _, _ in results]
    ok = not failed and names == EXPECTED
    print(json.dumps({"server_version_num": server, "total": len(results), "expected": len(EXPECTED), "failed": failed}))
    print(("PASS" if ok else "FAIL") + f": {len(results)} checks, {len(failed)} failed, expected exactly {len(EXPECTED)}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
