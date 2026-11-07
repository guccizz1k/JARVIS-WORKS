#!/usr/bin/env python3
"""V22.3 Track B (issue #140): gate for applying change C ALONE (the jw_backup_ro proposal) on a database that has the
observed Supabase privilege model. psql client + standard library only; disposable local server (TCP, SCRAM) only.

  JW_CINEMA_PG_DISPOSABLE=1 PGHOST=127.0.0.1 PGPORT=… PGUSER=postgres PGPASSWORD=… \
      python3 -m scripts.ci_cinema_pg_v223_backup_role_c_gate [--allow-pg16-local]

Privilege model reproduced (as measured read-only on the live dev project, nothing was changed there):
  admin = LOGIN CREATEROLE BYPASSRLS NOSUPERUSER, owner of jw_dev and of the tables jw_cinema_owner does not own, and
  an ADMIN-only (no INHERIT, no SET) member of jw_cinema_owner, which owns the remaining tables.

What is proven (on the server it ran on; PG17 is the target, PG16 is supplemental evidence):
  * C commits as ONE transaction: the new role has exactly the intended attributes and no memberships, the admin's
    temporary INHERIT membership is gone again, the admin's pre-existing memberships are unchanged.
  * the backup tool's own least-privilege rules and the read-only preflight both accept the role (no violations).
  * the role cannot log in without a password, can after the owner sets one, cannot after expiry, is refused
    beyond CONNECTION LIMIT 2, and cannot write even after `SET default_transaction_read_only = off`.
  * a failure in the middle of C (injected) and a real failure (admin without ADMIN on jw_cinema_owner; admin without
    CREATEROLE; admin without BYPASSRLS) leave the database byte-for-byte unchanged (catalog + ACL + role + membership +
    row-count fingerprint), with and without ON_ERROR_STOP.
  * C with its COMMIT replaced by ROLLBACK (a dry run) leaves nothing behind.
  * the rollback SQL returns the database to the pre-C fingerprint and is idempotent; C can be applied again after it;
    applying C twice fails cleanly without side effects.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import ci_cinema_pg_sql_gate as gate  # noqa: E402
from scripts import ci_cinema_pg_v223_preflight_gate as pf  # noqa: E402

C_SQL, ROLLBACK_SQL = pf.BK, pf.BK_RB
ADMIN = pf.SIM_ADMIN
NO_ADMIN_OPT, NO_CREATEROLE, NO_BYPASS = "jw_sim_cg_noadminopt", "jw_sim_cg_nocreaterole", "jw_sim_cg_nobypass"
for _r in (NO_ADMIN_OPT, NO_CREATEROLE, NO_BYPASS):
    pf.PASSWORDS[_r] = "ci-only-" + secrets.token_hex(8)
EXPECTED = ["CG.01", "CG.02", "CG.03", "CG.04", "CG.05", "CG.06", "CG.07", "CG.08", "CG.09", "CG.10", "CG.11",
            "CG.12", "CG.13", "CG.14", "CG.15", "CG.16"]
results: list[tuple[str, bool, str]] = []

_RAW = "coalesce(c.relacl::text,'')"
assert _RAW in pf.FINGERPRINT
FP = pf.FINGERPRINT.replace(_RAW, "coalesce(c.relacl, acldefault((CASE c.relkind WHEN 'S' THEN 's' ELSE 'r' END)::\"char\", c.relowner))::text")
# relations whose ACL is stored explicitly although it equals the owner default (what GRANT + REVOKE leaves behind)
EXPLICIT_DEFAULT = ("SELECT coalesce(string_agg(c.relname||':'||c.relkind::text, ',' ORDER BY c.relname), '') FROM pg_class c "
                    "WHERE c.relnamespace='jw_dev'::regnamespace AND c.relacl IS NOT NULL "
                    "AND c.relacl = acldefault((CASE c.relkind WHEN 'S' THEN 's' ELSE 'r' END)::\"char\", c.relowner)")
ADMIN_MEMBERSHIPS = ("SELECT coalesce(string_agg(r.rolname||':'||left(m.admin_option::text,1)||left(m.inherit_option::text,1)||left(m.set_option::text,1),"
                     " ',' ORDER BY r.rolname), '') FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid "
                     f"JOIN pg_roles u ON u.oid=m.member WHERE u.rolname='{ADMIN}'")
ROLE_FACTS = ("SELECT concat_ws('|', a.rolcanlogin, a.rolbypassrls, a.rolsuper, a.rolcreatedb, a.rolcreaterole, a.rolreplication, "
              "a.rolconnlimit, a.rolvaliduntil > now(), coalesce(r.rolconfig::text,''), a.rolpassword IS NULL) "
              "FROM pg_authid a JOIN pg_roles r ON r.oid = a.oid WHERE a.rolname='jw_backup_ro'")


def rec(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail[:300])


def until(days: int = 2) -> str:
    return (date.today() + timedelta(days=days)).isoformat() + " 00:00:00+09"


def run_c(db: str, user: str, *, file: Path = C_SQL, on_error_stop: bool = True, valid_until: str | None = None):
    cmd = ["psql", "-X", "-q", "-A", "-t", "-d", db, "-U", user, "-v", f"valid_until={valid_until or until()}", "-f", str(file)]
    if on_error_stop:
        cmd[3:3] = ["-v", "ON_ERROR_STOP=1"]
    env = dict(os.environ, PGPASSWORD=pf.PASSWORDS.get(user, os.environ.get("PGPASSWORD", "")))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)


def variant(text: str, name: str) -> Path:
    path = Path(tempfile.mkdtemp(prefix="jwcg_")) / name
    path.write_text(text)
    return path


def login_ok(db: str, user: str, sql: str = "SELECT 1") -> subprocess.CompletedProcess:
    return pf.psql(db, user=user, sql=sql)


def fresh() -> str:
    db = pf.make_db()
    pf.shape_admin("postgres", db)
    return db


def drop_everything() -> None:
    for role in ("jw_backup_ro", NO_ADMIN_OPT, NO_CREATEROLE, NO_BYPASS):
        pf.psql("postgres", sql=f"DROP ROLE IF EXISTS {role}")


def phase_success_and_rollback() -> None:
    db = None
    try:
        db = fresh()
        base_fp, base_mem = pf.scalar(db, FP), pf.scalar(db, ADMIN_MEMBERSHIPS)
        base_residue = set(filter(None, pf.scalar(db, EXPLICIT_DEFAULT).split(",")))
        pre, _ = pf.preflight(db, ADMIN)
        rec("CG.01_premise_is_the_supabase_shape",
            pre["candidates"]["backup_role"] == {"exists": False} and base_mem.count(":") == 1
            and base_mem == "jw_cinema_owner:tff" and pf.scalar(db, f"SELECT rolcreaterole AND rolbypassrls AND NOT rolsuper "
                                                                  f"FROM pg_roles WHERE rolname='{ADMIN}'") == "t"
            and pf.scalar(db, f"SELECT has_table_privilege('{ADMIN}','jw_dev.cinema_pg_quotes','SELECT')") == "f",
            f"{base_mem} {json.dumps(pre['candidates']['backup_role'])}")

        done = run_c(db, ADMIN)
        facts = pf.scalar(db, ROLE_FACTS)
        rec("CG.02_C_commits_and_role_has_exactly_the_intended_attributes",
            done.returncode == 0 and facts == "t|t|f|f|f|f|2|t|{default_transaction_read_only=on}|t"
            and pf.scalar(db, "SELECT count(*) FROM pg_auth_members m JOIN pg_roles u ON u.oid=m.member "
                              "WHERE u.rolname='jw_backup_ro'") == "0", f"{done.stderr[-200:]} {facts}")
        mem_after = pf.scalar(db, ADMIN_MEMBERSHIPS)
        rows = set(mem_after.split(","))
        rec("CG.03_temporary_membership_is_gone_and_admin_gets_admin_only_on_the_new_role",
            rows == {"jw_cinema_owner:tff", "jw_backup_ro:tff"} and "jw_cinema_owner:tff" in base_mem, mem_after)

        pf.PASSWORDS.pop("jw_backup_ro", None)
        no_pw = login_ok(db, "jw_backup_ro")          # no password exists yet: SCRAM must refuse
        pw = secrets.token_hex(16)
        pf.PASSWORDS["jw_backup_ro"] = pw
        setpw = pf.psql(db, user=ADMIN, sql=f"ALTER ROLE jw_backup_ro PASSWORD '{pw}'")
        as_admin, _ = pf.preflight(db, ADMIN)
        bk = as_admin["candidates"]["backup_role"]
        tables = int(pf.scalar(db, "SELECT count(*) FROM pg_class WHERE relnamespace='jw_dev'::regnamespace AND relkind IN ('r','p')"))
        seqs = int(pf.scalar(db, "SELECT count(*) FROM pg_class WHERE relnamespace='jw_dev'::regnamespace AND relkind='S'"))
        sel = pf.scalar(db, "SELECT count(*) FILTER (WHERE has_table_privilege('jw_backup_ro', c.oid, 'SELECT')) FROM pg_class c "
                            "WHERE c.relnamespace='jw_dev'::regnamespace AND c.relkind IN ('r','p')")
        sq = pf.scalar(db, "SELECT count(*) FILTER (WHERE has_sequence_privilege('jw_backup_ro', c.oid, 'SELECT')) FROM pg_class c "
                           "WHERE c.relnamespace='jw_dev'::regnamespace AND c.relkind='S'")
        rec("CG.04_backup_tool_rules_and_preflight_accept_the_role",
            bk["violations"] == [] and pf.tool_violations(db, "jw_backup_ro") == [] and int(sel) == tables
            and int(sq) == seqs and tables > 0 and seqs > 0 and bk["tables_unreadable"] == 0,
            f"{bk['violations']} {sel}/{tables} {sq}/{seqs}")

        with_pw = login_ok(db, "jw_backup_ro", "SHOW default_transaction_read_only")
        wfile = variant("SET default_transaction_read_only = off;\n"
                        "INSERT INTO jw_dev.organizations(id,name,created_at) VALUES ('cg-w','x','x');\n", "write_try.sql")
        wr = pf.psql(db, user="jw_backup_ro", file=wfile)      # two statements, two transactions: the SET really applies
        rec("CG.05_no_login_without_password_login_with_it_and_never_writable",
            no_pw.returncode != 0 and "authentication failed" in no_pw.stderr and setpw.returncode == 0
            and with_pw.returncode == 0 and with_pw.stdout.strip() == "on"
            and wr.returncode != 0 and "permission denied" in wr.stderr, f"{no_pw.stderr[-80:]}|{wr.stderr[-120:]}")

        pf.psql(db, user=ADMIN, sql="ALTER ROLE jw_backup_ro VALID UNTIL '2000-01-01 00:00:00+00'")
        expired = login_ok(db, "jw_backup_ro")
        pf.psql(db, user=ADMIN, sql=f"ALTER ROLE jw_backup_ro VALID UNTIL '{until()}'")
        renewed = login_ok(db, "jw_backup_ro")
        rec("CG.06_expiry_blocks_login_and_renewal_restores_it",
            expired.returncode != 0 and "authentication failed" in expired.stderr and renewed.returncode == 0, expired.stderr[-120:])

        holders = [subprocess.Popen(["psql", "-X", "-q", "-d", db, "-U", "jw_backup_ro", "-c", "SELECT pg_sleep(6)"],
                                    env=dict(os.environ, PGPASSWORD=pw), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                   for _ in range(2)]
        time.sleep(2)
        third = login_ok(db, "jw_backup_ro")
        for h in holders:
            h.wait(timeout=30)
        rec("CG.07_connection_limit_two_refuses_a_third_session",
            third.returncode != 0 and "too many connections" in third.stderr, third.stderr[-120:])

        pf.psql(db, user=ADMIN, sql="ALTER ROLE jw_backup_ro PASSWORD NULL")
        rb = pf.psql(db, user=ADMIN, file=ROLLBACK_SQL)
        rb_fp, rb_mem = pf.scalar(db, FP), pf.scalar(db, ADMIN_MEMBERSHIPS)
        again = pf.psql(db, user=ADMIN, file=ROLLBACK_SQL)
        left = pf.scalar(db, "SELECT (SELECT count(*) FROM pg_roles WHERE rolname='jw_backup_ro')"
                             "+(SELECT count(*) FROM pg_shdepend d JOIN pg_roles r ON r.oid=d.refobjid WHERE r.rolname='jw_backup_ro')")
        residue = set(filter(None, pf.scalar(db, EXPLICIT_DEFAULT).split(",")))
        new_residue = residue - base_residue
        rec("CG.08_rollback_restores_the_pre_C_fingerprint_and_is_idempotent",
            rb.returncode == 0 and again.returncode == 0 and rb_fp == base_fp and rb_mem == base_mem and left == "0"
            and all(item.endswith(":S") for item in new_residue),
            f"{rb.stderr[-120:]} fp_equal={rb_fp == base_fp} mem={rb_mem} new_explicit_default_acl={sorted(new_residue)}")
        print("NOTE rollback leaves", len(new_residue), "sequence(s) with an explicit owner-only ACL (was NULL): "
              "semantically identical, pg_dump prints no GRANT for it")

        second = run_c(db, ADMIN)
        dup = run_c(db, ADMIN)
        again_state = pf.scalar(db, ROLE_FACTS)
        rec("CG.09_reapply_after_rollback_works_and_double_apply_fails_cleanly",
            second.returncode == 0 and dup.returncode != 0 and "already exists" in dup.stderr
            and pf.scalar(db, ADMIN_MEMBERSHIPS) in ("jw_backup_ro:tff,jw_cinema_owner:tff",) and again_state.startswith("t|t|f|f|f|f|2|t"),
            f"{dup.stderr[-120:]} {pf.scalar(db, ADMIN_MEMBERSHIPS)}")
        pf.psql(db, user=ADMIN, file=ROLLBACK_SQL)
        rec("CG.10_after_the_second_cycle_the_database_is_pre_C_again", pf.scalar(db, FP) == base_fp, "")
    finally:
        drop_everything()
        pf.cleanup(db)


def phase_failures_and_dry_run() -> None:
    db = None
    try:
        db = fresh()
        base_fp, base_mem = pf.scalar(db, FP), pf.scalar(db, ADMIN_MEMBERSHIPS)
        sql = C_SQL.read_text()
        marker = "GRANT jw_cinema_owner TO CURRENT_USER WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;\n"
        assert marker in sql and sql.rstrip().endswith("COMMIT;")
        broken = variant(sql.replace(marker, marker + "GRANT USAGE ON SCHEMA jw_cg_missing_schema TO jw_backup_ro;\n"), "mid_failure.sql")
        stop = run_c(db, ADMIN, file=broken)
        nostop = run_c(db, ADMIN, file=broken, on_error_stop=False)
        rec("CG.11_failure_after_the_temporary_grant_rolls_everything_back",
            stop.returncode != 0 and "jw_cg_missing_schema" in stop.stderr and pf.scalar(db, FP) == base_fp
            and pf.scalar(db, ADMIN_MEMBERSHIPS) == base_mem and nostop.returncode in (0, 3)
            and pf.scalar(db, "SELECT count(*) FROM pg_roles WHERE rolname='jw_backup_ro'") == "0",
            f"{stop.stderr[-120:]} rc_nostop={nostop.returncode}")

        # real failure shapes: nobody must be able to create the role through a weaker admin
        for role, attrs, name in ((NO_ADMIN_OPT, "LOGIN CREATEROLE BYPASSRLS", "CG.12_admin_without_admin_option_on_jw_cinema_owner_fails_atomically"),
                                  (NO_CREATEROLE, "LOGIN BYPASSRLS", "CG.13_admin_without_createrole_fails_atomically"),
                                  (NO_BYPASS, "LOGIN CREATEROLE", "CG.14_admin_without_bypassrls_cannot_create_a_bypassrls_role")):
            pf.psql("postgres", sql=f"CREATE ROLE {role} {attrs} NOSUPERUSER PASSWORD '{pf.PASSWORDS[role]}'")
            pf.psql(db, sql=f"GRANT USAGE ON SCHEMA jw_dev TO {role}")
            before = pf.scalar(db, FP)
            out = run_c(db, role)
            after = pf.scalar(db, FP)
            err = out.stderr.lower()
            rec(name, out.returncode != 0 and before == after and ("permission denied" in err or "must" in err or "privilege" in err
                                                                    or "admin option" in err)
                and pf.scalar(db, "SELECT count(*) FROM pg_roles WHERE rolname='jw_backup_ro'") == "0", out.stderr[-200:])

        base_fp, base_mem = pf.scalar(db, FP), pf.scalar(db, ADMIN_MEMBERSHIPS)      # the helper roles above now belong to the baseline
        dry = variant(sql.rstrip()[:-len("COMMIT;")] + "SELECT 'in_txn:' || (SELECT count(*) FROM pg_roles WHERE rolname='jw_backup_ro')"
                      " || ':' || has_table_privilege('jw_backup_ro','jw_dev.cinema_pg_quotes','SELECT');\nROLLBACK;\n", "dry_run.sql")
        d = run_c(db, ADMIN, file=dry)
        rec("CG.15_dry_run_with_ROLLBACK_shows_the_effect_and_leaves_nothing",
            d.returncode == 0 and "in_txn:1:true" in d.stdout
            and pf.scalar(db, FP) == base_fp and pf.scalar(db, ADMIN_MEMBERSHIPS) == base_mem,
            d.stdout[-160:] + d.stderr[-160:])
        secrets_in_sql = re.search(r"(?i)password\s*['\"]|postgres(?:ql)?://|secret|token", sql)
        rec("CG.16_C_sql_contains_no_password_dsn_or_secret_and_takes_expiry_as_a_variable",
            not secrets_in_sql and ":'valid_until'" in sql and "NOSUPERUSER" in sql and "NOCREATEROLE" in sql
            and "CONNECTION LIMIT 2" in sql and "BEGIN;" in sql, str(secrets_in_sql))
    finally:
        drop_everything()
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
    drop_everything()
    phase_success_and_rollback()
    phase_failures_and_dry_run()
    failed = [n for n, ok, _ in results if not ok]
    names = [re.match(r"CG\.\d+", n).group(0) for n, _, _ in results]
    ok = not failed and names == EXPECTED
    print(json.dumps({"server_version_num": server, "total": len(results), "expected": len(EXPECTED), "failed": failed}))
    print(("PASS" if ok else "FAIL") + f": {len(results)} checks, {len(failed)} failed, expected exactly {len(EXPECTED)}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
