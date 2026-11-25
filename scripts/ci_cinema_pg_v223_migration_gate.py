#!/usr/bin/env python3
"""V22.3 dev-DB migration CANDIDATES on a disposable PostgreSQL: apply, attack, roll back, re-apply.

  JW_CINEMA_PG_DISPOSABLE=1 PGHOST=127.0.0.1 ... python3 -m scripts.ci_cinema_pg_v223_migration_gate

Candidates under test (none is applied to Supabase by this script or by CI):
  * scripts/review/cinema_pg_v223_quote_two_person_proposal.sql  + _rollback.sql
  * scripts/review/cinema_pg_v223_terms_proposal.sql + _disable.sql / _enable.sql (lossless) + _rollback.sql (hard)
  * scripts/review/cinema_pg_v223_backup_role_proposal.sql + _rollback.sql, run by a NON-superuser admin role
    shaped like the observed Supabase ``postgres`` (LOGIN CREATEROLE BYPASSRLS, ADMIN-only member of
    jw_cinema_owner, owner of jw_dev and the legacy tables). The fidelity of that imitation is limited to
    those attributes; it is not the Supabase project.
Also: the "RLS enabled, no policy" tables of the repository schema are checked to be deny-all for the
API roles (anon, authenticated, jw_app_dev, jw_cinema_writer). That proves the REPOSITORY schema's intent,
not the live database's grants.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
from datetime import date, timedelta
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import pg_cinema_legacy_api_v1 as legacy  # noqa: E402
from scripts import ci_cinema_pg_sql_gate as gate  # noqa: E402
from scripts import pg_backup_v223 as pb  # noqa: E402

REV = ROOT / "scripts/review"
TWO, TWO_RB = REV / "cinema_pg_v223_quote_two_person_proposal.sql", REV / "cinema_pg_v223_quote_two_person_rollback.sql"
TERMS, T_OFF, T_ON, T_RB = (REV / "cinema_pg_v223_terms_proposal.sql", REV / "cinema_pg_v223_terms_disable.sql",
                            REV / "cinema_pg_v223_terms_enable.sql", REV / "cinema_pg_v223_terms_rollback.sql")
BK, BK_RB = REV / "cinema_pg_v223_backup_role_proposal.sql", REV / "cinema_pg_v223_backup_role_rollback.sql"
EXPECTED_CHECKS = 36
SIM_ADMIN, SIM_PW, BK_PW = "jw_sim_supabase_admin", "ci-only-" + secrets.token_hex(8), "ci-only-" + secrets.token_hex(8)
results: list[tuple[str, bool, str]] = []


def rec(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, "" if ok else detail[:300])


class DB:
    def __init__(self, name: str):
        self.name = name

    def psql(self, path: Path, user: str | None = None, password: str | None = None, *, vars_: dict | None = None):
        cmd = ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-d", self.name, "-f", str(path)]
        for k, v in (vars_ or {}).items():
            cmd += ["-v", f"{k}={v}"]
        env = dict(os.environ)
        if user:
            cmd += ["-U", user]
            env["PGPASSWORD"] = password or ""
        return subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=env)

    def conn(self, user: str | None = None, password: str | None = None, autocommit: bool = True):
        kw = {"dbname": self.name, "autocommit": autocommit}
        if user:
            kw.update(user=user, password=password)
        return psycopg.connect(**kw)

    def q(self, sql: str, params: tuple = ()):
        with self.conn() as c:
            cur = c.execute(sql, params)
            return cur.fetchall() if cur.description else None

    def one(self, sql: str, params: tuple = ()):
        rows = self.q(sql, params)
        return rows[0][0] if rows else None

    def as_writer(self, session_hash: str, sql: str, params: tuple = ()):
        """(sqlstate or 'OK', rows) for ``sql`` run as jw_cinema_writer with this session."""
        with self.conn(autocommit=False) as c:
            try:
                with c.transaction(), c.cursor() as cur:
                    cur.execute("SET LOCAL ROLE jw_cinema_writer")
                    cur.execute("SELECT set_config('jw.session_hash', %s, true)", (session_hash,))
                    cur.execute(sql, params)
                    return "OK", (cur.fetchall() if cur.description else None)
            except psycopg.Error as exc:
                return exc.sqlstate or "?????", None


def state_of(p: subprocess.CompletedProcess) -> str:
    import re
    m = re.search(r"ERROR:\s+([0-9A-Z]{5}):", p.stderr)
    return m.group(1) if m else ("OK" if p.returncode == 0 else "?????")


def make_db(admin: gate.Psql, with_terms: bool) -> DB:
    name = "jw_cinema_mig_" + secrets.token_hex(4)
    if admin.sql(f"CREATE DATABASE {name}").returncode != 0:
        raise SystemExit("BLOCKED: cannot create disposable database")
    psq = gate.Psql(name)
    for role in ("jw_app_dev", "jw_auth_stage_v85", "anon", "authenticated", "service_role"):
        admin.sql(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{role}') "
                  f"THEN CREATE ROLE {role} NOLOGIN NOINHERIT NOBYPASSRLS; END IF; END $$")
    for path in gate.BASE_FILES:
        if psq.file(path).returncode != 0:
            raise SystemExit(f"FAIL: base schema {path}")
    if psq.file(gate.ENGINE, single_transaction=True).returncode != 0 or psq.file(gate.TESTS).returncode != 0:
        raise SystemExit("FAIL: engine or fixtures")
    db = DB(name)
    if with_terms and db.psql(TERMS).returncode != 0:
        raise SystemExit("FAIL: terms proposal")
    return db


def session(db: DB, user: str) -> str:
    token = secrets.token_urlsafe(32)
    hashed = hashlib.sha256(token.encode()).hexdigest()
    db.q("INSERT INTO jw_dev.sessions(id,token_hash,user_id,expires_at,csrf_token,created_at) VALUES "
         "(%s,%s,%s,(now()+interval '1 hour')::text,'c',now()::text)", ("m-" + secrets.token_hex(5), hashed, user))
    return hashed


def open_order(db: DB, a1: str, a2: str) -> str:
    """A fresh open order of tenant A (two different admins submit/approve)."""
    def call(h, fn, *args):
        st, rows = db.as_writer(h, f"SELECT jw_dev.{fn}({','.join(['%s'] * len(args))})", args)
        assert st == "OK", (fn, st)
        return rows[0][0]["entity"]["id"]
    rid = lambda: "mig-" + secrets.token_hex(8)  # noqa: E731
    partner = db.one("SELECT id FROM jw_dev.cinema_pg_partners WHERE org_id='ci-a' LIMIT 1")
    q = call(a1, "cinema_pg_quote_create", rid(), partner, "mig", "taxable",
             json.dumps([{"name": "x", "quantity": 1, "unit_price": 100}]))
    call(a1, "cinema_pg_quote_transition", rid(), q, 1, "submitted")
    call(a2, "cinema_pg_quote_transition", rid(), q, 2, "approved")
    return call(a1, "cinema_pg_order_create", rid(), q)


# ------------------------------------------------------------------------- scenarios
def two_person(db: DB, a1: str, a2: str) -> None:
    p = db.psql(TWO)
    rec("M2.01_two_person_applies", p.returncode == 0, p.stderr[-200:])
    rb = db.psql(TWO_RB)
    rec("M2.02_rollback_removes_only_the_constraint", rb.returncode == 0 and
        db.one("SELECT count(*) FROM pg_constraint WHERE conname='cinema_pg_quote_two_person'") == 0, rb.stderr[-200:])
    rec("M2.03_rollback_is_idempotent", db.psql(TWO_RB).returncode == 0)
    again = db.psql(TWO)
    rec("M2.04_reapply_after_rollback", again.returncode == 0 and
        db.one("SELECT convalidated::text FROM pg_constraint WHERE conname='cinema_pg_quote_two_person'") == "false", again.stderr[-200:])
    twice = db.psql(TWO)
    rec("M2.05_second_apply_is_refused_not_duplicated", twice.returncode != 0 and
        db.one("SELECT count(*) FROM pg_constraint WHERE conname='cinema_pg_quote_two_person'") == 1, twice.stderr[-120:])


def terms(db: DB, a1: str, a2: str, member: str, b1: str) -> None:
    order = open_order(db, a1, a2)
    due = (date.today() + timedelta(days=10)).isoformat()
    st, _ = db.as_writer(a1, "SELECT jw_dev.cinema_pg_order_terms_set(%s,%s,%s)", ("mig-due-0000001", order, due))
    rec("MT.01_due_date_set_through_function", st == "OK", st)
    # two sessions race to set the due date of ANOTHER open order: exactly one wins
    order2 = open_order(db, a1, a2)
    outs: list[str] = []
    def race(i):
        s, _ = db.as_writer(a1 if i % 2 else a2, "SELECT jw_dev.cinema_pg_order_terms_set(%s,%s,%s)",
                            (f"mig-race-{i:08d}", order2, due))
        outs.append(s)
    ts = [threading.Thread(target=race, args=(i,)) for i in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    rec("MT.02_concurrent_due_date_exactly_one_wins", outs.count("OK") == 1 and
        db.one("SELECT count(*) FROM jw_dev.cinema_pg_order_terms WHERE order_id=%s", (order2,)) == 1, str(sorted(outs)))
    for role in ("anon", "authenticated", "jw_app_dev"):
        ok = db.one(f"SELECT NOT has_function_privilege('{role}','jw_dev.cinema_pg_order_terms_set(text,text,date)','EXECUTE') "
                    f"AND NOT has_table_privilege('{role}','jw_dev.cinema_pg_order_terms','SELECT')")
        rec(f"MT.03_{role}_cannot_execute_or_read_terms", ok is True)
    st, _ = db.as_writer(member, "SELECT jw_dev.cinema_pg_order_terms_set(%s,%s,%s)", ("mig-due-mem-001", open_order(db, a1, a2), due))
    rec("MT.04_member_cannot_set_due_date", st == "42501", st)
    st, rows = db.as_writer(b1, "SELECT count(*) FROM jw_dev.cinema_pg_order_terms")
    rec("MT.05_other_tenant_sees_no_terms_rows", st == "OK" and rows[0][0] == 0, f"{st} {rows}")

    stored = db.one("SELECT count(*) FROM jw_dev.cinema_pg_order_terms")
    off = db.psql(T_OFF)
    st, _ = db.as_writer(a1, "SELECT jw_dev.cinema_pg_order_terms_set(%s,%s,%s)", ("mig-due-off-001", open_order(db, a1, a2), due))
    rec("MT.06_disable_blocks_new_terms_for_writer", off.returncode == 0 and st == "42501", f"{off.stderr[-100:]} {st}")
    st, rows = db.as_writer(a1, "SELECT due_date::text FROM jw_dev.cinema_pg_order_terms WHERE order_id=%s", (order,))
    rec("MT.07_disable_keeps_stored_rows_readable", st == "OK" and rows == [(due,)] and
        db.one("SELECT count(*) FROM jw_dev.cinema_pg_order_terms") == stored, f"{st} {rows}")
    seen = legacy.WriterTx(lambda: db.conn(autocommit=False)).run(
        a1, lambda cur: legacy._fn_exists(cur, "jw_dev.cinema_pg_order_terms_set(text,text,date)"))
    rec("MT.08_router_sees_terms_disabled_and_will_refuse_not_drop", seen is False, str(seen))
    on = db.psql(T_ON)
    seen = legacy.WriterTx(lambda: db.conn(autocommit=False)).run(
        a1, lambda cur: legacy._fn_exists(cur, "jw_dev.cinema_pg_order_terms_set(text,text,date)"))
    rec("MT.09_enable_restores_writer_execute", on.returncode == 0 and seen is True, on.stderr[-100:])
    hard = db.psql(T_RB)
    rec("MT.10_hard_rollback_refused_while_rows_exist", hard.returncode != 0 and state_of(hard) == "55000" and
        db.one("SELECT count(*) FROM jw_dev.cinema_pg_order_terms") == stored and
        db.one("SELECT to_regclass('jw_dev.cinema_pg_order_terms') IS NOT NULL") is True, hard.stderr[-200:])


def hard_rollback_on_empty(admin: gate.Psql) -> None:
    db = make_db(admin, with_terms=True)
    try:
        rb = db.psql(T_RB)
        gone = db.one("SELECT to_regclass('jw_dev.cinema_pg_order_terms') IS NULL AND "
                      "to_regprocedure('jw_dev.cinema_pg_payment_note_set(text,text,text)') IS NULL")
        rec("MT.11_hard_rollback_on_empty_tables_removes_everything", rb.returncode == 0 and gone is True, rb.stderr[-200:])
        rec("MT.12_owner_membership_not_left_behind_by_rollback", db.one(
            "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member "
            "WHERE r.rolname='jw_cinema_owner' AND u.rolname=session_user") == 0)
        again = db.psql(TERMS)
        rec("MT.13_reapply_after_hard_rollback", again.returncode == 0 and
            db.one("SELECT to_regclass('jw_dev.cinema_pg_payment_notes') IS NOT NULL") is True, again.stderr[-200:])
    finally:
        admin.sql(f"DROP DATABASE IF EXISTS {db.name} WITH (FORCE)")


def backup_role(db: DB, admin: gate.Psql) -> None:
    owner_tables = db.one("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                          "WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p')")
    # imitate the observed Supabase shape: admin = LOGIN CREATEROLE BYPASSRLS, not superuser,
    # owns jw_dev and every table that jw_cinema_owner does not own; ADMIN-only member of jw_cinema_owner.
    for stmt in (f"DROP ROLE IF EXISTS {SIM_ADMIN}",
                 f"CREATE ROLE {SIM_ADMIN} LOGIN CREATEROLE BYPASSRLS NOSUPERUSER PASSWORD '{SIM_PW}'",
                 f"GRANT jw_cinema_owner TO {SIM_ADMIN} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"):
        db.q(stmt)
    db.q(f"ALTER SCHEMA jw_dev OWNER TO {SIM_ADMIN}")
    for (rel,) in db.q("SELECT c.oid::regclass::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                       "JOIN pg_roles o ON o.oid=c.relowner WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p','S') "
                       "AND o.rolname<>'jw_cinema_owner' AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid=c.oid "
                       "AND d.deptype IN ('a','i'))"):
        db.q(f"ALTER TABLE {rel} OWNER TO {SIM_ADMIN}")     # tables and free-standing sequences
    rec("MB.00_simulated_admin_is_not_superuser", db.one(f"SELECT NOT rolsuper AND rolcreaterole AND rolbypassrls "
                                                          f"FROM pg_roles WHERE rolname='{SIM_ADMIN}'") is True)
    until = (date.today() + timedelta(days=2)).isoformat() + " 00:00:00+09"
    broken = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / f"jw_bk_broken_{secrets.token_hex(4)}.sql"
    broken.write_text(BK.read_text().replace("GRANT SELECT ON ALL SEQUENCES IN SCHEMA jw_dev TO jw_backup_ro;",
                                             "GRANT SELECT ON jw_dev.no_such_table_v223 TO jw_backup_ro;"))
    bp = db.psql(broken, SIM_ADMIN, SIM_PW, vars_={"valid_until": until})
    broken.unlink(missing_ok=True)
    rec("MB.00b_failing_recipe_leaves_no_role_and_no_temporary_membership", bp.returncode != 0 and
        db.one("SELECT count(*) FROM pg_roles WHERE rolname='jw_backup_ro'") == 0 and db.one(
            "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member "
            f"WHERE r.rolname='jw_cinema_owner' AND u.rolname='{SIM_ADMIN}' AND m.inherit_option") == 0, bp.stderr[-200:])
    p = db.psql(BK, SIM_ADMIN, SIM_PW, vars_={"valid_until": until})
    warnings = [l for l in p.stderr.splitlines() if "no privileges were granted" in l]
    rec("MB.01_recipe_runs_as_non_superuser_admin_without_grant_warnings", p.returncode == 0 and not warnings,
        p.stderr[-300:])
    db.q(f"ALTER ROLE jw_backup_ro PASSWORD '{BK_PW}'")            # CI only; the real one is typed by the owner
    with db.conn("jw_backup_ro", BK_PW) as c:
        facts = pb.fetch_role_facts(c, "jw_dev")
        refusals = pb.evaluate_source_privileges(facts)
        readable = c.execute("SELECT count(*) FILTER (WHERE has_table_privilege(c.oid,'SELECT')), count(*) FILTER (WHERE "
                             "has_table_privilege(c.oid,'INSERT') OR has_table_privilege(c.oid,'UPDATE') OR "
                             "has_table_privilege(c.oid,'DELETE') OR has_table_privilege(c.oid,'TRUNCATE')) FROM pg_class c "
                             "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p')").fetchone()
        rows_seen = c.execute("SELECT count(*) FROM jw_dev.cinema_pg_quotes").fetchone()[0]
        try:
            c.execute("INSERT INTO jw_dev.organizations(id,name,created_at) VALUES ('x','x','x')")
            write_state = "OK"
        except psycopg.Error as exc:
            write_state = exc.sqlstate
        try:
            c.execute("SET ROLE jw_cinema_owner")
            setrole = "OK"
        except psycopg.Error as exc:
            setrole = exc.sqlstate
    rec("MB.02_backup_tool_least_privilege_check_accepts_the_role", refusals == [], str(refusals))
    rec("MB.03_every_jw_dev_table_readable_none_writable", readable == (owner_tables, 0), f"{readable} of {owner_tables}")
    rec("MB.04_force_rls_cinema_rows_fully_visible",
        rows_seen == db.one("SELECT count(*) FROM jw_dev.cinema_pg_quotes") and rows_seen > 0, str(rows_seen))
    rec("MB.05_session_is_read_only", write_state == "25006", str(write_state))
    rec("MB.06_cannot_switch_to_owner_role", setrole == "42501", str(setrole))
    rec("MB.07_admin_back_to_admin_only_membership", db.one(
        "SELECT bool_and(m.admin_option AND NOT m.inherit_option AND NOT m.set_option) AND count(*)=1 FROM pg_auth_members m "
        f"JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE r.rolname='jw_cinema_owner' AND u.rolname='{SIM_ADMIN}'") is True)
    rec("MB.08_no_pg_read_all_data_shortcut", db.one(
        "SELECT NOT pg_has_role('jw_backup_ro','pg_read_all_data','MEMBER')") is True)
    rb = db.psql(BK_RB, SIM_ADMIN, SIM_PW)
    rec("MB.09_rollback_removes_the_role", rb.returncode == 0 and db.one("SELECT count(*) FROM pg_roles WHERE rolname='jw_backup_ro'") == 0, rb.stderr[-200:])
    rec("MB.10_rollback_is_idempotent", db.psql(BK_RB, SIM_ADMIN, SIM_PW).returncode == 0)


def rls_no_policy(db: DB, a1: str) -> None:
    tables = [r[0] for r in db.q(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='jw_dev' "
        "AND c.relkind='r' AND c.relrowsecurity AND NOT EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname='jw_dev' "
        "AND p.tablename=c.relname) ORDER BY 1")]
    rec("MR.01_rls_enabled_no_policy_tables_listed", True, ",".join(tables))
    leaks = []
    for t in tables:
        for role in ("anon", "authenticated", "jw_app_dev", "jw_cinema_writer"):
            if db.one(f"SELECT has_table_privilege('{role}','jw_dev.{t}','SELECT') OR has_table_privilege('{role}','jw_dev.{t}','INSERT')"):
                with db.conn(autocommit=False) as c:
                    try:
                        with c.transaction():
                            c.execute(f"SET LOCAL ROLE {role}")
                            c.execute("SELECT set_config('jw.session_hash', %s, true)", (a1,))
                            n = c.execute(f"SELECT count(*) FROM jw_dev.{t}").fetchone()[0]
                    except psycopg.Error:
                        n = 0
                if n:
                    leaks.append(f"{role}:{t}:{n}")
    print("INFO MR rls-no-policy tables:", tables)
    rec("MR.02_no_api_role_reads_rows_from_policy_free_rls_tables", not leaks, ",".join(leaks))
    sensitive = [t for t in tables if t in ("sessions", "users", "mfa_credentials")]
    rec("MR.03_sessions_users_mfa_are_among_the_deny_all_tables_or_absent", all(
        db.one(f"SELECT NOT has_table_privilege('anon','jw_dev.{t}','SELECT') AND NOT has_table_privilege('authenticated','jw_dev.{t}','SELECT')")
        for t in sensitive), ",".join(sensitive))


def main() -> int:
    gate.local_server_or_die()
    admin = gate.Psql("postgres")
    server = admin.sql("SHOW server_version_num").stdout.strip()
    if not server.isdigit() or (int(server) < 170000 and "--allow-pg16-local" not in sys.argv):
        print("BLOCKED: PostgreSQL 17 required")
        return 2
    db = make_db(admin, with_terms=False)
    try:
        a1, a2, member, b1 = session(db, "ci-ua"), session(db, "ci-ua2"), session(db, "ci-ua3"), session(db, "ci-ub")
        two_person(db, a1, a2)
        p = db.psql(TERMS)
        rec("MT.00_terms_apply", p.returncode == 0, p.stderr[-200:])
        terms(db, a1, a2, member, b1)
        rls_no_policy(db, a1)
        backup_role(db, admin)
    finally:
        if os.environ.get("JW_CINEMA_KEEP_DB") != "1":
            admin.sql(f"DROP DATABASE IF EXISTS {db.name} WITH (FORCE)")
            admin.sql("DROP ROLE IF EXISTS jw_backup_ro")
            admin.sql(f"DROP ROLE IF EXISTS {SIM_ADMIN}")
    hard_rollback_on_empty(admin)
    failed = [n for n, ok, _ in results if not ok]
    names = [n for n, _, _ in results]
    ok = not failed and len(set(names)) == len(names) and len(results) == EXPECTED_CHECKS
    print(json.dumps({"server_version_num": server, "total": len(results), "expected": EXPECTED_CHECKS, "failed": failed}))
    print(("PASS" if ok else "FAIL") + f": {len(results)} checks, {len(failed)} failed, expected exactly {EXPECTED_CHECKS}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
