#!/usr/bin/env python3
"""P1 (S4 two-ledger claims) + P2 (least-privilege login role) candidate gate for the CINEMA PostgreSQL engine.

Disposable databases only: refuses to run unless JW_CINEMA_PG_DISPOSABLE=1 and PGHOST is a unix socket or a
loopback address. It creates its own throw-away database (and cluster-level test roles), applies the candidate
files under scripts/review/ exactly as written, attacks them, rolls them back and drops the database.
Emulates the Supabase dev shape: a non-superuser owner role (jw_mig_admin) owns jw_dev and the legacy tables and
holds only the ADMIN-only baseline membership in the CINEMA roles.

  python3 -I scripts/ci_cinema_pg_p1_p2_pg17_suite.py --report out.json            (CI: requires PostgreSQL 17)
  python3 -I scripts/ci_cinema_pg_p1_p2_pg17_suite.py --report out.json --allow-pg16-local   (supplemental only)

Exit status is non-zero on any failed check, on an unexpected number of checks (tests may not be silently
dropped), or when the server is not PostgreSQL 17 and --allow-pg16-local was not given."""
import json, os, re, runpy, secrets, subprocess, sys, tempfile, threading, time
from pathlib import Path
REPO = Path(__file__).resolve().parents[1]
REVIEW = REPO / "scripts/review"
ARGS = sys.argv[1:]
ALLOW_PG16 = "--allow-pg16-local" in ARGS
REPORT = Path(ARGS[ARGS.index("--report") + 1]) if "--report" in ARGS else Path("jw-cinema-pg-p1-p2-pg17.json")
# The 96 checks of the previous gate keep their exact names. They may not be deleted, renamed, merged or turned into skips:
# the run fails if any of them is missing. New checks are added on top, so the total below is exact, not "at least".
BASELINE_CHECKS = (
    'S4M.00z_original_file_requires_pg17',
    'S4M.00a_refuses_non_empty_ledger',
    'S4M.00b_refusal_leaves_no_residue',
    'S4M.00c_refuses_superuser_runner',
    'S4M.01_migration_applies_as_nonsuperuser_owner',
    'S4M.02_ten_enabled_triggers',
    'S4M.03_legacy_and_cinema_acl_restored_exactly',
    'S4M.04_schema_acl_restored_exactly',
    'S4M.05_no_effective_owner_membership',
    'S4M.06_existing_objects_fingerprint_unchanged',
    'S4M.07_claims_owned_by_cinema_owner_force_rls',
    'S4M.08_second_apply_refused',
    'S4A.01_legacy_first_blocks_cinema_same_tenant',
    'S4A.02_cinema_first_blocks_legacy_same_tenant',
    'S4A.03_other_tenants_unaffected',
    'S4X.claims_select_denied_for_jw_cinema_writer',
    'S4X.claims_insert_denied_for_jw_cinema_writer',
    'S4X.claims_update_denied_for_jw_cinema_writer',
    'S4X.claims_delete_denied_for_jw_cinema_writer',
    'S4X.claims_truncate_denied_for_jw_cinema_writer',
    'S4X.claims_select_denied_for_jw_app_dev',
    'S4X.claims_insert_denied_for_jw_app_dev',
    'S4X.claims_update_denied_for_jw_app_dev',
    'S4X.claims_delete_denied_for_jw_app_dev',
    'S4X.claims_truncate_denied_for_jw_app_dev',
    'S4X.writer_cannot_execute_claim_fn',
    'S4X.writer_cannot_disable_triggers_via_replication_role',
    'S4X.writer_cannot_alter_table_triggers',
    'S4X.app_cannot_alter_legacy_triggers',
    'S4X.app_cannot_drop_s4_trigger',
    'S4X.writer_cannot_truncate_cinema_quotes',
    'S4X.writer_cannot_move_cinema_quote_to_other_tenant',
    'S4X.org_move_cinema_blocked_by_s4_trigger_itself',
    'S4X.owner_path_org_move_blocked_legacy_by_s4_trigger_itself',
    'S4X.superuser_path_org_move_blocked_by_s4_trigger',
    'S4X.whitespace_org_id_rejected',
    'S4X.claim_survives_row_deletion',
    'S4X.same_tx_mixed_ledgers_blocked',
    'S4X.same_tx_failure_leaves_no_claim',
    'S4S.01_no_session_fails_closed',
    'S4S.02_forged_hash_fails_closed',
    'S4S.03_expired_session_fails_closed',
    'S4S.04_writer_cannot_read_sessions',
    'S4S.05_writer_cannot_read_users',
    'S4S.06_valid_session_A_creates_partner',
    'S4S.07_partner_row_tenant_is_session_org',
    'S4S.08_tenant_B_cannot_update_tenant_A_partner',
    'S4S.09_A_partner_unchanged',
    'S4S.10_same_request_id_other_tenant_no_replay_leak',
    'S4S.11_engine_quote_create_works_with_S4_trigger',
    'S4S.12_claim_created_by_engine_path',
    'S4S.13_tenant_B_cannot_trace_tenant_A_trade',
    'S4S.14_tenant_A_can_trace_own_trade',
    'S4S.15_legacy_insert_blocked_after_engine_claim',
    'S4S.16_local_guc_does_not_leak_to_next_tx_same_connection',
    'S4S.17_HAZARD_confirmed_session_level_set_leaks (app code uses only is_local=true)',
    'S4C.01_48_sessions_exactly_one_ledger_wins_per_tenant',
    'S4C.02_no_deadlock_and_only_expected_errors',
    'S4C.03_claims_rows_equal_tenant_count',
    'P2.00_no_password_or_secret_in_sql',
    'P2.01_login_role_sql_applies_as_nonsuperuser',
    'P2.02_attributes_exact',
    'P2.03_membership_only_writer_set_noinherit_noadmin',
    'P2.04_no_password_hash_stored',
    'P2.05_timeouts_and_pinned_search_path',
    'P2.06_login_can_connect_but_is_plain',
    'P2.07_direct_select_denied_cinema_pg_quotes',
    'P2.07_direct_select_denied_cinema_pg_partners',
    'P2.07_direct_select_denied_sessions',
    'P2.07_direct_select_denied_users',
    'P2.07_direct_select_denied_orders',
    'P2.07_direct_select_denied_cinema_pg_ledger_claims',
    'P2.08_direct_insert_denied',
    'P2.09_cannot_set_role_jw_cinema_owner',
    'P2.09_cannot_set_role_jw_mig_admin',
    'P2.09_cannot_set_role_jw_app_dev',
    'P2.09_cannot_set_role_jw_auth_stage_v85',
    'P2.09_cannot_set_role_postgres',
    'P2.10_denied_self_escalate',
    'P2.10_denied_self_bypassrls',
    'P2.10_denied_create_role',
    'P2.10_denied_disable_triggers',
    'P2.10_denied_grant_owner',
    'P2.10_denied_ddl',
    'P2.11_login_via_set_role_writer_valid_session_works',
    'P2.12_login_via_writer_without_session_fails_closed',
    'P2.13_login_via_writer_forged_hash_fails_closed',
    'P2.14_no_context_leak_on_next_connection',
    'P2.15_connection_limit_8_enforced',
    'P2.16_second_apply_refused',
    'P2.17_rollback_runs',
    'P2.18_rollback_removes_role_and_memberships',
    'P2.19_reapply_after_rollback_works',
    'S4M.09_rollback_runs',
    'S4M.10_rollback_restores_fingerprint_and_acl',
    'S4M.11_no_s4_objects_after_rollback',
)
EXPECTED_NEW_CHECKS = 80
EXPECTED_CHECKS = len(BASELINE_CHECKS) + EXPECTED_NEW_CHECKS
if os.environ.get("JW_CINEMA_PG_DISPOSABLE") != "1":
    raise SystemExit("BLOCKED: set JW_CINEMA_PG_DISPOSABLE=1 to confirm a throw-away local cluster")
_host = os.environ.get("PGHOST", "")
if not (_host.startswith("/") or _host in ("localhost", "127.0.0.1", "::1")):
    raise SystemExit("BLOCKED: PGHOST must be a unix socket directory or loopback address")
# Never run next to production or Supabase credentials. (PGPASSWORD is allowed for local throw-away clusters; the CI workflow
# additionally forbids it because its service container uses trust authentication.)
_FORBIDDEN_ENV = re.compile(r"^(SUPABASE_|DATABASE_URL$|POSTGRES_URL|POSTGRES_PRISMA_URL|RENDER_|PGSERVICE$|PGPASSFILE$|PGSSLROOTCERT$)")
_ENV_NAMES = sorted(k for k in os.environ if _FORBIDDEN_ENV.match(k))
_ENV_VALUES = sorted(k for k, v in os.environ.items() if re.search(r"supabase\.(co|com|net)|pooler\.supabase|onrender\.com", v, re.I))
if _ENV_NAMES or _ENV_VALUES:
    raise SystemExit("BLOCKED: production/Supabase/Render connection settings present in the environment: " + ", ".join(_ENV_NAMES + _ENV_VALUES))
old = runpy.run_path(str(REPO / "scripts/ci_cinema_pg_sql_gate.py")); Psql = old["Psql"]; BASE = old["BASE_FILES"]
ENGINE = "scripts/review/cinema_pg_write_engine.sql"
ORIG_MIG = REVIEW / "cinema_pg_s4_dev_migration.sql"
P1_ROLLBACK = REVIEW / "cinema_pg_s4_dev_rollback.sql"
P2 = REVIEW / "cinema_pg_p2_login_role.sql"; P2R = REVIEW / "cinema_pg_p2_login_role_rollback.sql"
MIG = ORIG_MIG
HERE = Path(tempfile.mkdtemp(prefix="jw_p1p2_"))   # scratch only (never inside the repo)
R = []
def rec(n, ok, d=""):
    if any(r[0] == n for r in R): raise SystemExit("FAIL: duplicate check name " + n)
    R.append((n, "PASS" if ok else "FAIL", d)); print(("PASS " if ok else "FAIL ") + n + (" | " + d if d and not ok else ""), flush=True)
def sh(db, sql, user=None, extra=()):
    cmd = ["psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-d", db] + (["-U", user] if user else []) + list(extra) + ["-c", sql]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120); return p
def must(p, step):
    if p.returncode: raise RuntimeError(step + ": " + p.stderr[-500:])
    return p.stdout.strip()
def err_state(db, sql, user=None):
    p = sh(db, sql, user, ["-v", "VERBOSITY=verbose"]); m = re.search(r"ERROR:\s+(\w{5}):", p.stderr)
    return (p.returncode, m.group(1) if m else None, p.stderr.strip()[-600:])

SVN = int(must(sh("postgres", "show server_version_num"), "server_version_num"))
MAJOR = SVN // 10000
if MAJOR != 17 and not (MAJOR == 16 and ALLOW_PG16):   # exactly 17 in CI mode; 16 only as an explicit, labelled supplemental run
    raise SystemExit(f"BLOCKED: PostgreSQL 17 required (server_version_num={SVN}); --allow-pg16-local only permits PostgreSQL 16 as supplemental evidence")
if MAJOR == 16:   # supplemental local run: ONLY the version floor is lowered, in a scratch copy
    _src = ORIG_MIG.read_text(); assert _src.count("< 170000") == 1
    MIG = HERE / "_mig_local_pg16_only.sql"; MIG.write_text(_src.replace("< 170000", "< 160000"))
DB = "jw_cinema_s4_gate_" + secrets.token_hex(4)
adm = Psql("postgres")
def build():
    must(sh("postgres", f"CREATE DATABASE {DB}"), "createdb")
    d = Psql(DB)
    for r in ("jw_app_dev", "jw_auth_stage_v85", "anon", "authenticated", "service_role"):
        must(sh("postgres", f"DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='{r}') THEN CREATE ROLE {r} NOLOGIN NOINHERIT NOBYPASSRLS; END IF; END $$"), r)
    for f in BASE: must(d.file(f), f)
    must(sh(DB, """
CREATE TABLE jw_dev.orders(id text PRIMARY KEY,org_id text NOT NULL);
CREATE TABLE jw_dev.invoices(id text PRIMARY KEY,org_id text NOT NULL);
CREATE TABLE jw_dev.payments(id text PRIMARY KEY,org_id text NOT NULL);
"""), "synthetic legacy")
    for t in ("quotes", "orders", "invoices", "payments"):
        must(sh(DB, f"ALTER TABLE jw_dev.{t} ENABLE ROW LEVEL SECURITY; ALTER TABLE jw_dev.{t} FORCE ROW LEVEL SECURITY; GRANT SELECT,INSERT,UPDATE ON jw_dev.{t} TO jw_app_dev"), t)
    for t in ("orders", "invoices", "payments"):
        must(sh(DB, f"CREATE POLICY app_all ON jw_dev.{t} FOR ALL TO jw_app_dev USING (org_id=jw_dev.current_org_from_session()) WITH CHECK (org_id=jw_dev.current_org_from_session())"), "pol")
    # emulate the real dev org-immutability guard that already exists on legacy tables
    must(sh(DB, """CREATE FUNCTION jw_dev.guard_core_trade_relationships() RETURNS trigger LANGUAGE plpgsql SET search_path TO 'pg_catalog' AS $f$
 BEGIN IF TG_OP='UPDATE' AND NEW.org_id IS DISTINCT FROM OLD.org_id THEN RAISE EXCEPTION 'JARVIS guard: organization cannot change' USING ERRCODE='23514'; END IF; RETURN NEW; END $f$;
 CREATE TRIGGER jw_trade_quote_guard BEFORE INSERT OR UPDATE ON jw_dev.quotes FOR EACH ROW EXECUTE FUNCTION jw_dev.guard_core_trade_relationships();
 CREATE TRIGGER jw_trade_order_guard BEFORE INSERT OR UPDATE ON jw_dev.orders FOR EACH ROW EXECUTE FUNCTION jw_dev.guard_core_trade_relationships();
 CREATE TRIGGER jw_trade_invoice_guard BEFORE INSERT OR UPDATE ON jw_dev.invoices FOR EACH ROW EXECUTE FUNCTION jw_dev.guard_core_trade_relationships();
 CREATE TRIGGER jw_trade_payment_guard BEFORE INSERT OR UPDATE ON jw_dev.payments FOR EACH ROW EXECUTE FUNCTION jw_dev.guard_core_trade_relationships();"""), "dev guard emulation")
    must(d.file(ENGINE, single_transaction=True), "engine")
    # Supabase-like ownership: non-superuser owner, creator ADMIN-only baseline membership
    must(sh("postgres", "DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='jw_mig_admin') THEN CREATE ROLE jw_mig_admin LOGIN CREATEROLE BYPASSRLS NOSUPERUSER; END IF; END $$"), "mig role")
    must(sh(DB, """ALTER SCHEMA jw_dev OWNER TO jw_mig_admin;
 ALTER TABLE jw_dev.quotes OWNER TO jw_mig_admin; ALTER TABLE jw_dev.orders OWNER TO jw_mig_admin;
 ALTER TABLE jw_dev.invoices OWNER TO jw_mig_admin; ALTER TABLE jw_dev.payments OWNER TO jw_mig_admin;
 GRANT jw_cinema_owner TO jw_mig_admin WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
 GRANT jw_cinema_writer TO jw_mig_admin WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;"""), "ownership")
def fp():
    return must(sh(DB, """SELECT md5(string_agg(c.relname::text||c.relrowsecurity::text||c.relforcerowsecurity::text||coalesce(c.relacl::text,'')||pg_get_userbyid(c.relowner),'|' ORDER BY c.relname))||'/'||
 (SELECT md5(string_agg(polrelid::regclass::text||polname::text||polcmd::text,'|' ORDER BY polrelid::regclass::text,polname)) FROM pg_policy WHERE polrelid<>coalesce(to_regclass('jw_dev.cinema_pg_ledger_claims'),0::oid::regclass))||'/'||
 (SELECT md5(string_agg(proname::text||coalesce(proacl::text,''),'|' ORDER BY oid)) FROM pg_proc WHERE pronamespace='jw_dev'::regnamespace AND proname NOT LIKE 'cinema\\_pg\\_s4\\_%')
 FROM pg_class c WHERE c.relnamespace='jw_dev'::regnamespace AND c.relkind='r' AND c.relname<>'cinema_pg_ledger_claims'"""), "fp")
def apply(path, user="jw_mig_admin", single=True):
    return subprocess.run(["psql","-X","-q","-v","ON_ERROR_STOP=1","-v","VERBOSITY=verbose"] + (["--single-transaction"] if single else []) + ["-d",DB,"-U",user,"-f",str(path)],capture_output=True,text=True,timeout=120)
def q(sql, user=None): return must(sh(DB, sql, user), sql[:50])
lq = lambda i,o: f"INSERT INTO jw_dev.quotes(id,org_id,customer_id,customer_name_snapshot,doc_no,title,status,vat_mode,created_at,updated_at) VALUES('{i}','{o}','cu-{o}','S','Q-{i}','S','draft','exempt',now()::text,now()::text)"
cq = lambda i,o: f"INSERT INTO jw_dev.cinema_pg_quotes(id,org_id,trade_no,partner_id,title,status,vat_mode,created_by) VALUES('{i}','{o}','T-{i}','pa-{o}','S','draft','exempt','ci-ua')"
def li(t, i, o): return lq(i, o) if t == "quotes" else f"INSERT INTO jw_dev.{t}(id,org_id) VALUES('{i}','{o}')"
def mkorg(o):
    q(f"INSERT INTO jw_dev.organizations(id,name,created_at) VALUES('{o}','S {o}',now()::text)")
    q(f"INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES('cu-{o}','{o}','S',now()::text)")
    q(f"INSERT INTO jw_dev.cinema_pg_partners(id,org_id,name,created_by) VALUES('pa-{o}','{o}','S','ci-ua')")
LEDGER = ("quotes", "orders", "invoices", "payments", "cinema_pg_quotes")
NON_LEDGER = ("organizations", "customers", "users", "sessions", "cinema_pg_partners", "cinema_pg_audit", "cinema_pg_requests")
# every pg_auth_members row that involves a CINEMA role, with all six columns the review asked for (roleid, member, grantor, admin, inherit, set)
MEMQ = ("select coalesce(string_agg(r, ';' order by r),'') from (select roleid::regrole||'>'||member::regrole||' by '||grantor::regrole||' admin='||admin_option::int||' inherit='||inherit_option::int||' set='||set_option::int as r "
        "from pg_auth_members where roleid in (select oid from pg_roles where rolname like 'jw\\_cinema\\_%') or member in (select oid from pg_roles where rolname like 'jw\\_cinema\\_%')) s")
ROLEQ = "select coalesce(string_agg(rolname||':'||rolsuper::int||rolinherit::int||rolcreaterole::int||rolcreatedb::int||rolcanlogin::int||rolreplication::int||rolbypassrls::int||':'||rolconnlimit, ';' order by rolname),'') from pg_roles where rolname like 'jw\\_cinema\\_%'"
def datasum(tables):
    out = []
    for t in tables:
        if q(f"select to_regclass('jw_dev.{t}') is not null") != "t": out.append(f"{t}:absent"); continue
        out.append(f"{t}:" + q(f"select count(*)||'/'||md5(coalesce(string_agg(x::text,'|' order by x::text),'')) from jw_dev.{t} x"))
    return "|".join(out)
def s4state():
    """Everything a refused rollback must leave untouched: triggers, functions, claims table (ACL/policies/data), ledger data, memberships, role attributes, ACLs."""
    parts = [
      q("select coalesce(string_agg(c.relname||'.'||g.tgname||':'||g.tgenabled::text||':'||g.tgtype::text||':'||g.tgfoid::regproc::text, '|' order by c.relname,g.tgname),'') from pg_trigger g join pg_class c on c.oid=g.tgrelid where c.relnamespace='jw_dev'::regnamespace and not g.tgisinternal"),
      q("select coalesce(string_agg(proname||':'||md5(prosrc)||':'||coalesce(proacl::text,'')||':'||prosecdef::int||':'||coalesce(proconfig::text,''),'|' order by proname,oid),'') from pg_proc where pronamespace='jw_dev'::regnamespace"),
      q("select coalesce((select relacl::text||relrowsecurity||relforcerowsecurity||pg_get_userbyid(relowner) from pg_class where oid=to_regclass('jw_dev.cinema_pg_ledger_claims')),'none')"),
      q("select coalesce(string_agg(polname::text||polcmd::text||polroles::text,'|'),'') from pg_policy where polrelid=to_regclass('jw_dev.cinema_pg_ledger_claims')"),
      q(MEMQ), q(ROLEQ),
      q("select coalesce(string_agg(relname||coalesce(relacl::text,''),'|' order by relname),'') from pg_class where relnamespace='jw_dev'::regnamespace and relname in ('quotes','orders','invoices','payments','cinema_pg_quotes')"),
      q("select coalesce(nspacl::text,'') from pg_namespace where nspname='jw_dev'"),
      datasum(LEDGER + ("cinema_pg_ledger_claims",)),
    ]
    return "\n".join(parts)
def run_async(sql, delay=0.0):
    res = {}
    def f():
        time.sleep(delay); t0 = time.time(); p = sh(DB, sql, None, ["-v", "VERBOSITY=verbose"]); m = re.search(r"ERROR:\s+(\w{5}):", p.stderr)
        res.update(rc=p.returncode, err=p.stderr, out=p.stdout, el=time.time() - t0, state=(m.group(1) if (m and p.returncode) else None))
    th = threading.Thread(target=f); th.start(); return th, res
try:
    must(adm.sql("select 1"), "conn"); ver = must(sh("postgres","show server_version"), "ver"); print("SERVER", ver)
    build()
    base = fp()
    mem0 = q(MEMQ); role0 = q(ROLEQ); nonledger0 = datasum(NON_LEDGER)
    # ---- R0: refusal preconditions (must fail closed, leave nothing behind)
    q("INSERT INTO jw_dev.organizations(id,name,created_at) VALUES('pre-x','x',now()::text)")
    q("INSERT INTO jw_dev.orders(id,org_id) VALUES('pre-o','pre-x')")
    p = apply(ORIG_MIG)
    if MAJOR != 17:
        rec("S4M.00z_original_file_requires_pg17", p.returncode != 0 and "requires PostgreSQL 17" in p.stderr, p.stderr[-120:])
    else:
        rec("S4M.00z_original_file_passes_pg17_gate_then_refuses_non_empty_ledger", p.returncode != 0 and "requires PostgreSQL 17" not in p.stderr and "non-empty ledger" in p.stderr, p.stderr[-160:])
    p = apply(MIG)
    rec("S4M.00a_refuses_non_empty_ledger", p.returncode != 0 and "non-empty ledger" in p.stderr, p.stderr[-140:])
    rec("S4M.00b_refusal_leaves_no_residue", q("select to_regclass('jw_dev.cinema_pg_ledger_claims') is null") == "t" and fp() == base)
    q("DELETE FROM jw_dev.orders WHERE id='pre-o'")
    p = apply(MIG, user="postgres")
    rec("S4M.00c_refuses_superuser_runner", p.returncode != 0 and "non-superuser" in p.stderr, p.stderr[-140:])
    # RLS blind spot: the owner's FORCE-RLS policy (org = session org) shows the owner ZERO rows, so an owner-side emptiness check is vacuous.
    # The install must still refuse because a row exists in cinema_pg_quotes.
    mkorg("pre-c"); q(cq("pre-cq", "pre-c"))
    owner_sees = sh(DB, "SET ROLE jw_cinema_owner; SELECT count(*) FROM jw_dev.cinema_pg_quotes").stdout.strip().splitlines()[-1]
    rec("S4M.00d_owner_role_is_blind_to_the_cinema_row_documents_why_old_check_was_vacuous", owner_sees == "0" and q("select count(*) from jw_dev.cinema_pg_quotes") == "1", owner_sees)
    p = apply(MIG)
    rec("S4M.00e_refuses_row_in_cinema_pg_quotes_despite_rls", p.returncode != 0 and "non-empty ledger table jw_dev.cinema_pg_quotes" in p.stderr, p.stderr[-200:])
    rec("S4M.00f_cinema_refusal_leaves_no_residue", q("select to_regclass('jw_dev.cinema_pg_ledger_claims') is null") == "t" and fp() == base and q(MEMQ) == mem0 and q(ROLEQ) == role0)
    sh(DB, "SET session_replication_role=replica; DELETE FROM jw_dev.cinema_pg_quotes WHERE id='pre-cq'")
    q("ALTER ROLE jw_mig_admin NOBYPASSRLS")
    p = apply(MIG)
    q("ALTER ROLE jw_mig_admin BYPASSRLS")
    rec("S4M.00g_refuses_runner_without_bypassrls", p.returncode != 0 and "BYPASSRLS" in p.stderr and fp() == base and q("select rolbypassrls from pg_roles where rolname='jw_mig_admin'") == "t", p.stderr[-200:])
    # Race: a writer is in flight (uncommitted row) and COMMITS while the install is waiting for its table locks. The install may not look at
    # the table before it holds the lock, otherwise it would see an empty table, install and leave a committed row without a claim.
    mkorg("ci-ir"); a, ra = run_async("BEGIN; " + li("orders", "ir-1", "ci-ir") + "; SELECT pg_sleep(3); COMMIT;")
    time.sleep(1.0); t0 = time.time(); p = apply(MIG); took = time.time() - t0; a.join()
    rec("S4M.00h_install_waits_for_in_flight_writer_then_refuses_because_it_committed", ra["rc"] == 0 and p.returncode != 0 and "non-empty ledger table jw_dev.orders" in p.stderr and 1.0 <= took <= 4.9 and q("select to_regclass('jw_dev.cinema_pg_ledger_claims') is null") == "t" and fp() == base, f"{took:.1f}s {p.stderr[-200:]}")
    q("DELETE FROM jw_dev.orders WHERE id='ir-1'")
    # ---- R1: apply as the non-superuser owner
    ACLQ = "select string_agg(relname||coalesce(relacl::text,''),'|' order by relname) from pg_class where relnamespace='jw_dev'::regnamespace and relname in ('quotes','orders','invoices','payments','cinema_pg_quotes')"
    acl_before = q(ACLQ)
    schema_acl_before = q("select coalesce(nspacl::text,'') from pg_namespace where nspname='jw_dev'")
    # Mid-install probe: run the real migration text up to the marker inside BEGIN..ROLLBACK and inspect the temporary-privilege state.
    _src = MIG.read_text(); _cut = _src.index("-- S4_BUILD_PHASE")
    _probe = HERE / "_probe_mid_install.sql"
    _probe.write_text("BEGIN;\n" + _src[:_cut] + """
SELECT 'PROBE_USER='||current_user||'|'||session_user;
SELECT 'PROBE_MEM='||(""" + MEMQ + """);
SELECT 'PROBE_PRIV=create:'||has_schema_privilege('jw_cinema_owner','jw_dev','CREATE')||' trig:'||(has_table_privilege('jw_cinema_owner','jw_dev.quotes','TRIGGER') and has_table_privilege('jw_cinema_owner','jw_dev.orders','TRIGGER') and has_table_privilege('jw_cinema_owner','jw_dev.invoices','TRIGGER') and has_table_privilege('jw_cinema_owner','jw_dev.payments','TRIGGER'))||' runner_select_cq:'||has_table_privilege(session_user,'jw_dev.cinema_pg_quotes','SELECT')||' writer_select_cq:'||has_table_privilege('jw_cinema_writer','jw_dev.cinema_pg_quotes','SELECT');
ROLLBACK;
""")
    pp = subprocess.run(["psql","-X","-q","-A","-t","-v","ON_ERROR_STOP=1","-d",DB,"-U","jw_mig_admin","-f",str(_probe)], capture_output=True, text=True, timeout=120)
    pr = {l.split("=", 1)[0]: l.split("=", 1)[1] for l in pp.stdout.splitlines() if l.startswith("PROBE_")}
    rec("S4M.12_mid_install_runs_as_cinema_owner_with_session_user_unchanged", pp.returncode == 0 and pr.get("PROBE_USER") == "jw_cinema_owner|jw_mig_admin", pp.stderr[-200:] + str(pr))
    _mid = set(pr.get("PROBE_MEM", "").split(";")); _b = set(mem0.split(";"))
    rec("S4M.13_mid_install_adds_exactly_one_set_only_membership_and_keeps_baseline", _b <= _mid and (_mid - _b) == {"jw_cinema_owner>jw_mig_admin by jw_mig_admin admin=0 inherit=0 set=1"}, str(_mid - _b))
    rec("S4M.14_mid_install_temporary_privileges_are_exactly_the_expected_ones", pr.get("PROBE_PRIV") == "create:true trig:true runner_select_cq:true writer_select_cq:true", pr.get("PROBE_PRIV", ""))
    rec("S4M.15_probe_rollback_leaves_no_residue", fp() == base and q(MEMQ) == mem0 and q(ROLEQ) == role0 and q(ACLQ) == acl_before and q("select to_regclass('jw_dev.cinema_pg_ledger_claims') is null") == "t")
    p = apply(MIG)
    rec("S4M.01_migration_applies_as_nonsuperuser_owner", p.returncode == 0, p.stderr[-300:])
    if p.returncode: raise SystemExit("migration failed; stop")
    rec("S4M.02_ten_enabled_triggers", q("select count(*) from pg_trigger where tgname like 'cinema\\_pg\\_s4\\_%' and not tgisinternal and tgenabled='O'") == "10")
    rec("S4M.03_legacy_and_cinema_acl_restored_exactly", q(ACLQ) == acl_before)
    rec("S4M.16_membership_rows_identical_to_pre_install_all_six_columns", q(MEMQ) == mem0, q(MEMQ)[-200:])
    rec("S4M.17_cinema_role_attributes_identical_to_pre_install", q(ROLEQ) == role0, q(ROLEQ)[-200:])
    rec("S4M.18_runner_has_no_select_on_cinema_pg_quotes_after_install", q("select has_table_privilege('jw_mig_admin','jw_dev.cinema_pg_quotes','SELECT')::text||has_table_privilege('jw_mig_admin','jw_dev.cinema_pg_ledger_claims','SELECT')::text") == "falsefalse")
    rec("S4M.04_schema_acl_restored_exactly", q("select coalesce(nspacl::text,'') from pg_namespace where nspname='jw_dev'") == schema_acl_before)
    rec("S4M.05_no_effective_owner_membership", q("select count(*) from pg_auth_members m join pg_roles a on a.oid=m.roleid join pg_roles b on b.oid=m.member where a.rolname='jw_cinema_owner' and b.rolname='jw_mig_admin' and (m.set_option or m.inherit_option)") == "0")
    rec("S4M.06_existing_objects_fingerprint_unchanged", fp() == base)
    rec("S4M.07_claims_owned_by_cinema_owner_force_rls", q("select pg_get_userbyid(relowner)||relrowsecurity||relforcerowsecurity from pg_class where oid='jw_dev.cinema_pg_ledger_claims'::regclass") == "jw_cinema_ownertruetrue")
    p = apply(MIG)
    rec("S4M.08_second_apply_refused", p.returncode != 0 and "already exist" in p.stderr, p.stderr[-140:])
    # ---- R2: functional claim behaviour through the guarded tables
    for o in ("ci-p", "ci-q"):
        q(f"INSERT INTO jw_dev.organizations(id,name,created_at) VALUES('{o}','S {o}',now()::text)")
        q(f"INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES('cu-{o}','{o}','S',now()::text)")
        q(f"INSERT INTO jw_dev.cinema_pg_partners(id,org_id,name,created_by) VALUES('pa-{o}','{o}','S','ci-ua')")
    q(lq("lg1", "ci-p"))
    c = err_state(DB, cq("cn1", "ci-p"))
    rec("S4A.01_legacy_first_blocks_cinema_same_tenant", c[1] == "23514" and "reserved" in c[2], str(c))
    q(cq("cn2", "ci-q"))
    c = err_state(DB, lq("lg2", "ci-q"))
    rec("S4A.02_cinema_first_blocks_legacy_same_tenant", c[1] == "23514" and "reserved" in c[2], str(c))
    rec("S4A.03_other_tenants_unaffected", q("select count(*) from jw_dev.cinema_pg_ledger_claims") == "2")
    # ---- R2b: the S4 objects verified on their own, independent of every other guard
    _exp = {"cinema_pg_s4_claim_new_quote": ("cinema_pg_quotes", "cinema_pg_s4_claim_on_insert", 5), "cinema_pg_s4_claim_legacy_quote": ("quotes", "cinema_pg_s4_claim_on_insert", 5),
            "cinema_pg_s4_claim_legacy_order": ("orders", "cinema_pg_s4_claim_on_insert", 5), "cinema_pg_s4_claim_legacy_invoice": ("invoices", "cinema_pg_s4_claim_on_insert", 5),
            "cinema_pg_s4_claim_legacy_payment": ("payments", "cinema_pg_s4_claim_on_insert", 5),
            "cinema_pg_s4_org_new_quote": ("cinema_pg_quotes", "cinema_pg_s4_org_immutable", 19), "cinema_pg_s4_org_legacy_quote": ("quotes", "cinema_pg_s4_org_immutable", 19),
            "cinema_pg_s4_org_legacy_order": ("orders", "cinema_pg_s4_org_immutable", 19), "cinema_pg_s4_org_legacy_invoice": ("invoices", "cinema_pg_s4_org_immutable", 19),
            "cinema_pg_s4_org_legacy_payment": ("payments", "cinema_pg_s4_org_immutable", 19)}
    _got = {}
    for _ln in q("select g.tgname||'|'||c.relname||'|'||p.proname||'|'||g.tgenabled::text||'|'||g.tgtype::text||'|'||(g.tgattr::text<>'')::text from pg_trigger g join pg_class c on c.oid=g.tgrelid join pg_proc p on p.oid=g.tgfoid where g.tgname like 'cinema\\_pg\\_s4\\_%' and not g.tgisinternal").splitlines():
        _a = _ln.split("|"); _got[_a[0]] = (_a[1], _a[2], int(_a[4]), _a[3], _a[5])
    _ok = set(_got) == set(_exp) and all(_got[k][:3] == _exp[k] and _got[k][3] == "O" and (_got[k][4] == "true") == k.startswith("cinema_pg_s4_org_") for k in _exp)
    rec("S4T.01_ten_triggers_on_expected_tables_functions_timing_enabled", _ok, str(_got)[:300])
    rec("S4T.02_claims_table_has_exactly_one_owner_only_policy", q("select count(*)||'/'||coalesce(string_agg(polcmd||polpermissive::int||array_to_string(array(select rolname from pg_roles where oid=any(polroles)),','),'|'),'') from pg_policy where polrelid='jw_dev.cinema_pg_ledger_claims'::regclass") == "1/*1jw_cinema_owner")
    rec("S4T.03_function_security_modes_and_pinned_search_path", q("select string_agg(proname||':'||prosecdef::int||':'||coalesce(array_to_string(proconfig,','),''),'|' order by proname) from pg_proc where pronamespace='jw_dev'::regnamespace and proname like 'cinema\\_pg\\_s4\\_%'") == "cinema_pg_s4_claim_on_insert:1:search_path=pg_catalog|cinema_pg_s4_org_immutable:0:search_path=pg_catalog")
    rec("S4T.04_s4_functions_not_executable_by_public_writer_app_anon_authenticated",
        q("select bool_or(has_function_privilege(r, p.oid, 'EXECUTE') or p.proacl is null or p.proacl::text ~ '(^\\{|,)=') from pg_proc p, unnest(array['jw_cinema_writer','jw_app_dev','anon','authenticated']) r where p.pronamespace='jw_dev'::regnamespace and p.proname like 'cinema\\_pg\\_s4\\_%'") == "f")
    for _i, _t in enumerate(LEDGER):
        _o = f"ci-t{_i}"; mkorg(_o); q(cq(f"t-{_o}", _o) if _t == "cinema_pg_quotes" else li(_t, f"t-{_o}", _o))
        rec(f"S4T.05_{_t}_insert_creates_exactly_one_claim_with_expected_ledger", q(f"select count(*)||'/'||coalesce(max(ledger),'') from jw_dev.cinema_pg_ledger_claims where org_id='{_o}'") == "1/" + ("cinema" if _t == "cinema_pg_quotes" else "legacy"))
    # ---- R2c: no orphan claims. A claim must exist only for a row that was REALLY inserted.
    _noN = lambda sql: [l for l in sh(DB, sql).stdout.splitlines() if l.startswith("N=")]
    rec("S4O.01_on_conflict_do_nothing_leaves_no_orphan_claim", _noN("BEGIN; INSERT INTO jw_dev.orders(id,org_id) VALUES('o-dup','ci-o1'); INSERT INTO jw_dev.orders(id,org_id) VALUES('o-dup','ci-o2') ON CONFLICT DO NOTHING; SELECT 'N='||count(*) FROM jw_dev.cinema_pg_ledger_claims WHERE org_id='ci-o2'; ROLLBACK;") == ["N=0"])
    rec("S4O.02_on_conflict_do_update_noop_leaves_no_orphan_claim", _noN("BEGIN; INSERT INTO jw_dev.orders(id,org_id) VALUES('o-dup2','ci-o1'); INSERT INTO jw_dev.orders(id,org_id) VALUES('o-dup2','ci-o3') ON CONFLICT (id) DO UPDATE SET id=orders.id; SELECT 'N='||count(*) FROM jw_dev.cinema_pg_ledger_claims WHERE org_id='ci-o3'; ROLLBACK;") == ["N=0"])
    rec("S4O.03_another_before_trigger_skipping_the_row_leaves_no_orphan_claim", _noN("BEGIN; CREATE FUNCTION jw_dev.zz_skip() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RETURN NULL; END $f$; CREATE TRIGGER zz_skip BEFORE INSERT ON jw_dev.payments FOR EACH ROW EXECUTE FUNCTION jw_dev.zz_skip(); INSERT INTO jw_dev.payments(id,org_id) VALUES('p-skip','ci-o4'); SELECT 'N='||count(*) FROM jw_dev.cinema_pg_ledger_claims WHERE org_id='ci-o4'; ROLLBACK;") == ["N=0"])
    # ---- R3: attack suite (roles used via SET ROLE inside the session)
    def as_role(role, sql): 
        p = sh(DB, f"SET ROLE {role}; {sql}", None, ["-v", "VERBOSITY=verbose"]); m = re.search(r"ERROR:\s+(\w{5}):", p.stderr); return p.returncode, (m.group(1) if m else None), (p.stdout + p.stderr).strip()[-200:]
    for role in ("jw_cinema_writer", "jw_app_dev"):
        for op, sql in (("select", "SELECT * FROM jw_dev.cinema_pg_ledger_claims"), ("insert", "INSERT INTO jw_dev.cinema_pg_ledger_claims(org_id,ledger) VALUES('evil','legacy')"),
                        ("update", "UPDATE jw_dev.cinema_pg_ledger_claims SET ledger='legacy'"), ("delete", "DELETE FROM jw_dev.cinema_pg_ledger_claims"), ("truncate", "TRUNCATE jw_dev.cinema_pg_ledger_claims")):
            c = as_role(role, sql); rec(f"S4X.claims_{op}_denied_for_{role}", c[0] != 0 and c[1] == "42501", str(c))
    c = as_role("jw_cinema_writer", "SELECT jw_dev.cinema_pg_s4_claim_on_insert()"); rec("S4X.writer_cannot_execute_claim_fn", c[0] != 0 and c[1] in ("42501", "0A000"), str(c))
    c = as_role("jw_cinema_writer", "SET session_replication_role='replica'"); rec("S4X.writer_cannot_disable_triggers_via_replication_role", c[0] != 0 and c[1] == "42501", str(c))
    c = as_role("jw_cinema_writer", "ALTER TABLE jw_dev.cinema_pg_quotes DISABLE TRIGGER ALL"); rec("S4X.writer_cannot_alter_table_triggers", c[0] != 0 and c[1] == "42501", str(c))
    c = as_role("jw_app_dev", "ALTER TABLE jw_dev.quotes DISABLE TRIGGER ALL"); rec("S4X.app_cannot_alter_legacy_triggers", c[0] != 0 and c[1] == "42501", str(c))
    c = as_role("jw_app_dev", "DROP TRIGGER cinema_pg_s4_claim_legacy_quote ON jw_dev.quotes"); rec("S4X.app_cannot_drop_s4_trigger", c[0] != 0 and c[1] == "42501", str(c))
    c = as_role("jw_cinema_writer", "TRUNCATE jw_dev.cinema_pg_quotes"); rec("S4X.writer_cannot_truncate_cinema_quotes", c[0] != 0 and c[1] == "42501", str(c))
    c = as_role("jw_cinema_writer", "UPDATE jw_dev.cinema_pg_quotes SET org_id='ci-p' WHERE id='cn2'"); rec("S4X.writer_cannot_move_cinema_quote_to_other_tenant", c[0] != 0, str(c))
    q("SET ROLE jw_mig_admin; SELECT 1")  # sanity
    # The error text must come from the S4 trigger itself: existing guards raise the same SQLSTATE, so the code alone would not prove S4 works.
    SMSG = "S4: organization cannot change on a ledger row"
    c = err_state(DB, "UPDATE jw_dev.cinema_pg_quotes SET org_id='ci-p' WHERE id='cn2'"); rec("S4X.org_move_cinema_blocked_by_s4_trigger_itself", c[0] != 0 and c[1] == "23514" and SMSG in c[2], str(c))
    c = err_state(DB, "UPDATE jw_dev.quotes SET org_id='ci-q' WHERE id='lg1'", "jw_mig_admin"); rec("S4X.owner_path_org_move_blocked_legacy_by_s4_trigger_itself", c[0] != 0 and c[1] == "23514" and SMSG in c[2], str(c))
    c = err_state(DB, "UPDATE jw_dev.quotes SET org_id='ci-q' WHERE id='lg1'"); rec("S4X.superuser_path_org_move_blocked_by_s4_trigger", c[0] != 0 and c[1] == "23514" and SMSG in c[2], str(c))
    # The claim trigger now runs AFTER the row insert, so the FK to organizations is evaluated first. To prove S4's OWN whitespace rule (not the FK),
    # the whitespace id must exist in organizations; the expected SQLSTATE and message stay S4's.
    q("INSERT INTO jw_dev.organizations(id,name,created_at) VALUES(' ci-p','ws',now()::text)")
    c = err_state(DB, "INSERT INTO jw_dev.quotes(id,org_id,customer_id,customer_name_snapshot,doc_no,title,status,vat_mode,created_at,updated_at) VALUES('lg9',' ci-p','cu-ci-p','S','Q-9','S','draft','exempt',now()::text,now()::text)")
    rec("S4X.whitespace_org_id_rejected", c[0] != 0 and c[1] == "23514" and "S4 invalid ledger or organization" in c[2], str(c))
    q("DELETE FROM jw_dev.organizations WHERE id=' ci-p'")
    # claim persistence: deleting all rows must NOT free the tenant for the other ledger
    q("DELETE FROM jw_dev.quotes WHERE id='lg1'")
    c = err_state(DB, cq("cn3", "ci-p")); rec("S4X.claim_survives_row_deletion", c[0] != 0 and "reserved" in c[2], str(c))
    # multi-row / single-transaction mixed-ledger attack on a NEW tenant
    q("INSERT INTO jw_dev.organizations(id,name,created_at) VALUES('ci-m','M',now()::text)"); q("INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES('cu-ci-m','ci-m','S',now()::text)"); q("INSERT INTO jw_dev.cinema_pg_partners(id,org_id,name,created_by) VALUES('pa-ci-m','ci-m','S','ci-ua')")
    c = err_state(DB, "BEGIN; " + cq("mx1", "ci-m") + "; " + lq("mx2", "ci-m") + "; COMMIT;"); rec("S4X.same_tx_mixed_ledgers_blocked", c[0] != 0 and "reserved" in c[2], str(c))
    rec("S4X.same_tx_failure_leaves_no_claim", q("select count(*) from jw_dev.cinema_pg_ledger_claims where org_id='ci-m'") == "0")
    # ---- R3b: masking detection. Every NON-S4 user trigger on the five ledger tables is disabled inside a transaction (rolled back afterwards),
    # so a pass can only come from the S4 triggers themselves; the message must be S4's own text.
    DISABLE = ("DO $$ DECLARE r record; BEGIN FOR r IN SELECT c.relname, g.tgname FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid WHERE c.relnamespace='jw_dev'::regnamespace "
               "AND c.relname IN ('quotes','orders','invoices','payments','cinema_pg_quotes') AND NOT g.tgisinternal AND g.tgname NOT LIKE 'cinema\\_pg\\_s4\\_%' LOOP "
               "EXECUTE format('ALTER TABLE jw_dev.%I DISABLE TRIGGER %I', r.relname, r.tgname); END LOOP; END $$;")
    c = sh(DB, "BEGIN; " + DISABLE + " SELECT 'N='||count(*) FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid WHERE c.relnamespace='jw_dev'::regnamespace AND c.relname IN ('quotes','orders','invoices','payments','cinema_pg_quotes') AND NOT g.tgisinternal AND g.tgname NOT LIKE 'cinema\\_pg\\_s4\\_%' AND g.tgenabled<>'D'; ROLLBACK;").stdout
    rec("S4D.00_control_every_non_s4_guard_really_disabled_in_the_masking_transaction", "N=0" in c and q("select count(*) from pg_trigger g join pg_class c on c.oid=g.tgrelid where c.relnamespace='jw_dev'::regnamespace and c.relname in ('quotes','orders','invoices','payments','cinema_pg_quotes') and not g.tgisinternal and g.tgname not like 'cinema\\_pg\\_s4\\_%' and g.tgenabled<>'O'") == "0", c)
    for _t in LEDGER:
        ins = cq("mk-c", "ci-m") if _t == "cinema_pg_quotes" else li(_t, "mk-" + _t, "ci-m")
        c = err_state(DB, f"BEGIN; {DISABLE} {ins}; UPDATE jw_dev.{_t} SET org_id='ci-q' WHERE id='{'mk-c' if _t == 'cinema_pg_quotes' else 'mk-' + _t}'; ROLLBACK;")
        rec(f"S4D.org_move_{_t}_blocked_by_s4_alone", c[0] != 0 and c[1] == "23514" and SMSG in c[2], str(c))
    for _t in LEDGER:
        if _t == "cinema_pg_quotes": ins, org = cq("mx-c", "ci-p"), "ci-p"      # ci-p is legacy-claimed
        else: ins, org = li(_t, "mx-" + _t, "ci-q"), "ci-q"                       # ci-q is cinema-claimed
        c = err_state(DB, f"BEGIN; {DISABLE} {ins}; ROLLBACK;")
        rec(f"S4D.cross_ledger_insert_{_t}_blocked_by_s4_alone", c[0] != 0 and c[1] == "23514" and "reserved" in c[2], str(c))
    # ---- R4: session/tenant isolation of the CINEMA writer path
    q("INSERT INTO jw_dev.sessions(id,user_id,token_hash,created_at,expires_at) VALUES('s-a','ci-ua','hashA-0123456789abcdef',now()::text,(now()+interval '1 hour')::text),('s-b','ci-ub','hashB-0123456789abcdef',now()::text,(now()+interval '1 hour')::text)") if False else None
    # ---- R4: session-hash forgery / leak / tenant isolation through the real CINEMA writer functions
    q("INSERT INTO jw_dev.sessions(id,user_id,token_hash,csrf_token,created_at,expires_at) VALUES ('s-a','ci-ua','hashA-0123456789abcdef','c1',now(),now()+interval '1 hour'),('s-b','ci-ub','hashB-0123456789abcdef','c2',now(),now()+interval '1 hour'),('s-x','ci-uc','hashX-0123456789abcdef','c3',now()-interval '2 hour',now()-interval '1 hour')")
    def wr(sql, h=None):
        pre = "BEGIN; SET LOCAL ROLE jw_cinema_writer; " + (f"SELECT set_config('jw.session_hash','{h}',true); " if h else "")
        p = sh(DB, pre + sql + "; COMMIT;", None, ["-v", "VERBOSITY=verbose"]); m = re.search(r"ERROR:\s+(\w{5}):", p.stderr)
        return p.returncode, (m.group(1) if m else None), p.stdout.strip(), p.stderr.strip()[-160:]
    ups = lambda rid, pid, name: f"SELECT jw_dev.cinema_pg_partner_upsert('{rid}',{('NULL' if pid is None else repr(pid))},'{name}','','','','',NULL)"
    c = wr(ups("rq-s1-0000001", None, "p")); rec("S4S.01_no_session_fails_closed", c[0] != 0 and c[1] == "42501", str(c))
    c = wr(ups("rq-s2-0000001", None, "p"), "forged-hash-0123456789"); rec("S4S.02_forged_hash_fails_closed", c[0] != 0 and c[1] == "42501", str(c))
    c = wr(ups("rq-s3-0000001", None, "p"), "hashX-0123456789abcdef"); rec("S4S.03_expired_session_fails_closed", c[0] != 0 and c[1] == "42501", str(c))
    c = wr("SELECT 1 FROM jw_dev.sessions"); rec("S4S.04_writer_cannot_read_sessions", c[0] != 0 and c[1] == "42501", str(c))
    c = wr("SELECT email FROM jw_dev.users"); rec("S4S.05_writer_cannot_read_users", c[0] != 0 and c[1] == "42501", str(c))
    c = wr(ups("rq-a-00000001", None, "PartnerA"), "hashA-0123456789abcdef")
    ok_a = c[0] == 0 and '"id"' in c[2]; rec("S4S.06_valid_session_A_creates_partner", ok_a, str(c))
    pid_a = q("select id from jw_dev.cinema_pg_partners where org_id='ci-a' and name='PartnerA'")
    rec("S4S.07_partner_row_tenant_is_session_org", q(f"select org_id from jw_dev.cinema_pg_partners where id='{pid_a}'") == "ci-a")
    c = wr(ups("rq-b-00000001", pid_a, "HackedByB"), "hashB-0123456789abcdef"); rec("S4S.08_tenant_B_cannot_update_tenant_A_partner", c[0] != 0, str(c))
    rec("S4S.09_A_partner_unchanged", q(f"select name from jw_dev.cinema_pg_partners where id='{pid_a}'") == "PartnerA")
    c = wr(ups("rq-a-00000001", None, "PartnerA"), "hashB-0123456789abcdef")
    rec("S4S.10_same_request_id_other_tenant_no_replay_leak", c[0] == 0 and pid_a not in c[2] and q("select count(*) from jw_dev.cinema_pg_partners where org_id='ci-b' and name='PartnerA'") == "1", str(c))
    qa = wr(f"SELECT jw_dev.cinema_pg_quote_create('rq-a-00000002','{pid_a}','TitleA','exempt','[{{\"name\":\"item\",\"quantity\":2,\"unit_price\":1500}}]'::jsonb)", "hashA-0123456789abcdef")
    rec("S4S.11_engine_quote_create_works_with_S4_trigger", qa[0] == 0, str(qa))
    rec("S4S.12_claim_created_by_engine_path", q("select ledger from jw_dev.cinema_pg_ledger_claims where org_id='ci-a'") == "cinema")
    tn = q("select trade_no from jw_dev.cinema_pg_quotes where org_id='ci-a' limit 1")
    c = wr(f"SELECT jw_dev.cinema_pg_trade_trace('{tn}')", "hashB-0123456789abcdef"); rec("S4S.13_tenant_B_cannot_trace_tenant_A_trade", c[0] != 0 and c[1] == "P0002", str(c))
    c = wr(f"SELECT jw_dev.cinema_pg_trade_trace('{tn}')", "hashA-0123456789abcdef"); rec("S4S.14_tenant_A_can_trace_own_trade", c[0] == 0, str(c))
    q("INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES('cu-ci-a','ci-a','S',now()::text)")
    c = err_state(DB, lq("lg-a1", "ci-a").replace("'cu-ci-p'", "'cu-ci-a'")); rec("S4S.15_legacy_insert_blocked_after_engine_claim", c[0] != 0 and "reserved" in c[2], str(c))
    # transaction-local GUC does not leak into the next transaction on the same connection
    p = sh(DB, "BEGIN; SET LOCAL ROLE jw_cinema_writer; SELECT set_config('jw.session_hash','hashA-0123456789abcdef',true); SELECT 1; COMMIT; "
               "BEGIN; SET LOCAL ROLE jw_cinema_writer; SELECT jw_dev.cinema_pg_trade_trace('x'); COMMIT;", None, ["-v", "VERBOSITY=verbose"])
    rec("S4S.16_local_guc_does_not_leak_to_next_tx_same_connection", p.returncode != 0 and "42501" in p.stderr, p.stderr[-160:])
    # documented hazard: a SESSION-level set_config(...,false) would leak across transactions on a pooled connection
    p = sh(DB, "SELECT set_config('jw.session_hash','hashA-0123456789abcdef',false); BEGIN; SET LOCAL ROLE jw_cinema_writer; SELECT (jw_dev.cinema_pg_trade_trace('"+tn+"')->>'trade_no') IS NOT NULL OR true; COMMIT;")
    rec("S4S.17_HAZARD_confirmed_session_level_set_leaks (app code uses only is_local=true)", p.returncode == 0, p.stderr[-120:])
    # ---- R4b: real multi-connection concurrency with the candidate installed (6 tenants x 8 sessions)
    for i in range(1, 7):
        o = f"ci-k{i}"
        q(f"INSERT INTO jw_dev.organizations(id,name,created_at) VALUES('{o}','K',now()::text)"); q(f"INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES('cu-{o}','{o}','S',now()::text)"); q(f"INSERT INTO jw_dev.cinema_pg_partners(id,org_id,name,created_by) VALUES('pa-{o}','{o}','S','ci-ua')")
    out = {}
    def worker(o, kind, n):
        stmt = cq(f"k-{o}-c{n}", o) if kind == "cinema" else lq(f"k-{o}-l{n}", o)
        p = sh(DB, "BEGIN; " + stmt + "; SELECT pg_sleep(0.25); COMMIT;", None, ["-v", "VERBOSITY=verbose"])
        out[(o, kind, n)] = (p.returncode, re.search(r"ERROR:\s+(\w{5}):", p.stderr).group(1) if p.returncode and re.search(r"ERROR:\s+(\w{5}):", p.stderr) else None)
    th = []
    for i in range(1, 7):
        for n in range(4):
            for kind in ("cinema", "legacy"): th.append(threading.Thread(target=worker, args=(f"ci-k{i}", kind, n)))
    for t in th: t.start()
    for t in th: t.join()
    bad = []; deadl = sum(1 for v in out.values() if v[1] == "40P01"); other = [k for k, v in out.items() if v[0] != 0 and v[1] not in ("23514",)]
    for i in range(1, 7):
        o = f"ci-k{i}"; okc = sum(1 for k, v in out.items() if k[0] == o and k[1] == "cinema" and v[0] == 0); okl = sum(1 for k, v in out.items() if k[0] == o and k[1] == "legacy" and v[0] == 0)
        led = q(f"select ledger from jw_dev.cinema_pg_ledger_claims where org_id='{o}'")
        rows_c = q(f"select count(*) from jw_dev.cinema_pg_quotes where org_id='{o}'"); rows_l = q(f"select count(*) from jw_dev.quotes where org_id='{o}'")
        good = (okc == 0) != (okl == 0) and ((led == "cinema" and rows_l == "0" and int(rows_c) == okc) or (led == "legacy" and rows_c == "0" and int(rows_l) == okl))
        if not good: bad.append((o, okc, okl, led, rows_c, rows_l))
    rec("S4C.01_48_sessions_exactly_one_ledger_wins_per_tenant", not bad, str(bad))
    rec("S4C.02_no_deadlock_and_only_expected_errors", deadl == 0 and not other, f"deadlocks={deadl} other={other[:3]}")
    rec("S4C.03_claims_rows_equal_tenant_count", q("select count(*) from jw_dev.cinema_pg_ledger_claims where org_id like 'ci-k%'") == "6")
    # ---- R4c: two-session commit / rollback / deadlock races (the second session must really wait for the first one's claim)
    INV = ("select count(*) from (select org_id, l from (select org_id,'legacy' l from jw_dev.quotes union select org_id,'legacy' from jw_dev.orders union select org_id,'legacy' from jw_dev.invoices "
           "union select org_id,'legacy' from jw_dev.payments union select org_id,'cinema' from jw_dev.cinema_pg_quotes) r) r left join jw_dev.cinema_pg_ledger_claims c on c.org_id=r.org_id where c.ledger is distinct from r.l")
    mkorg("ci-r1"); a, ra = run_async("BEGIN; " + li("orders", "r1-a", "ci-r1") + "; SELECT pg_sleep(2); COMMIT;"); b, rb = run_async(cq("r1-b", "ci-r1"), 0.7); a.join(); b.join()
    rec("S4Q.01_commit_race_second_ledger_waits_then_is_refused", ra["rc"] == 0 and rb["rc"] != 0 and rb["state"] == "23514" and "reserved" in rb["err"] and rb["el"] >= 0.8, f"{ra['rc']} {rb['state']} {rb['el']:.2f}")
    rec("S4Q.02_commit_race_final_state_single_ledger", q("select (select ledger from jw_dev.cinema_pg_ledger_claims where org_id='ci-r1')||'/'||(select count(*) from jw_dev.orders where org_id='ci-r1')||'/'||(select count(*) from jw_dev.cinema_pg_quotes where org_id='ci-r1')") == "legacy/1/0")
    mkorg("ci-r2"); a, ra = run_async("BEGIN; " + li("orders", "r2-a", "ci-r2") + "; SELECT pg_sleep(2); ROLLBACK;"); b, rb = run_async(cq("r2-b", "ci-r2"), 0.7); a.join(); b.join()
    rec("S4Q.03_explicit_rollback_frees_the_tenant_for_the_other_ledger", ra["rc"] == 0 and rb["rc"] == 0 and rb["el"] >= 0.8, f"{ra['rc']} {rb['rc']} {rb['el']:.2f} {rb['err'][-120:]}")
    rec("S4Q.04_rollback_race_final_state_single_ledger", q("select (select ledger from jw_dev.cinema_pg_ledger_claims where org_id='ci-r2')||'/'||(select count(*) from jw_dev.orders where org_id='ci-r2')||'/'||(select count(*) from jw_dev.cinema_pg_quotes where org_id='ci-r2')") == "cinema/0/1")
    mkorg("ci-r3"); a, ra = run_async("BEGIN; " + li("orders", "r3-a", "ci-r3") + "; SELECT pg_sleep(1.5); COMMIT;"); b, rb = run_async(li("invoices", "r3-b", "ci-r3"), 0.5); a.join(); b.join()
    rec("S4Q.05_same_ledger_concurrent_writers_both_succeed_with_one_claim", ra["rc"] == 0 and rb["rc"] == 0 and q("select count(*) from jw_dev.cinema_pg_ledger_claims where org_id='ci-r3'") == "1", f"{ra['rc']} {rb['rc']}")
    mkorg("ci-r4"); p = sh(DB, "BEGIN; SAVEPOINT s; " + li("orders", "r4-a", "ci-r4") + "; ROLLBACK TO s; " + cq("r4-b", "ci-r4") + "; COMMIT;")
    rec("S4Q.06_claim_is_undone_with_a_rolled_back_savepoint", p.returncode == 0 and q("select (select ledger from jw_dev.cinema_pg_ledger_claims where org_id='ci-r4')||'/'||(select count(*) from jw_dev.orders where org_id='ci-r4')") == "cinema/0", p.stderr[-160:])
    mkorg("ci-d1"); mkorg("ci-d2")
    a, ra = run_async("BEGIN; " + li("orders", "d-a1", "ci-d1") + "; SELECT pg_sleep(1); " + cq("d-a2", "ci-d2") + "; COMMIT;")
    b, rb = run_async("BEGIN; " + li("orders", "d-b1", "ci-d2") + "; SELECT pg_sleep(1); " + cq("d-b2", "ci-d1") + "; COMMIT;"); a.join(); b.join()
    rec("S4Q.07_opposite_order_cross_ledger_writers_resolve_by_deadlock_or_refusal_without_corruption", {ra["state"], rb["state"]} <= {None, "40P01", "23514"} and (ra["rc"] == 0 or rb["rc"] == 0) and q(INV) == "0", f"{ra['state']} {rb['state']}")
    rec("S4Q.08_no_tenant_has_rows_outside_its_claimed_ledger", q(INV) == "0")
    # ---- P2: least-privilege LOGIN role (candidate file, applied here on the throw-away DB only)
    rec("P2.00_no_password_or_secret_in_sql", not re.search(r"(?i)password\s+'|encrypted\s+password|passwd|postgres(ql)?://", P2.read_text()))
    mem_pre_p2 = q(MEMQ); role_pre_p2 = q(ROLEQ)
    p = apply(P2); rec("P2.01_login_role_sql_applies_as_nonsuperuser", p.returncode == 0, p.stderr[-300:])
    _after = set(q(MEMQ).split(";")); _before = set(mem_pre_p2.split(";"))
    rec("P2.21_install_keeps_every_existing_membership_row_and_only_adds_login_role_rows", _before <= _after and len(_after - _before) >= 1 and all("jw_cinema_login" in r for r in _after - _before), str(_after - _before))
    rec("P2.02_attributes_exact", q("select rolcanlogin::int||''||rolinherit::int||rolbypassrls::int||rolsuper::int||rolcreatedb::int||rolcreaterole::int||rolreplication::int||'/'||rolconnlimit from pg_roles where rolname='jw_cinema_login'") == "1000000/8")
    rec("P2.03_membership_only_writer_set_noinherit_noadmin", q("select string_agg(roleid::regrole||':'||inherit_option::int||set_option::int||admin_option::int,',') from pg_auth_members where member='jw_cinema_login'::regrole") == "jw_cinema_writer:010")
    rec("P2.04_no_password_hash_stored", q("select coalesce(rolpassword,'NULL') from pg_authid where rolname='jw_cinema_login'") == "NULL")
    cfg = q("select array_to_string(setconfig,'|') from pg_db_role_setting where setrole='jw_cinema_login'::regrole")
    rec("P2.05_timeouts_and_pinned_search_path", all(k in cfg for k in ("statement_timeout=15s", "lock_timeout=5s", "idle_in_transaction_session_timeout=10s", "search_path=pg_catalog")), cfg)
    rec("P2.06_login_can_connect_but_is_plain", q("select current_user", "jw_cinema_login") == "jw_cinema_login")
    for tbl in ("cinema_pg_quotes", "cinema_pg_partners", "sessions", "users", "orders", "cinema_pg_ledger_claims"):
        c = err_state(DB, f"SELECT * FROM jw_dev.{tbl}", "jw_cinema_login"); rec(f"P2.07_direct_select_denied_{tbl}", c[0] != 0 and c[1] == "42501", str(c))
    c = err_state(DB, "INSERT INTO jw_dev.cinema_pg_partners(id,org_id,name,created_by) VALUES('evil','ci-p','x','x')", "jw_cinema_login"); rec("P2.08_direct_insert_denied", c[0] != 0 and c[1] == "42501", str(c))
    for tgt in ("jw_cinema_owner", "jw_mig_admin", "jw_app_dev", "jw_auth_stage_v85", "postgres"):
        c = err_state(DB, f"SET ROLE {tgt}", "jw_cinema_login"); rec(f"P2.09_cannot_set_role_{tgt}", c[0] != 0 and c[1] == "42501", str(c))
    for stmt, nm in (("ALTER ROLE jw_cinema_login SUPERUSER", "self_escalate"), ("ALTER ROLE jw_cinema_login BYPASSRLS", "self_bypassrls"), ("CREATE ROLE evil", "create_role"),
                     ("SET session_replication_role='replica'", "disable_triggers"), ("GRANT jw_cinema_owner TO jw_cinema_login", "grant_owner"), ("CREATE TABLE jw_dev.evil(id int)", "ddl")):
        c = err_state(DB, stmt, "jw_cinema_login"); rec(f"P2.10_denied_{nm}", c[0] != 0 and c[1] == "42501", str(c))
    def wl(sql, h=None):
        pre = "BEGIN; SET LOCAL ROLE jw_cinema_writer; " + (f"SELECT set_config('jw.session_hash','{h}',true); " if h else "")
        pp = sh(DB, pre + sql + "; COMMIT;", "jw_cinema_login", ["-v", "VERBOSITY=verbose"]); mm = re.search(r"ERROR:\s+(\w{5}):", pp.stderr)
        return pp.returncode, (mm.group(1) if mm else None), pp.stdout.strip(), pp.stderr.strip()[-160:]
    c = wl(ups("rq-p2-0000001", None, "p"), "hashA-0123456789abcdef"); rec("P2.11_login_via_set_role_writer_valid_session_works", c[0] == 0, str(c))
    c = wl(ups("rq-p2-0000002", None, "p")); rec("P2.12_login_via_writer_without_session_fails_closed", c[0] != 0 and c[1] == "42501", str(c))
    c = wl(ups("rq-p2-0000003", None, "p"), "forged-hash-0123456789"); rec("P2.13_login_via_writer_forged_hash_fails_closed", c[0] != 0 and c[1] == "42501", str(c))
    rec("P2.14_no_context_leak_on_next_connection", q("select current_user||'|'||coalesce(nullif(current_setting('jw.session_hash', true),''),'EMPTY')", "jw_cinema_login") == "jw_cinema_login|EMPTY")
    res = []
    def hold():
        pp = sh(DB, "select pg_sleep(2.5)", "jw_cinema_login", ["-v", "VERBOSITY=verbose"]); mm = re.search(r"ERROR:\s+(\w{5}):", pp.stderr); res.append("ok" if pp.returncode == 0 else ("limit" if "too many connections for role" in pp.stderr else "other:" + pp.stderr.strip()[-120:]))
    th = [threading.Thread(target=hold) for _ in range(12)]
    [t.start() for t in th]; [t.join() for t in th]
    rec("P2.15_connection_limit_8_enforced", res.count("ok") == 8 and res.count("limit") == 4, str(sorted(res)))
    p = apply(P2); rec("P2.16_second_apply_refused", p.returncode != 0 and "already exists" in p.stderr, p.stderr[-140:])
    p = apply(P2R); rec("P2.17_rollback_runs", p.returncode == 0, p.stderr[-300:])
    rec("P2.18_rollback_removes_role_and_memberships", q("select (select count(*) from pg_roles where rolname='jw_cinema_login')||'/'||(select count(*) from pg_auth_members m where m.member not in (select oid from pg_roles where rolname<>'jw_cinema_login'))") == "0/0" and fp() == base)
    p = apply(P2); rec("P2.19_reapply_after_rollback_works", p.returncode == 0, p.stderr[-200:]); p = apply(P2R)
    rec("P2.20_second_rollback_restores_membership_rows_and_role_attributes_exactly", p.returncode == 0 and q(MEMQ) == mem_pre_p2 and q(ROLEQ) == role_pre_p2, p.stderr[-160:])
    # ---- R5: rollback safety. The rollback is SAFE-ONLY: it must refuse (atomically, changing nothing) while ANY claim or ledger row exists.
    CLEAN = ("SET session_replication_role=replica; DELETE FROM jw_dev.quotes; DELETE FROM jw_dev.orders; DELETE FROM jw_dev.invoices; DELETE FROM jw_dev.payments; "
             "DELETE FROM jw_dev.cinema_pg_quotes; TRUNCATE jw_dev.cinema_pg_ledger_claims")   # throw-away database only
    st = s4state(); nl_before = datasum(NON_LEDGER)
    rec("S4R.00_precondition_dangerous_state_has_claims_and_rows_in_all_ledgers", all(int(q(f"select count(*) from jw_dev.{t}")) > 0 for t in LEDGER + ("cinema_pg_ledger_claims",)))
    p = apply(P1_ROLLBACK)
    rec("S4R.01_rollback_refused_when_claims_and_ledger_rows_exist", p.returncode != 0 and "55000" in p.stderr and "REFUSED" in p.stderr and all(t in p.stderr for t in ("cinema_pg_ledger_claims", "quotes", "cinema_pg_quotes")), p.stderr[-300:])
    rec("S4R.02_refusal_changed_nothing_objects_acl_memberships_triggers_functions_data", s4state() == st and datasum(NON_LEDGER) == nl_before)
    p = apply(P1_ROLLBACK, single=False)
    rec("S4R.03_refusal_is_atomic_even_without_single_transaction_wrapper", p.returncode != 0 and "REFUSED" in p.stderr and s4state() == st, p.stderr[-200:])
    # claims only: delete every ledger row but keep the claims
    sh(DB, "SET session_replication_role=replica; DELETE FROM jw_dev.quotes; DELETE FROM jw_dev.orders; DELETE FROM jw_dev.invoices; DELETE FROM jw_dev.payments; DELETE FROM jw_dev.cinema_pg_quotes")
    st_claims_only = s4state(); p = apply(P1_ROLLBACK)
    rec("S4R.04_claims_only_state_refused_and_unchanged", p.returncode != 0 and "55000" in p.stderr and "cinema_pg_ledger_claims" in p.stderr and s4state() == st_claims_only, p.stderr[-200:])
    # one ledger row, no claim, one table at a time
    q("TRUNCATE jw_dev.cinema_pg_ledger_claims")
    for _t in LEDGER:
        ins = cq("rb-" + _t, "ci-t4") if _t == "cinema_pg_quotes" else li(_t, "rb-" + _t, "ci-t0")
        must(sh(DB, "SET session_replication_role=replica; " + ins), "seed " + _t)
        stx = s4state(); p = apply(P1_ROLLBACK)
        rec(f"S4R.05_single_row_in_{_t}_alone_refuses_rollback_and_changes_nothing", p.returncode != 0 and "55000" in p.stderr and p.stderr.split("data exists in ")[-1].split(".")[0] == _t and s4state() == stx, p.stderr[-200:])
        must(sh(DB, f"SET session_replication_role=replica; DELETE FROM jw_dev.{_t}"), "unseed " + _t)
    # lock boundary 1: an in-flight writer COMMITS while the rollback waits for its locks. The rollback must count only AFTER it holds the locks,
    # see the committed row + claim and refuse; counting first would see an empty table, wait for the lock and then destroy the committed data.
    sh(DB, CLEAN); mkorg("ci-lk"); st_idle = s4state()
    a, ra = run_async("BEGIN; " + li("orders", "lk-c", "ci-lk") + "; SELECT pg_sleep(3); COMMIT;")
    time.sleep(1.0); t0 = time.time(); p = apply(P1_ROLLBACK); took = time.time() - t0; a.join()
    rec("S4R.06a_writer_committing_during_the_lock_wait_makes_the_rollback_refuse", ra["rc"] == 0 and p.returncode != 0 and "REFUSED" in p.stderr and "orders" in p.stderr and 1.0 <= took <= 4.9, f"{took:.1f}s {p.stderr[-200:]}")
    rec("S4R.06b_committed_row_claim_and_triggers_survived", q("select (select count(*) from jw_dev.orders where id='lk-c')||'/'||(select ledger from jw_dev.cinema_pg_ledger_claims where org_id='ci-lk')||'/'||(select count(*) from pg_trigger where tgname like 'cinema\\_pg\\_s4\\_%' and not tgisinternal and tgenabled='O')") == "1/legacy/10")
    # lock boundary 2: a writer holds its lock longer than lock_timeout => the rollback fails fast (55P03) instead of hanging or racing
    sh(DB, CLEAN); st_idle = s4state()
    a, ra = run_async("BEGIN; " + li("orders", "lk-1", "ci-lk") + "; SELECT pg_sleep(9); ROLLBACK;")
    time.sleep(1.0); t0 = time.time(); p = apply(P1_ROLLBACK); took = time.time() - t0; a.join()
    rec("S4R.07a_long_running_writer_makes_rollback_fail_on_lock_timeout_not_race", p.returncode != 0 and "55P03" in p.stderr and 3.0 <= took <= 8.5, f"{took:.1f}s {p.stderr[-160:]}")
    rec("S4R.07b_in_flight_writer_unharmed_and_state_unchanged_after_lock_timeout", ra["rc"] == 0 and s4state() == st_idle, str(ra["err"])[-120:])
    # safe state: nothing was ever written -> the rollback runs and restores everything exactly
    sh(DB, CLEAN)
    rec("S4R.08_clean_state_precondition_all_ledgers_and_claims_empty", all(q(f"select count(*) from jw_dev.{t}") == "0" for t in LEDGER + ("cinema_pg_ledger_claims",)))
    nl_pre_rb = datasum(NON_LEDGER)
    p = apply(P1_ROLLBACK); rec("S4M.09_rollback_runs", p.returncode == 0, p.stderr[-300:])
    rec("S4M.10_rollback_restores_fingerprint_and_acl", fp() == base and q(ACLQ) == acl_before)
    rec("S4M.11_no_s4_objects_after_rollback", q("select (select count(*) from pg_trigger where tgname like 'cinema\\_pg\\_s4\\_%')||'/'||(select count(*) from pg_proc where proname like 'cinema\\_pg\\_s4\\_%')||'/'||coalesce(to_regclass('jw_dev.cinema_pg_ledger_claims')::text,'none')") == "0/0/none")
    rec("S4R.09_rollback_restores_membership_rows_exactly_all_six_columns", q(MEMQ) == mem0, q(MEMQ)[-200:])
    rec("S4R.10_rollback_restores_cinema_role_attributes_and_leaves_no_runner_privilege", q(ROLEQ) == role0 and q("select has_table_privilege('jw_mig_admin','jw_dev.cinema_pg_quotes','SELECT')::text||has_schema_privilege('jw_cinema_owner','jw_dev','CREATE')::text") == "falsefalse")
    rec("S4R.11_rollback_did_not_touch_non_ledger_business_data", datasum(NON_LEDGER) == nl_pre_rb)
    p = apply(P1_ROLLBACK)
    rec("S4R.12_second_rollback_is_refused_cleanly_nothing_to_roll_back", p.returncode != 0 and "55000" in p.stderr and "not installed" in p.stderr and fp() == base and q(MEMQ) == mem0, p.stderr[-200:])
    # repeat safety: re-install, use it, refuse, clean, roll back again
    p = apply(MIG); rec("S4R.13_reinstall_after_rollback_works_and_restores_baseline_memberships", p.returncode == 0 and q(MEMQ) == mem0 and q(ROLEQ) == role0, p.stderr[-300:])
    mkorg("ci-z1"); q(li("orders", "z-1", "ci-z1"))
    rec("S4R.14_reinstalled_s4_claims_again", q("select ledger from jw_dev.cinema_pg_ledger_claims where org_id='ci-z1'") == "legacy" and q("select count(*) from pg_trigger where tgname like 'cinema\\_pg\\_s4\\_%' and not tgisinternal and tgenabled='O'") == "10")
    st_z = s4state(); p = apply(P1_ROLLBACK)
    rec("S4R.15_rollback_after_reinstall_with_data_is_refused_and_unchanged", p.returncode != 0 and "REFUSED" in p.stderr and s4state() == st_z, p.stderr[-200:])
    sh(DB, CLEAN); p = apply(P1_ROLLBACK)
    rec("S4R.16_second_clean_rollback_restores_fingerprint_acl_and_memberships", p.returncode == 0 and fp() == base and q(ACLQ) == acl_before and q(MEMQ) == mem0 and q(ROLEQ) == role0, p.stderr[-300:])
    # ---- R5b: Supabase shape: the real dev runner (postgres) inherits pg_read_all_data and therefore ALREADY reads every table. Found by a read-only
    # look at the dev project; the emulated runner above has no such role, so this configuration needs its own scenario.
    q("GRANT pg_read_all_data TO jw_mig_admin")
    _rsel = lambda: q("select has_table_privilege('jw_mig_admin','jw_dev.cinema_pg_quotes','SELECT')::text")
    p = apply(MIG)
    rec("S4V.01_install_works_when_runner_already_reads_every_table_via_pg_read_all_data", p.returncode == 0 and _rsel() == "true", p.stderr[-300:])
    rec("S4V.02_install_adds_no_acl_or_membership_residue_in_that_configuration", q(ACLQ) == acl_before and q(MEMQ) == mem0 and q(ROLEQ) == role0)
    mkorg("ci-v1"); q(li("orders", "v-1", "ci-v1")); stv = s4state(); p = apply(P1_ROLLBACK)
    rec("S4V.03_rollback_refuses_with_data_in_that_configuration_and_changes_nothing", p.returncode != 0 and "REFUSED" in p.stderr and s4state() == stv, p.stderr[-200:])
    sh(DB, CLEAN); p = apply(P1_ROLLBACK)
    rec("S4V.04_clean_rollback_in_that_configuration_restores_everything", p.returncode == 0 and fp() == base and q(ACLQ) == acl_before and q(MEMQ) == mem0 and q(ROLEQ) == role0 and _rsel() == "true", p.stderr[-300:])
    q("REVOKE pg_read_all_data FROM jw_mig_admin")
    rec("S4V.05_cleanup_returns_runner_to_the_plain_configuration", _rsel() == "false" and fp() == base)
    # ---- static checks of the CI definition and of the candidate files
    _wf = (REPO / ".github/workflows/jw-cinema-pg-p1-p2-pg17.yml").read_text()
    rec("STAT.01_workflow_uses_postgres_17_disposable_service", "image: postgres:17" in _wf and "POSTGRES_HOST_AUTH_METHOD: trust" in _wf)
    rec("STAT.02_workflow_publishes_service_port_on_loopback_only", re.search(r"^\s*-\s*127\.0\.0\.1:5432:5432\s*(#.*)?$", _wf, re.M) is not None and re.search(r"^\s*-\s*(0\.0\.0\.0:)?5432:5432\s*(#.*)?$", _wf, re.M) is None)
    rec("STAT.03_workflow_references_no_secrets_tokens_or_external_database_settings", not re.search(r"secrets\.|onrender\.com|supabase\.co|postgres(ql)?://|^\s*(SUPABASE_\w*|DATABASE_URL|RENDER_\w*|PGPASSWORD|POSTGRES_PASSWORD)\s*:", _wf, re.M))
    rec("STAT.04_workflow_has_read_only_contents_permission_and_no_write_scopes", re.search(r"^permissions:\s*\n\s+contents:\s*read\s*$", _wf, re.M) is not None and not re.search(r":\s*write\b", _wf))
    rec("STAT.05_workflow_has_no_pull_request_target_or_pull_request_trigger", "pull_request_target" not in _wf and not re.search(r"^\s*pull_request\s*:", _wf, re.M))
    rec("STAT.06_runtime_environment_has_no_production_or_supabase_connection_settings", not _ENV_NAMES and not _ENV_VALUES and (_host in ("localhost", "127.0.0.1", "::1") or _host.startswith("/")))
    rec("STAT.07_candidate_sql_files_contain_no_password_secret_or_connection_string", not any(re.search(r"(?i)password\s+'|encrypted\s+password|postgres(ql)?://|api[_-]?key|service_role\s*key|eyJ[A-Za-z0-9_-]{20,}", f.read_text()) for f in (ORIG_MIG, P1_ROLLBACK, P2, P2R)))
finally:
    adm.sql(f"DROP DATABASE IF EXISTS {DB} WITH (FORCE)")
    f = [r for r in R if r[1] != "PASS"]
    print(f"\nSUMMARY {len(R)-len(f)}/{len(R)} PASS, failures={len(f)}")
    REPORT.write_text(json.dumps({"server": ver if 'ver' in dir() else None, "server_version_num": SVN, "mode": "PG17_CI" if MAJOR == 17 else "SUPPLEMENTAL_LOCAL_PG16", "expected_checks": EXPECTED_CHECKS, "results": R}, ensure_ascii=False, indent=1))
_bad = [r for r in R if r[1] != "PASS"]
_names = [r[0] for r in R]
_missing = [n for n in BASELINE_CHECKS if n not in _names]
_odd = [r for r in R if r[1] not in ("PASS", "FAIL")]
if _bad or _odd or _missing or len(set(_names)) != len(_names) or len(R) != EXPECTED_CHECKS:
    raise SystemExit(f"FAIL: {len(_bad)} failed, {len(R)} checks run (expected {EXPECTED_CHECKS}), missing baseline checks={_missing}, non PASS/FAIL statuses={len(_odd)}")
print("PASS_P1_P2_PG17_CANDIDATE_GATE" if MAJOR == 17 else "PASS_SUPPLEMENTAL_LOCAL_PG16_ONLY_NOT_PG17_EVIDENCE")
