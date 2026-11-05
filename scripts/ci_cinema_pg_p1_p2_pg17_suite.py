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
EXPECTED_CHECKS = 96
if os.environ.get("JW_CINEMA_PG_DISPOSABLE") != "1":
    raise SystemExit("BLOCKED: set JW_CINEMA_PG_DISPOSABLE=1 to confirm a throw-away local cluster")
_host = os.environ.get("PGHOST", "")
if not (_host.startswith("/") or _host in ("localhost", "127.0.0.1", "::1")):
    raise SystemExit("BLOCKED: PGHOST must be a unix socket directory or loopback address")
old = runpy.run_path(str(REPO / "scripts/ci_cinema_pg_sql_gate.py")); Psql = old["Psql"]; BASE = old["BASE_FILES"]
ENGINE = "scripts/review/cinema_pg_write_engine.sql"
ORIG_MIG = REVIEW / "cinema_pg_s4_dev_migration.sql"
P1_ROLLBACK = REVIEW / "cinema_pg_s4_dev_rollback.sql"
P2 = REVIEW / "cinema_pg_p2_login_role.sql"; P2R = REVIEW / "cinema_pg_p2_login_role_rollback.sql"
MIG = ORIG_MIG
HERE = Path(tempfile.mkdtemp(prefix="jw_p1p2_"))   # scratch only (never inside the repo)
R = []
def rec(n, ok, d=""): R.append((n, "PASS" if ok else "FAIL", d)); print(("PASS " if ok else "FAIL ") + n + (" | " + d if d and not ok else ""), flush=True)
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
if SVN < 170000 and not ALLOW_PG16:
    raise SystemExit(f"BLOCKED: PostgreSQL 17 required (server_version_num={SVN}); --allow-pg16-local is supplemental only")
if SVN < 170000:   # supplemental local run: ONLY the version floor is lowered, in a scratch copy
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
def apply(path, user="jw_mig_admin"):
    return subprocess.run(["psql","-X","-q","-v","ON_ERROR_STOP=1","--single-transaction","-d",DB,"-U",user,"-f",str(path)],capture_output=True,text=True,timeout=120)
def q(sql, user=None): return must(sh(DB, sql, user), sql[:50])
try:
    must(adm.sql("select 1"), "conn"); ver = must(sh("postgres","show server_version"), "ver"); print("SERVER", ver)
    build()
    base = fp()
    # ---- R0: refusal preconditions (must fail closed, leave nothing behind)
    q("INSERT INTO jw_dev.organizations(id,name,created_at) VALUES('pre-x','x',now()::text)")
    q("INSERT INTO jw_dev.orders(id,org_id) VALUES('pre-o','pre-x')")
    p = apply(ORIG_MIG)
    if SVN < 170000:
        rec("S4M.00z_original_file_requires_pg17", p.returncode != 0 and "requires PostgreSQL 17" in p.stderr, p.stderr[-120:])
    else:
        rec("S4M.00z_original_file_passes_pg17_gate_then_refuses_non_empty_ledger", p.returncode != 0 and "requires PostgreSQL 17" not in p.stderr and "non-empty ledger" in p.stderr, p.stderr[-160:])
    p = apply(MIG)
    rec("S4M.00a_refuses_non_empty_ledger", p.returncode != 0 and "non-empty ledger" in p.stderr, p.stderr[-140:])
    rec("S4M.00b_refusal_leaves_no_residue", q("select to_regclass('jw_dev.cinema_pg_ledger_claims') is null") == "t" and fp() == base)
    q("DELETE FROM jw_dev.orders WHERE id='pre-o'")
    p = apply(MIG, user="postgres")
    rec("S4M.00c_refuses_superuser_runner", p.returncode != 0 and "non-superuser" in p.stderr, p.stderr[-140:])
    # ---- R1: apply as the non-superuser owner
    acl_before = q("select string_agg(relname||coalesce(relacl::text,''),'|' order by relname) from pg_class where relnamespace='jw_dev'::regnamespace and relname in ('quotes','orders','invoices','payments')")
    schema_acl_before = q("select coalesce(nspacl::text,'') from pg_namespace where nspname='jw_dev'")
    p = apply(MIG)
    rec("S4M.01_migration_applies_as_nonsuperuser_owner", p.returncode == 0, p.stderr[-300:])
    if p.returncode: raise SystemExit("migration failed; stop")
    rec("S4M.02_ten_enabled_triggers", q("select count(*) from pg_trigger where tgname like 'cinema\\_pg\\_s4\\_%' and not tgisinternal and tgenabled='O'") == "10")
    rec("S4M.03_legacy_and_cinema_acl_restored_exactly", q("select string_agg(relname||coalesce(relacl::text,''),'|' order by relname) from pg_class where relnamespace='jw_dev'::regnamespace and relname in ('quotes','orders','invoices','payments')") == acl_before)
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
    lq = lambda i,o: f"INSERT INTO jw_dev.quotes(id,org_id,customer_id,customer_name_snapshot,doc_no,title,status,vat_mode,created_at,updated_at) VALUES('{i}','{o}','cu-{o}','S','Q-{i}','S','draft','exempt',now()::text,now()::text)"
    cq = lambda i,o: f"INSERT INTO jw_dev.cinema_pg_quotes(id,org_id,trade_no,partner_id,title,status,vat_mode,created_by) VALUES('{i}','{o}','T-{i}','pa-{o}','S','draft','exempt','ci-ua')"
    q(lq("lg1", "ci-p"))
    c = err_state(DB, cq("cn1", "ci-p"))
    rec("S4A.01_legacy_first_blocks_cinema_same_tenant", c[1] == "23514" and "reserved" in c[2], str(c))
    q(cq("cn2", "ci-q"))
    c = err_state(DB, lq("lg2", "ci-q"))
    rec("S4A.02_cinema_first_blocks_legacy_same_tenant", c[1] == "23514" and "reserved" in c[2], str(c))
    rec("S4A.03_other_tenants_unaffected", q("select count(*) from jw_dev.cinema_pg_ledger_claims") == "2")
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
    c = err_state(DB, "INSERT INTO jw_dev.quotes(id,org_id,customer_id,customer_name_snapshot,doc_no,title,status,vat_mode,created_at,updated_at) VALUES('lg9',' ci-p','cu-ci-p','S','Q-9','S','draft','exempt',now()::text,now()::text)")
    rec("S4X.whitespace_org_id_rejected", c[0] != 0 and c[1] == "23514", str(c))
    # claim persistence: deleting all rows must NOT free the tenant for the other ledger
    q("DELETE FROM jw_dev.quotes WHERE id='lg1'")
    c = err_state(DB, cq("cn3", "ci-p")); rec("S4X.claim_survives_row_deletion", c[0] != 0 and "reserved" in c[2], str(c))
    # multi-row / single-transaction mixed-ledger attack on a NEW tenant
    q("INSERT INTO jw_dev.organizations(id,name,created_at) VALUES('ci-m','M',now()::text)"); q("INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES('cu-ci-m','ci-m','S',now()::text)"); q("INSERT INTO jw_dev.cinema_pg_partners(id,org_id,name,created_by) VALUES('pa-ci-m','ci-m','S','ci-ua')")
    c = err_state(DB, "BEGIN; " + cq("mx1", "ci-m") + "; " + lq("mx2", "ci-m") + "; COMMIT;"); rec("S4X.same_tx_mixed_ledgers_blocked", c[0] != 0 and "reserved" in c[2], str(c))
    rec("S4X.same_tx_failure_leaves_no_claim", q("select count(*) from jw_dev.cinema_pg_ledger_claims where org_id='ci-m'") == "0")
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
    # ---- P2: least-privilege LOGIN role (candidate file, applied here on the throw-away DB only)
    rec("P2.00_no_password_or_secret_in_sql", not re.search(r"(?i)password\s+'|encrypted\s+password|passwd|postgres(ql)?://", P2.read_text()))
    p = apply(P2); rec("P2.01_login_role_sql_applies_as_nonsuperuser", p.returncode == 0, p.stderr[-300:])
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
    p = apply(P2); rec("P2.19_reapply_after_rollback_works", p.returncode == 0, p.stderr[-200:]); apply(P2R)
    # ---- R5: rollback test (apply -> rollback -> fingerprint equal -> re-apply)
    p = apply(P1_ROLLBACK); rec("S4M.09_rollback_runs", p.returncode == 0, p.stderr[-300:])
    rec("S4M.10_rollback_restores_fingerprint_and_acl", fp() == base and q("select string_agg(relname||coalesce(relacl::text,''),'|' order by relname) from pg_class where relnamespace='jw_dev'::regnamespace and relname in ('quotes','orders','invoices','payments')") == acl_before)
    rec("S4M.11_no_s4_objects_after_rollback", q("select (select count(*) from pg_trigger where tgname like 'cinema\\_pg\\_s4\\_%')||'/'||(select count(*) from pg_proc where proname like 'cinema\\_pg\\_s4\\_%')||'/'||coalesce(to_regclass('jw_dev.cinema_pg_ledger_claims')::text,'none')") == "0/0/none")
finally:
    adm.sql(f"DROP DATABASE IF EXISTS {DB} WITH (FORCE)")
    f = [r for r in R if r[1] != "PASS"]
    print(f"\nSUMMARY {len(R)-len(f)}/{len(R)} PASS, failures={len(f)}")
    REPORT.write_text(json.dumps({"server": ver if 'ver' in dir() else None, "server_version_num": SVN, "mode": "PG17_CI" if SVN >= 170000 else "SUPPLEMENTAL_LOCAL_PG16", "expected_checks": EXPECTED_CHECKS, "results": R}, ensure_ascii=False, indent=1))
_bad = [r for r in R if r[1] != "PASS"]
if _bad or len(R) != EXPECTED_CHECKS:
    raise SystemExit(f"FAIL: {len(_bad)} failed, {len(R)} checks run (expected {EXPECTED_CHECKS})")
print("PASS_P1_P2_PG17_CANDIDATE_GATE" if SVN >= 170000 else "PASS_SUPPLEMENTAL_LOCAL_PG16_ONLY_NOT_PG17_EVIDENCE")
