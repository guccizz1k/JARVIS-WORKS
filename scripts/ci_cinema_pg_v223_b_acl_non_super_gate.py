#!/usr/bin/env python3
"""Regression for SUPABASE-like, non-superuser owner role during terms migration.

Never contacts Supabase. Runs only against an explicitly flagged localhost-only
disposable PostgreSQL 17. This caught a security leak that superuser-only CI
could not detect: PUBLIC EXECUTE on three SECURITY DEFINER business functions.
"""
from __future__ import annotations
import os
from pathlib import Path
import secrets
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import ci_cinema_pg_sql_gate as gate
from scripts import ci_cinema_pg_v223_migration_gate as mg

def require(flag,label):
    print(("PASS" if flag else "FAIL")+" "+label)
    if not flag:
        raise RuntimeError("FAILED_"+label)

def swapped_acl_sql(text):
    start=text.index("DO $g$\n",text.index("-- ---------------------------------------------------------------------------- privileges"))
    end=text.index("END $g$;",start)+len("END $g$;")
    block=text[start:end]
    orig=block+"\nRESET ROLE;"
    if orig not in text or text.count(orig)!=1:
        raise RuntimeError("BLOCKED_ACL_SOURCE_MARKER_CHANGED")
    return text.replace(orig,"RESET ROLE;\n"+block)

def one_query(db,statement):
    return db.one(statement)

def run():
    gate.local_server_or_die()
    admin=gate.Psql("postgres")
    ver=admin.sql("SHOW server_version_num").stdout.strip()
    require(ver.isdigit() and 170000<=int(ver)<180000,"PG17_disposable_server")
    db=mg.make_db(admin,with_terms=False)
    sim=mg.SIM_ADMIN
    try:
        # Bootstrap as local synthetic superuser, then use only the
        # restricted LOGIN/CREATEROLE/BYPASSRLS admin when running proposal.
        for stmt in (
            f"CREATE ROLE {sim} LOGIN CREATEROLE BYPASSRLS NOSUPERUSER PASSWORD '{mg.SIM_PW}'",
            f"GRANT jw_cinema_owner TO {sim} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE",
            f"ALTER SCHEMA jw_dev OWNER TO {sim}",
        ):
            db.q(stmt)
        require(db.one(f"SELECT NOT rolsuper AND rolcreaterole AND rolbypassrls FROM pg_roles WHERE rolname='{sim}'") is True,
                "simulated_Supabase_non_superuser")
        candidate=mg.TERMS.read_text(encoding="utf-8")
        # Mutation: put REVOKE after RESET ROLE, reproducing the exact
        # bug seen in live Supabase. The NEW assertion must abort atomically.
        with tempfile.TemporaryDirectory(prefix="jw_terms_acl_") as d:
            path=Path(d)/"broken.sql"
            path.write_text(swapped_acl_sql(candidate),encoding="utf-8")
            bad=db.psql(path,sim,mg.SIM_PW)
        require(bad.returncode!=0 and "V22.3 B security ACL verification failed" in bad.stderr,
                "old_acl_ordering_rejected")
        require(db.one("SELECT to_regclass('jw_dev.cinema_pg_order_terms') IS NULL") is True,
                "failed_migration_rolled_back_all_terms")
        # The review candidate must run as a NON-SUPERUSER, unlike
        # the old PG17 synthetic gate. Denial of public EXECUTE is enforced
        # inside the SAME transaction as table/function creation.
        good=db.psql(mg.TERMS,sim,mg.SIM_PW)
        require(good.returncode==0, "terms_apply_as_non_superuser")
        safe=db.one("""
          SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='jw_dev' AND p.proname IN
            ('cinema_pg_order_terms_set','cinema_pg_invoice_terms_set','cinema_pg_payment_note_set')
          AND NOT has_function_privilege('public',p.oid,'EXECUTE')
          AND NOT has_function_privilege('anon',p.oid,'EXECUTE')
          AND NOT has_function_privilege('authenticated',p.oid,'EXECUTE')
          AND has_function_privilege('jw_cinema_writer',p.oid,'EXECUTE')
          AND p.prosecdef
          AND p.proconfig @> ARRAY['search_path=pg_catalog']
          AND pg_get_userbyid(p.proowner)='jw_cinema_owner'
        """)
        require(safe==3,"three_functions_public_denied_writer_granted")
        protected=db.one("""
          SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='jw_dev' AND c.relname IN
            ('cinema_pg_order_terms','cinema_pg_invoice_terms','cinema_pg_payment_notes')
          AND c.relrowsecurity AND c.relforcerowsecurity
        """)
        require(protected==3,"all_new_tables_force_rls")
        membership=db.one(f"""SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid
          JOIN pg_roles u ON u.oid=m.member WHERE r.rolname='jw_cinema_owner' AND u.rolname='{sim}'
          AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option""")
        require(membership==1,"non_superuser_admin_membership_restored")
        print("PASS_V223_NON_SUPERUSER_TERMS_ACL_GATE checks=7 failed=0 synthetic_only=true")
    finally:
        admin.sql(f"DROP DATABASE IF EXISTS {db.name} WITH (FORCE)")
        admin.sql(f"DROP ROLE IF EXISTS {sim}")

if __name__=="__main__":
    run()
