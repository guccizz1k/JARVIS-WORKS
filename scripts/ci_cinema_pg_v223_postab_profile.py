#!/usr/bin/env python3
"""Fail-closed, read-only preflight for REAL post-A/B V22.3 development backup.

This is NOT a backup and cannot report P0 PASS. Accepts credentials only from
private process environment; never prints host credentials, DSN, row content,
keys, or function definitions. All database commands are SELECT or READ ONLY.
"""
from __future__ import annotations
import json
import os
import re
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.pg_backup_v223 import guard_source,parse_dsn,BackupError,IDENTITY_SQL

PROJECT_REF="rvymwwzclagvljnofyss"
HOST="aws-0-ap-northeast-2.pooler.supabase.com"
SCHEMA="jw_dev"
ROLE="jw_backup_ro"
FINGERPRINT="d3e6284dfbd277b43041052ea8f927ca"
EXPECTED={"tables":65,"force_rls":64,"functions":72,"triggers":74,
          "approved_quote_constraint":1,"side_tables_secured":3,
          "side_functions_secured":3,"backup_readable":65,
          "backup_writable":0,"transition_rows":22}
EXTRA_SQL="""
WITH objects AS (
 SELECT c.oid,c.relname,c.relrowsecurity,c.relforcerowsecurity,
        pg_get_userbyid(c.relowner) AS owner
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p')
), bfunc AS (
 SELECT p.oid,p.proowner,p.prosecdef,p.proconfig,p.proacl,
        pg_get_userbyid(p.proowner) AS owner
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='jw_dev' AND p.proname IN (
   'cinema_pg_order_terms_set','cinema_pg_invoice_terms_set',
   'cinema_pg_payment_note_set')
)
SELECT
 (SELECT count(*) FROM pg_constraint k WHERE
   k.conrelid='jw_dev.cinema_pg_quotes'::regclass AND
   k.conname='cinema_pg_quote_two_person' AND k.convalidated),
 (SELECT count(*) FROM objects WHERE relname IN (
   'cinema_pg_order_terms','cinema_pg_invoice_terms',
   'cinema_pg_payment_notes') AND relrowsecurity AND relforcerowsecurity
   AND owner='jw_cinema_owner'),
 (SELECT count(*) FROM bfunc WHERE proconfig @> ARRAY['search_path=pg_catalog']
   AND prosecdef AND owner='jw_cinema_owner'
   AND NOT EXISTS(SELECT 1 FROM
     aclexplode(coalesce(proacl,acldefault('f',proowner))) acl
     WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE')
   AND NOT has_function_privilege('anon',oid,'EXECUTE')
   AND NOT has_function_privilege('authenticated',oid,'EXECUTE')
   AND has_function_privilege('jw_cinema_writer',oid,'EXECUTE')),
 (SELECT count(*) FROM objects WHERE has_table_privilege('jw_backup_ro',oid,'SELECT')),
 (SELECT count(*) FROM objects WHERE
   has_table_privilege('jw_backup_ro',oid,'INSERT') OR
   has_table_privilege('jw_backup_ro',oid,'UPDATE') OR
   has_table_privilege('jw_backup_ro',oid,'DELETE') OR
   has_table_privilege('jw_backup_ro',oid,'TRUNCATE') OR
   has_table_privilege('jw_backup_ro',oid,'REFERENCES') OR
   has_table_privilege('jw_backup_ro',oid,'TRIGGER')),
 (SELECT count(*) FROM jw_dev.cinema_pg_transitions)
"""

ROLE_SQL="""
SELECT rolcanlogin,rolbypassrls,rolsuper,rolcreaterole,
       rolcreatedb,rolreplication,rolconnlimit,
       rolvaliduntil > now(), rolvaliduntil
FROM pg_roles WHERE rolname=current_user
"""

def classify(identity_row, extra_row, role_row):
    """Pure verdict with no data-dependent logging; all fields required."""
    issues=[]
    if not isinstance(identity_row,(list,tuple)) or len(identity_row)!=7:
        return ["source_identity_row_shape"]
    for key,actual in zip(
        ("tables","force_rls","functions","triggers"),identity_row[:4]):
        if type(actual) is not int or actual!=EXPECTED[key]:
            issues.append(key)
    if identity_row[6]!=FINGERPRINT:
        issues.append("schema_fingerprint")
    if not isinstance(extra_row,(list,tuple)) or len(extra_row)!=6:
        return issues+["ab_security_row_shape"]
    for key,actual in zip(
        ("approved_quote_constraint","side_tables_secured",
         "side_functions_secured","backup_readable",
         "backup_writable","transition_rows"),extra_row):
        if type(actual) is not int or actual!=EXPECTED[key]:
            issues.append(key)
    expected_role=(True,True,False,False,False,False,2,True)
    if (not isinstance(role_row,(tuple,list)) or len(role_row)!=9 or
        tuple(role_row[:8])!=expected_role or role_row[8] is None):
        issues.append("backup_role_privilege_or_expiration")
    return issues

def run_live():
    if os.environ.get("JW_ENV")!="review":
        raise BackupError("BLOCKED_JW_REVIEW_ONLY")
    dsn=os.environ.get("JW_PG_SOURCE_DSN","")
    if not dsn:
        raise BackupError("BLOCKED_SOURCE_CREDENTIALS_NOT_AVAILABLE")
    opts=guard_source(dsn)
    if (opts.get("host")!=HOST or opts.get("port")!="5432" or
        opts.get("dbname")!="postgres" or
        opts.get("user")!=f"{ROLE}.{PROJECT_REF}"):
        raise BackupError("BLOCKED_WRONG_REAL_DEV_DATABASE_IDENTITY")
    import psycopg
    with psycopg.connect(dsn,connect_timeout=8,autocommit=True) as conn:
        conn.execute("BEGIN READ ONLY")
        user,db,major,read_only=conn.execute(
            "SELECT current_user,current_database(),"
            "current_setting('server_version_num')::int,"
            "current_setting('transaction_read_only')").fetchone()
        if (user,db)!=(ROLE,"postgres") or major//10000!=17 or read_only!="on":
            raise BackupError("BLOCKED_DB_SESSION_IDENTITY")
        identity=conn.execute(IDENTITY_SQL,{"s":SCHEMA}).fetchone()
        extra=conn.execute(EXTRA_SQL).fetchone()
        role=conn.execute(ROLE_SQL).fetchone()
        issues=classify(identity,extra,role)
        conn.execute("ROLLBACK")
    if issues:
        print("POST_AB_SOURCE_GATE=BLOCKED")
        print("FAILED_CHECKS="+",".join(issues))
        return 2
    print("POST_AB_SOURCE_GATE=PASS")
    print("SCHEMA_FINGERPRINT="+FINGERPRINT)
    print("TABLES=65 FORCE_RLS=64 FUNCTIONS=72 TRIGGERS=74")
    print("BACKUP_ROLE_READABLE=65 WRITABLE=0")
    print("SOURCE_MUTATIONS=NONE")
    print("NOT_REAL_BACKUP_OR_RESTORE_PASS")
    return 0

def main():
    try:
        return run_live()
    except Exception as exc:
        reason=(str(exc) if isinstance(exc,BackupError) else
                "BLOCKED_"+type(exc).__name__.upper())
        if not re.fullmatch(r"BLOCKED_[A-Z0-9_]+",reason):
            reason="BLOCKED_UNEXPECTED_EXCEPTION"
        print("POST_AB_SOURCE_GATE=BLOCKED")
        print("REASON="+reason)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
