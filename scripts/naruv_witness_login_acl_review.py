"""Prospective witness-ledger ACL rehearsal, not approved operating policy.
Only disposable CI database. Three actual service logins, nonlogin object owner.
This is an internal global evidence ledger, not a tenant-scoped business table.
"""
import os
from psycopg.pq import TransactionStatus
from scripts import naruv_future_receipt_review as v

SCHEMA='naruv_witness_ledger_ci'
OWNER='naruv_witness_owner_ci'
REGISTRAR='naruv_witness_registrar_ci'
VERIFIER='naruv_witness_verifier_ci'
READER='naruv_witness_reader_ci'
LOGINS=(REGISTRAR,VERIFIER,READER)
TABLES=('approval','run','evidence')
INSERT={'approval':REGISTRAR,'run':REGISTRAR,'evidence':VERIFIER}
DDL="""
CREATE ROLE naruv_witness_owner_ci NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
ALTER SCHEMA naruv_witness_ledger_ci OWNER TO naruv_witness_owner_ci;
ALTER TABLE naruv_witness_ledger_ci.approval OWNER TO naruv_witness_owner_ci;
ALTER TABLE naruv_witness_ledger_ci.run OWNER TO naruv_witness_owner_ci;
ALTER TABLE naruv_witness_ledger_ci.evidence OWNER TO naruv_witness_owner_ci;
ALTER ROLE naruv_witness_registrar_ci NOINHERIT;
ALTER ROLE naruv_witness_verifier_ci NOINHERIT;
ALTER ROLE naruv_witness_reader_ci NOINHERIT;
ALTER TABLE naruv_witness_ledger_ci.approval ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_witness_ledger_ci.approval FORCE ROW LEVEL SECURITY;
ALTER TABLE naruv_witness_ledger_ci.run ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_witness_ledger_ci.run FORCE ROW LEVEL SECURITY;
ALTER TABLE naruv_witness_ledger_ci.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_witness_ledger_ci.evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY read_approval ON naruv_witness_ledger_ci.approval FOR SELECT TO naruv_witness_registrar_ci,naruv_witness_verifier_ci,naruv_witness_reader_ci USING (true);
CREATE POLICY append_approval ON naruv_witness_ledger_ci.approval FOR INSERT TO naruv_witness_registrar_ci WITH CHECK (true);
CREATE POLICY read_run ON naruv_witness_ledger_ci.run FOR SELECT TO naruv_witness_registrar_ci,naruv_witness_verifier_ci,naruv_witness_reader_ci USING (true);
CREATE POLICY append_run ON naruv_witness_ledger_ci.run FOR INSERT TO naruv_witness_registrar_ci WITH CHECK (true);
CREATE POLICY read_evidence ON naruv_witness_ledger_ci.evidence FOR SELECT TO naruv_witness_registrar_ci,naruv_witness_verifier_ci,naruv_witness_reader_ci USING (true);
CREATE POLICY append_evidence ON naruv_witness_ledger_ci.evidence FOR INSERT TO naruv_witness_verifier_ci WITH CHECK (true);
"""

def guard_login(c,role):
    v.need(os.environ.get('GITHUB_ACTIONS')=='true' and
           os.environ.get('GITHUB_REPOSITORY')=='guccizz1k/JARVIS-WORKS' and
           os.environ.get('NARUV_WITNESS_LEDGER_CI')=='1' and
           os.environ.get('NARUV_WITNESS_DIRECT_LOGIN_CI')=='1','DIRECT_LOGIN_CI_ONLY')
    v.need(role in LOGINS and c.info.host=='127.0.0.1' and c.info.port==55439 and
           c.info.dbname=='postgres' and c.info.user==role and
           c.info.server_version//10000==17,'DIRECT_LOGIN_TARGET')
    v.need(c.autocommit and c.info.transaction_status==TransactionStatus.IDLE,'TRANSACTION_BOUNDARY')
    v.need(c.execute('SELECT session_user,current_user').fetchone()==(role,role),'DIRECT_LOGIN_IDENTITY')
    flags=c.execute("""SELECT rolcanlogin,rolinherit,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication
                       FROM pg_catalog.pg_roles WHERE rolname=%s""",(role,)).fetchone()
    v.need(flags==(True,False,False,False,False,False,False),'DIRECT_LOGIN_ROLE_DRIFT')
    membership=c.execute("""SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m
                          JOIN pg_catalog.pg_roles r ON r.oid=m.member WHERE r.rolname=%s)""",(role,)).fetchone()
    v.need(membership==(False,),'DIRECT_LOGIN_MEMBERSHIP_DRIFT')

def audit(c):
    """Compare target catalog to explicit candidate policy, never learn from target."""
    roles=(OWNER,*LOGINS)
    flags=c.execute("""SELECT rolname::text,rolcanlogin,rolinherit,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication
        FROM pg_catalog.pg_roles WHERE rolname=ANY(%s)""",(list(roles),)).fetchall()
    v.need(set(flags)=={(r,r!=OWNER,False,False,False,False,False,False) for r in roles},'ACL_ROLE_FLAGS')
    n=c.execute("""SELECT count(*) FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles a ON a.oid=m.member JOIN pg_catalog.pg_roles b ON b.oid=m.roleid
        WHERE a.rolname=ANY(%s) OR b.rolname=ANY(%s)""",(list(roles),list(roles))).fetchone()
    v.need(n==(0,),'ACL_ROLE_MEMBERSHIP')
    ns=c.execute("""SELECT pg_catalog.pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace WHERE nspname=%s""",(SCHEMA,)).fetchone()
    v.need(ns==(OWNER,),'ACL_SCHEMA_OWNER')
    rows=c.execute("""SELECT c.relname::text,pg_catalog.pg_get_userbyid(c.relowner),c.relrowsecurity,c.relforcerowsecurity,c.relkind
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=%s AND c.relkind IN ('r','p','v','m','S','f')""",(SCHEMA,)).fetchall()
    v.need(set(rows)=={(t,OWNER,True,True,'r') for t in TABLES},'ACL_OBJECT_OR_RLS')
    grants=c.execute("""SELECT c.relname::text,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,
          pg_catalog.pg_get_userbyid(a.grantor),a.privilege_type,a.is_grantable
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
        WHERE n.nspname=%s AND c.relkind='r' AND a.grantee<>c.relowner""",(SCHEMA,)).fetchall()
    expected={(t,r,OWNER,'SELECT',False) for t in TABLES for r in LOGINS}
    expected|={(t,INSERT[t],OWNER,'INSERT',False) for t in TABLES}
    v.need(set(grants)==expected,'ACL_TABLE_GRANTS')
    grants=c.execute("""SELECT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,
          pg_catalog.pg_get_userbyid(a.grantor),a.privilege_type,a.is_grantable
        FROM pg_catalog.pg_namespace n CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
        WHERE n.nspname=%s AND a.grantee<>n.nspowner""",(SCHEMA,)).fetchall()
    v.need(set(grants)=={(r,OWNER,'USAGE',False) for r in LOGINS},'ACL_SCHEMA_GRANTS')
    cols=c.execute("""SELECT count(*) FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
          JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND a.attacl IS NOT NULL""",(SCHEMA,)).fetchone()
    v.need(cols==(0,),'ACL_COLUMN_GRANTS')
    defs=c.execute("""SELECT count(*) FROM pg_catalog.pg_default_acl d JOIN pg_catalog.pg_roles r ON r.oid=d.defaclrole
                       WHERE r.rolname=ANY(%s)""",(list(roles),)).fetchone()
    v.need(defs==(0,),'ACL_DEFAULT_GRANTS')
    funcs=c.execute("""SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=%s""",(SCHEMA,)).fetchone()
    v.need(funcs==(0,),'ACL_UNEXPECTED_ROUTINE')
    policies=c.execute("""SELECT tablename::text,policyname::text,permissive,roles::text[],cmd,qual,with_check
                         FROM pg_catalog.pg_policies WHERE schemaname=%s""",(SCHEMA,)).fetchall()
    actual={(t,p,per,tuple(sorted(rs)),cmd,q,w) for t,p,per,rs,cmd,q,w in policies}
    expected={(t,'read_'+t,'PERMISSIVE',tuple(sorted(LOGINS)),'SELECT','true',None) for t in TABLES}
    expected|={(t,'append_'+t,'PERMISSIVE',(INSERT[t],),'INSERT',None,'true') for t in TABLES}
    v.need(actual==expected,'ACL_POLICY_DRIFT')
    return 'PASS_PROSPECTIVE_WITNESS_ACL_ONLY'
