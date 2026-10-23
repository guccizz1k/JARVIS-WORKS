"""Non-destructive PG17 catalog-only audit. Exit 2=NOT RUN, 1=FAIL, 0=CATALOG PASS.

Never tests actual tenant cross-access, and never authorizes a production cutover.
Requires *two* explicitly supplied DSNs to the same precreated synthetic lab DB.
"""
from __future__ import annotations

import json
import os
import re
import sys

from app.pg_rls_gate_v79 import audit_catalog, DANGEROUS_GRANTS
from app.pg_full_shadow_v76 import EXPECTED_TABLES

LAB_DB = re.compile(r'^jw_v20_test_[0-9a-f]{12}$')


def preflight(env):
    if env.get('JW_ENV','').strip().lower() in ('prod','production'):
        return 'Never query production via this lab auditor'
    if env.get('JW_PG_V79_CONSENT')!='ONLY_DISPOSABLE_LAB':
        return 'Explicit disposable lab consent missing'
    if not env.get('JW_PG_V79_ADMIN_DSN') or not env.get('JW_PG_V79_APP_DSN'):
        return 'Both separate lab PostgreSQL DSNs required'
    return None


def _connect_guard(cur, expected_role):
    cur.execute('SELECT current_database(), session_user, current_setting(%s)',('server_version_num',))
    db,role,version=cur.fetchone()
    if not LAB_DB.fullmatch(db) or role!=expected_role or int(version)//10000!=17:
        raise RuntimeError('Only disposable PG17 lab DB and expected login permitted')
    return db


def collect_catalog(admin, app):
    """Only read PostgreSQL system catalogs, never read user/customer rows."""
    with admin.cursor() as cur:
        db=_connect_guard(cur,'postgres')
        with app.cursor() as ac:
            if _connect_guard(ac,'jw_app')!=db:
                raise RuntimeError('Lab DSNs target different databases')
        cur.execute("SELECT rolname,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication FROM pg_roles WHERE rolname='jw_app'")
        role_row=cur.fetchone()
        if role_row is None:
            raise RuntimeError('Missing jw_app role')
        cur.execute("SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid WHERE m.member='jw_app'::regrole")
        memberships=[r[0] for r in cur.fetchall()]
        role=dict(zip(('name','superuser','bypassrls','createrole','createdb','replication'),role_row))
        role['member_of']=memberships
        cur.execute("""SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,owner.rolname,
                         c.oid FROM pg_class c
                         JOIN pg_namespace n ON n.oid=c.relnamespace
                         JOIN pg_roles owner ON owner.oid=c.relowner
                         WHERE n.nspname='public' AND c.relkind IN ('r','p')""")
        tables={}
        for name,enabled,forced,owner,oid in cur.fetchall():
            # privilege checks executed as the unprivileged role, not inferred
            # from ownership alone; both effective and direct grants matter.
            grants={}
            for grant in ('SELECT',)+DANGEROUS_GRANTS:
                cur.execute('SELECT has_table_privilege(%s,%s,%s)',('jw_app',f'public."{name}"',grant))
                grants[grant]=cur.fetchone()[0]
            tables[name]={'rls_enabled':enabled,'force_rls':forced,'owner':owner,'grants':grants}
        cur.execute("""SELECT tablename,policyname,cmd,roles,permissive,qual FROM pg_policies
                         WHERE schemaname='public'""")
        policies={name:[] for name in EXPECTED_TABLES}
        for table,name,cmd,roles,permissive,qual in cur.fetchall():
            policies.setdefault(table,[]).append({'name':name,'command':cmd,'roles':roles,'permissive':permissive=='PERMISSIVE','using':qual})
        cur.execute("""SELECT n.nspname,p.proname,p.prosecdef,owner.rolname,
                         has_function_privilege('jw_app',p.oid,'EXECUTE'),
                         pg_get_function_identity_arguments(p.oid),p.proconfig,
                         EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
                                WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
                         FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                         JOIN pg_roles owner ON owner.oid=p.proowner
                         WHERE n.nspname='jw_guard' AND p.proname='current_tenant'""")
        fnrows=cur.fetchall()
        guard={}
        if len(fnrows)==1:
            schema,name,definer,owner,can_exec,args,settings,public_exec=fnrows[0]
            guard={'schema':schema,'name':name,'definer':definer,'owner':owner,
                   'app_can_execute':can_exec,'signature':'current_tenant('+args+')',
                   'settings':settings or [],'public_can_execute':public_exec}
    return {'app_role':role,'tables':tables,'policies':policies,'tenant_guard':guard}


def run():
    blocker=preflight(os.environ)
    if blocker:
        print('NOT RUN: '+blocker,file=sys.stderr)
        return 2
    try:
        import psycopg
    except ImportError:
        print('NOT RUN: psycopg driver unavailable',file=sys.stderr)
        return 2
    try:
        with psycopg.connect(os.environ['JW_PG_V79_ADMIN_DSN']) as admin, psycopg.connect(os.environ['JW_PG_V79_APP_DSN']) as app:
            with admin.transaction(),app.transaction():
                snapshot=collect_catalog(admin,app)
                result=audit_catalog(snapshot)
                print(json.dumps({'decision':result.decision,'tables':result.tables,
                    'policies':result.policies,'findings':result.findings,
                    'postgres_catalog_queried':True,'tenant_cross_access_attack':'NOT_RUN',
                    'write_rls':'NOT_IMPLEMENTED','deployment_allowed':False},ensure_ascii=False))
                return 0 if result.decision=='CATALOG_ONLY_PASS' else 1
    except Exception as exc:
        print('FAIL: catalog audit: '+type(exc).__name__+' (connection details redacted)',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(run())
