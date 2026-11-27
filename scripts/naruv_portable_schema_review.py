"""Disposable PG17 review package: messenger owner isolation and credential-free schema restore.

The generated package is a review-only snapshot of the exact candidate, not a
Supabase migration. Source/target are fresh local CI databases. No real rows,
passwords, TLS private keys, or cluster globals are exported.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import secrets
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('owner',HERE/'naruv_auth_owner_review.py')
o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)
v=o.v;s=o.s;b=o.b;base=o.base;need=o.need
M='naruv_messenger_executor_ci'
MESSENGER=(
 'search_messenger_companies_v90(text,integer,integer)',
 'v90_start_chat(text)','v90_send_text(text,text,text,text,text,bytea)',
 'v90_mark_read(text,bigint)','v90_edit_text(text,text,bigint)',
 'v90_sync_messages(text,bigint,integer)','v90_sync_edits(text,timestamptz,text,integer)')
GRANTS={
 'organizations':('SELECT(id,name)',),
 'messenger_companies':('SELECT(org_id,business_number)',),
 'messenger_connections':('SELECT','INSERT','UPDATE(status,accepted_at)'),
 'messenger_messages':('SELECT','INSERT','UPDATE(body,version,edited_at)'),
 'messenger_attachments':('SELECT','INSERT'),
 'messenger_edits':('SELECT','INSERT'),
 'messenger_read_positions':('SELECT','INSERT','UPDATE(last_read_seq,updated_at)'),
}
SCHEMAS=sorted(set(base.SCHEMAS)|{'jw_dev','naruv_auth_fence','naruv_quote_fence','naruv_hosted_identity_review','naruv_sync_ci'})
ROLES=set("""jw_app_dev jw_auth_stage_v85 anon authenticated service_role
 jw_ci_trade jw_ci_auth naruv_ci_ingest naruv_native_owner naruv_native_stage
 naruv_auth_fence_owner naruv_quote_fence naruv_hid_owner naruv_hid_reader
 naruv_hid_writer naruv_hid_business naruv_hid_auth naruv_hid_ingest
 naruv_sync_owner_ci naruv_sync_broker_ci naruv_v85_cutover_ci
 naruv_identity_reader_ci naruv_v85_writer_ci naruv_messenger_executor_ci""".split())
TARGET='postgresql://postgres:ci-only-ephemeral-test-password@127.0.0.1:55440/postgres'
SOURCE_CONTAINER='naruv-erp-acl-ci'
TARGET_CONTAINER='naruv-portable-target-ci'
def install_messenger(fixture):
    with psycopg.connect(fixture.root_dsn) as c:
        originals={f:c.execute('SELECT pg_get_functiondef(%s::regprocedure)',('jw_dev.'+f,)).fetchone()[0] for f in MESSENGER}
        c.execute('CREATE ROLE '+M+' NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION')
        c.execute('GRANT USAGE ON SCHEMA jw_dev TO '+M)
        c.execute('GRANT EXECUTE ON FUNCTION jw_dev.current_org_from_session(),jw_dev.current_actor_from_session_v82() TO '+M)
        c.execute('GRANT USAGE ON SEQUENCE jw_dev.messenger_seq_v90 TO '+M)
        for name,perms in GRANTS.items():
            table='jw_dev.'+name
            c.execute('GRANT '+','.join(perms)+' ON '+table+' TO '+M)
            for op,expr in (('SELECT','USING(true)'),('INSERT','WITH CHECK(true)'),('UPDATE','USING(true) WITH CHECK(true)')):
                if any(x==op or x.startswith(op+'(') for x in perms):
                    c.execute('CREATE POLICY messenger_exec_'+op.lower()+' ON '+table+' FOR '+op+' TO '+M+' '+expr)
        for f in MESSENGER:
            c.execute('ALTER FUNCTION jw_dev.'+f+' OWNER TO '+M)
            need(c.execute('SELECT pg_get_functiondef(%s::regprocedure)',('jw_dev.'+f,)).fetchone()[0]==originals[f],'MESSENGER_BODY_CHANGED')
            need(c.execute("SELECT pg_get_userbyid(proowner),prosecdef,proconfig FROM pg_proc WHERE oid=%s::regprocedure",('jw_dev.'+f,)).fetchone()==(M,True,['search_path=pg_catalog']),'MESSENGER_OWNER')
        need(c.execute("SELECT rolcanlogin,rolinherit,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication FROM pg_roles WHERE rolname=%s",(M,)).fetchone()==(False,)*7,'MESSENGER_FLAGS')
        need(c.execute("SELECT count(*) FROM pg_auth_members WHERE roleid=(SELECT oid FROM pg_roles WHERE rolname=%s)",(M,)).fetchone()==(0,),'MESSENGER_MEMBERSHIP')
        need(c.execute("SELECT has_schema_privilege(%s,'jw_dev','CREATE')",(M,)).fetchone()==(False,),'MESSENGER_CREATE')
        c.execute('SET LOCAL ROLE '+M)
        for query in ('SELECT password_hash FROM jw_dev.users','SELECT * FROM jw_dev.sessions',
                      'SELECT * FROM jw_dev.mfa_credentials','DELETE FROM jw_dev.messenger_messages',
                      "UPDATE jw_dev.messenger_connections SET org_a='other'",
                      "UPDATE jw_dev.messenger_messages SET sender_org='other'"):
            s.expect(c,'42501',query)
        c.execute('RESET ROLE')
    print('PORTABLE_MESSENGER_OWNER_PASS routines=7 bodies_unchanged=7 direct_denials=6',flush=True)
def catalog(c):
    # Compare definitions, not OIDs, owner-derived ACL order or target snapshots as
    # a production security baseline. The source is a pinned disposable candidate.
    c.execute('SET LOCAL search_path=pg_catalog')
    queries={
      'schemas':"""SELECT nspname,pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname=ANY(%s)""",
      'schema_acl':"""SELECT n.nspname,pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable
       FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname=ANY(%s)""",
      'relations':"""SELECT n.nspname,t.relname,t.relkind,pg_get_userbyid(t.relowner),t.relrowsecurity,t.relforcerowsecurity,t.relpersistence
       FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=ANY(%s)""",
      'columns':"""SELECT n.nspname,t.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,
       coalesce(pg_get_expr(d.adbin,d.adrelid),'') FROM pg_attribute a JOIN pg_class t ON t.oid=a.attrelid JOIN pg_namespace n ON n.oid=t.relnamespace
       LEFT JOIN pg_attrdef d ON d.adrelid=t.oid AND d.adnum=a.attnum WHERE n.nspname=ANY(%s) AND a.attnum>0 AND NOT a.attisdropped""",
      'functions':"""SELECT n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),pg_get_userbyid(p.proowner),pg_get_functiondef(p.oid)
       FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=ANY(%s)""",
      'policies':"""SELECT schemaname,tablename,policyname,permissive,roles::text[],cmd,qual,with_check FROM pg_policies WHERE schemaname=ANY(%s)""",
      'constraints':"""SELECT n.nspname,t.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated
       FROM pg_constraint k JOIN pg_class t ON t.oid=k.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=ANY(%s)""",
      'indexes':"""SELECT n.nspname,t.relname,pg_get_indexdef(i.indexrelid) FROM pg_index i JOIN pg_class t ON t.oid=i.indexrelid
       JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=ANY(%s)""",
      'triggers':"""SELECT n.nspname,t.relname,g.tgname,g.tgenabled,pg_get_triggerdef(g.oid)
       FROM pg_trigger g JOIN pg_class t ON t.oid=g.tgrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=ANY(%s) AND NOT g.tgisinternal""",
      'sequences':"""SELECT n.nspname,t.relname,format_type(q.seqtypid,NULL),q.seqstart,q.seqincrement,q.seqmax,q.seqmin,q.seqcache,q.seqcycle
       FROM pg_sequence q JOIN pg_class t ON t.oid=q.seqrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=ANY(%s)""",
      'object_acl':"""SELECT n.nspname,t.relname,pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable
       FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
       CROSS JOIN LATERAL aclexplode(coalesce(t.relacl,acldefault(CASE WHEN t.relkind='S' THEN 's'::"char" ELSE 'r'::"char" END,t.relowner))) a
       WHERE n.nspname=ANY(%s) AND t.relkind IN ('r','p','S','v','m','f')""",
      'column_acl':"""SELECT n.nspname,t.relname,c.attname,pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable
       FROM pg_attribute c JOIN pg_class t ON t.oid=c.attrelid JOIN pg_namespace n ON n.oid=t.relnamespace
       CROSS JOIN LATERAL aclexplode(c.attacl) a WHERE n.nspname=ANY(%s) AND c.attnum>0 AND NOT c.attisdropped""",
      'routine_acl':"""SELECT n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable
       FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname=ANY(%s)""",
      'default_acl':"""SELECT n.nspname,pg_get_userbyid(d.defaclrole),d.defaclobjtype,d.defaclacl::text
       FROM pg_default_acl d JOIN pg_namespace n ON n.oid=d.defaclnamespace WHERE n.nspname=ANY(%s)""",
    }
    return {k:sorted(c.execute(q,(SCHEMAS,)).fetchall(),key=repr) for k,q in queries.items()}
def graph(c):
    rows=c.execute("""SELECT rolname,rolinherit,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication,rolconnlimit
       FROM pg_roles WHERE rolname<>'postgres' AND rolname NOT LIKE 'pg\\_%' ESCAPE '\\'""").fetchall()
    need({r[0] for r in rows}==ROLES,'PORTABLE_ROLE_INVENTORY:'+repr(sorted({r[0] for r in rows}^ROLES)))
    need(all(r[1:]==(False,False,False,False,False,False,-1) for r in rows),'PORTABLE_ROLE_FLAGS')
    m=c.execute("""SELECT r.rolname,u.rolname,g.rolname,m.admin_option,m.inherit_option,m.set_option
       FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member
       JOIN pg_roles g ON g.oid=m.grantor WHERE r.rolname=ANY(%s) OR u.rolname=ANY(%s)""",(sorted(ROLES),)*2).fetchall()
    need(all(r in ROLES and u in ROLES|{'postgres'} and g=='postgres' and not a and not i and z for r,u,g,a,i,z in m),'PORTABLE_MEMBERSHIP_FLAGS')
    return sorted(rows),sorted(m)
def execute_container(container,*args,**kwargs):
    need(container in (SOURCE_CONTAINER,TARGET_CONTAINER),'CONTAINER_SCOPE')
    return subprocess.run(['docker','exec','-i',container,*args],check=True,**kwargs)
def create_package(fixture):
    dest=Path(os.environ['NARUV_PORTABLE_OUTPUT']).resolve()
    need(dest.parent==Path(os.environ['RUNNER_TEMP']).resolve() and not dest.exists(),'PACKAGE_PATH')
    dest.mkdir(mode=0o700)
    archive=dest/'schema-only.dump'
    with psycopg.connect(fixture.root_dsn) as c:
        source=catalog(c);roles,members=graph(c)
        need({x[0] for x in source['schemas']}==set(SCHEMAS),'PACKAGE_SCHEMA_SCOPE')
        need(c.execute("SELECT count(*) FROM pg_default_acl WHERE defaclnamespace=0").fetchone()==(0,),'PACKAGE_GLOBAL_DEFAULT_ACL')
    with archive.open('xb') as f:
        execute_container(SOURCE_CONTAINER,'pg_dump','-U','postgres','-d','postgres','--schema-only','--format=custom',*['--schema='+n for n in SCHEMAS],stdout=f)
    toc=execute_container(SOURCE_CONTAINER,'pg_restore','--list',input=archive.read_bytes(),stdout=subprocess.PIPE).stdout.decode()
    need(not any(x in toc for x in (' TABLE DATA ',' SEQUENCE SET ',' BLOB DATA ',' LARGE OBJECT ')),'PACKAGE_DATA_ENTRY')
    need(' TABLE ' in toc and ' FUNCTION ' in toc,'PACKAGE_EMPTY')
    (dest/'schema-only.toc.txt').write_text(toc)
    role_sql=['-- REVIEW ONLY: all service roles remain NOLOGIN; no credentials.']
    for name,*_ in roles:
        role_sql.append('CREATE ROLE '+name+' NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;')
    for role,member,*_ in members:
        role_sql.append('GRANT '+role+' TO '+member+' WITH INHERIT FALSE, SET TRUE;')
    (dest/'roles-review.sql').write_text('\n'.join(role_sql)+'\n')
    with psycopg.connect(TARGET) as c:
        need(c.info.server_version//10000==17,'TARGET_PG17')
        need(c.execute("SELECT count(*) FROM pg_roles WHERE rolname<>'postgres' AND rolname NOT LIKE 'pg\\_%' ESCAPE '\\'").fetchone()==(0,),'TARGET_NOT_FRESH')
        c.execute('\n'.join(role_sql))
    execute_container(TARGET_CONTAINER,'pg_restore','-U','postgres','-d','postgres','--exit-on-error','--single-transaction',input=archive.read_bytes())
    with psycopg.connect(TARGET) as c:
        target=catalog(c)
        for k,rows in source.items():
            if rows!=target[k]:
                left={repr(x) for x in rows};right={repr(x) for x in target[k]}
                # Definitions/ACL only; no row content or credentials.
                print('PACKAGE_DIFF_SECTION='+k+' missing='+repr(sorted(left-right)[:4])+' extra='+repr(sorted(right-left)[:4]),flush=True)
                raise RuntimeError('PACKAGE_CATALOG_DIFF:'+k)
        need(graph(c)==(roles,members),'PACKAGE_ROLE_GRAPH')
        tables=c.execute("""SELECT n.nspname,t.relname FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=ANY(%s) AND t.relkind IN ('r','p')""",(SCHEMAS,)).fetchall()
        for sch,table in tables:
            need(c.execute(sql.SQL('SELECT count(*) FROM {}').format(sql.Identifier(sch,table))).fetchone()==(0,),'PACKAGE_ROW_EXPORTED')
        need(c.execute("SELECT count(*) FROM pg_roles WHERE rolname=ANY(%s) AND rolcanlogin",(sorted(ROLES),)).fetchone()==(0,),'PACKAGE_LOGIN_EXPORTED')
    print('PORTABLE_SCHEMA_RESTORE_PASS schemas='+str(len(SCHEMAS))+' tables='+str(len(tables))+' roles='+str(len(roles))+' catalog_sections='+str(len(source))+' rows=0 login_roles=0',flush=True)
    return dest,len(tables),len(source)
def smoke():
    # Fresh synthetic users only, no source fixture data copied.
    csrf='c'*32
    hashes={x:hashlib.sha256(('portable-review-'+x).encode()).hexdigest() for x in 'abc'}
    pw=secrets.token_urlsafe(32);aw=secrets.token_urlsafe(32)
    with psycopg.connect(TARGET) as c:
        for x in 'abc':
            org='ci-'+x;actor='ci-u'+x
            c.execute("INSERT INTO jw_dev.organizations VALUES(%s,%s,clock_timestamp()::text)",(org,'Company '+x))
            c.execute("INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES(%s,%s,%s,'synthetic-unused',%s,'admin',clock_timestamp()::text)",(actor,org,x+'@invalid.test',actor))
            c.execute("INSERT INTO jw_dev.messenger_companies(org_id,business_number) VALUES(%s,%s)",(org,'synthetic-'+x))
            c.execute("INSERT INTO naruv_hosted_identity_review.organizations VALUES(%s,%s)",(org,'Company '+x))
            c.execute("INSERT INTO naruv_hosted_identity_review.users VALUES(%s,%s,'admin',true,0)",(actor,org))
        for role,secret in [('jw_ci_trade',pw),('naruv_v85_cutover_ci',aw)]:
            c.execute(sql.SQL('ALTER ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(role),sql.Literal(secret)))
    ad=make_conninfo(TARGET,user='naruv_v85_cutover_ci',password=aw)
    td=make_conninfo(TARGET,user='jw_ci_trade',password=pw)
    with psycopg.connect(ad,autocommit=True) as a:
        a.execute('SET ROLE jw_auth_stage_v85')
        for x in 'abc':
            need(bool(a.execute('SELECT jw_dev.v85_auth_issue_session(%s,%s,%s,NULL,NULL)',('ci-u'+x,hashes[x],csrf)).fetchone()[0]),'RESTORE_ISSUE')
        def call(c,statement,args=()):return c.execute(statement,args).fetchone()
        with psycopg.connect(td) as c:
            b.bind(c,hashes['a'])
            chat=call(c,"SELECT jw_dev.v90_start_chat('ci-b')")[0]
            msg=call(c,"SELECT * FROM jw_dev.v90_send_text(%s,'portable-req-1','synthetic message',NULL,NULL,NULL)",(chat,))
            need(msg[2] is False,'RESTORE_SEND')
            again=call(c,"SELECT * FROM jw_dev.v90_send_text(%s,'portable-req-1','synthetic message',NULL,NULL,NULL)",(chat,))
            need(again==(msg[0],msg[1],True),'RESTORE_REPLAY')
            need(call(c,"SELECT jw_dev.v90_edit_text(%s,'edited',1)",(msg[0],))==(2,),'RESTORE_EDIT')
            for q in ('SELECT * FROM jw_dev.messenger_messages','SELECT * FROM jw_dev.messenger_attachments','SET ROLE '+M):
                s.expect(c,'42501',q)
        with psycopg.connect(td) as c:
            b.bind(c,hashes['b'])
            need(call(c,"SELECT body,version FROM jw_dev.v90_sync_messages(%s,0,100)",(chat,))==('edited',2),'RESTORE_READ')
            need(call(c,"SELECT jw_dev.v90_mark_read(%s,%s)",(chat,msg[1]))==(msg[1],),'RESTORE_CURSOR')
            s.expect(c,'42501',"SELECT jw_dev.v90_edit_text(%s,'forbidden',2)",(msg[0],))
        with psycopg.connect(td) as c:
            b.bind(c,hashes['c'])
            s.expect(c,'42501',"SELECT * FROM jw_dev.v90_sync_messages(%s,0,100)",(chat,))
            s.expect(c,'42501',"SELECT * FROM jw_dev.v90_send_text(%s,'portable-req-2','forbidden',NULL,NULL,NULL)",(chat,))
        need(a.execute('SELECT jw_dev.v85_auth_revoke_session(%s)',(hashes['a'],)).fetchone()==(True,),'RESTORE_REVOKE')
        with psycopg.connect(td) as c:
            b.bind(c,hashes['a'])
            s.expect(c,'42501',"SELECT * FROM jw_dev.v90_send_text(%s,'portable-req-3','revoked',NULL,NULL,NULL)",(chat,))
    print('PORTABLE_RESTORED_MESSENGER_PASS tenants=3 denied=7 replay=PASS edit=PASS cursor=PASS revoke=PASS',flush=True)
def main():
    base.preflight()
    b.pin(HERE/'naruv_auth_owner_review.py','6b382d88591c9b198ce54fadc1765dbf09948d9a')
    fixture,_=base.setup()
    b.install(fixture);s.install(fixture);v.install(fixture);o.install(fixture)
    profile=b.pin(base.ROOT/'db/review/naruv_hr_profile_ci.sql','835b0d6b6210d0e6151d701848f9276f6f5a7be2')
    with psycopg.connect(fixture.root_dsn) as c:
        c.execute("SET LOCAL naruv.profile_ci='DISPOSABLE_ONLY'");c.execute(profile)
    install_messenger(fixture)
    dest,tables,sections=create_package(fixture)
    smoke()
    manifest={'kind':'DISPOSABLE_SCHEMA_REVIEW_ONLY','source':base.SOURCE,'review':os.environ['EXPECTED_SHA'],
      'production_authorized':False,'hosted_install':False,'schemas':SCHEMAS,'tables':tables,'catalog_sections':sections,
      'roles':len(ROLES),'source_rows_exported':0,'login_roles_exported':0,'restore_smoke':'PASS',
      'sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(dest.iterdir())}}
    (dest/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    print('PORTABLE_SCHEMA_REVIEW_PASS production_authorized=false hosted_install=false gate5=BLOCKED',flush=True)
if __name__=='__main__':main()
