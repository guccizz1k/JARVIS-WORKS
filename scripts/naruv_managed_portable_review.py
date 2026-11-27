"""Non-superuser managed-role compatible schema package rehearsal.
Exact pinned review sources, two disposable local PG17 databases. Not a live
Supabase migration. Never executes against an external connection.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('portable',HERE/'naruv_portable_schema_review.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
b=p.b;base=p.base;need=p.need
PLATFORM={'anon','authenticated','service_role'}
CUSTOM=p.ROLES-PLATFORM
ROOT='naruv_platform_root'
ROLE_FLAGS="rolsuper,rolcreaterole,rolcreatedb,rolbypassrls,rolinherit,rolcanlogin"
def ident(x):return '"'+x.replace('"','""')+'"'
def relation(s,n):return ident(s)+'.'+ident(n)
def target_platform():
    root=make_conninfo(p.TARGET,user=ROOT)
    with psycopg.connect(root) as c:
        need(c.execute("SELECT count(*) FROM pg_roles WHERE rolname<>%s AND rolname NOT LIKE 'pg\\_%' ESCAPE '\\'",(ROOT,)).fetchone()==(0,),'MANAGED_TARGET_NOT_FRESH')
        c.execute("CREATE ROLE postgres LOGIN PASSWORD 'ci-only-ephemeral-test-password' NOSUPERUSER CREATEROLE CREATEDB BYPASSRLS INHERIT")
        c.execute('ALTER DATABASE postgres OWNER TO postgres')
        c.execute('CREATE ROLE anon NOLOGIN INHERIT; CREATE ROLE authenticated NOLOGIN INHERIT; CREATE ROLE service_role NOLOGIN INHERIT BYPASSRLS; CREATE ROLE authenticator LOGIN NOINHERIT')
        c.execute('GRANT anon,authenticated,service_role TO authenticator WITH INHERIT FALSE, SET TRUE')
    with psycopg.connect(p.TARGET) as c:
        need(c.execute('SELECT '+ROLE_FLAGS+' FROM pg_roles WHERE rolname=current_user').fetchone()==(False,True,True,True,True,True),'MANAGED_ADMIN_FLAGS')
        return root,platform_snapshot(c)
def platform_snapshot(c):
    return (
      c.execute('SELECT rolname,'+ROLE_FLAGS+' FROM pg_roles WHERE rolname=ANY(%s) ORDER BY rolname',(sorted(PLATFORM|{'postgres','authenticator',ROOT}),)).fetchall(),
      c.execute("""SELECT r.rolname,u.rolname,g.rolname,m.admin_option,m.inherit_option,m.set_option
       FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member JOIN pg_roles g ON g.oid=m.grantor
       WHERE r.rolname=ANY(%s) AND u.rolname=ANY(%s) ORDER BY 1,2,3""",(sorted(PLATFORM|{'postgres','authenticator',ROOT}),)*2).fetchall())
def owner_commands(source):
    schemas=dict(source['schemas'])
    rels={(s,n):(k,o) for s,n,k,o,*_ in source['relations'] if k in ('r','p','S','v','m','f')}
    funcs={(s,n,a):o for s,n,a,o,_ in source['functions']}
    need(set(schemas.values())|{o for _,o in rels.values()}|set(funcs.values())<=CUSTOM|{'postgres'},'MANAGED_OWNER_SCOPE')
    need(not source['default_acl'],'MANAGED_DEFAULT_ACL_UNSUPPORTED')
    q=['RESET ROLE;']
    all_owners=sorted((set(schemas.values())|{o for _,o in rels.values()}|set(funcs.values()))-{'postgres'})
    for owner in set(schemas.values())-{'postgres'}:
        q.append('GRANT CREATE ON DATABASE postgres TO '+ident(owner)+';')
    for schema in sorted(schemas):
        for owner in all_owners:
            q.append('GRANT USAGE,CREATE ON SCHEMA '+ident(schema)+' TO '+ident(owner)+';')
    # pg_restore --no-owner --no-acl created everything as admin.
    for (schema,name),(kind,owner) in sorted(rels.items()):
        typ={'r':'TABLE','p':'TABLE','S':'SEQUENCE','v':'VIEW','m':'MATERIALIZED VIEW','f':'FOREIGN TABLE'}[kind]
        obj=typ+' '+relation(schema,name)
        q.append('REVOKE ALL ON '+obj+' FROM PUBLIC;')
        if owner!='postgres':q.append('ALTER '+obj+' OWNER TO '+ident(owner)+';')
    for (schema,name,args),owner in sorted(funcs.items()):
        obj='FUNCTION '+relation(schema,name)+'('+args+')'
        q.append('REVOKE ALL ON '+obj+' FROM PUBLIC;')
        if owner!='postgres':q.append('ALTER '+obj+' OWNER TO '+ident(owner)+';')
    for schema,owner in sorted(schemas.items()):
        for r in all_owners:
            q.append('REVOKE USAGE,CREATE ON SCHEMA '+ident(schema)+' FROM '+ident(r)+';')
        q.append('REVOKE ALL ON SCHEMA '+ident(schema)+' FROM PUBLIC;')
        if owner!='postgres':q.append('ALTER SCHEMA '+ident(schema)+' OWNER TO '+ident(owner)+';')
    for owner in set(schemas.values())-{'postgres'}:
        q.append('REVOKE CREATE ON DATABASE postgres FROM '+ident(owner)+';')
    # All grants are explicitly reconstructed by the original object owner.
    # Reject a grant chain rather than silently changing its grantor.
    groups={}
    def add(obj,owner,grantor,grantee,priv,option):
        need(owner==grantor,'MANAGED_UNSUPPORTED_GRANT_CHAIN:'+obj)
        need(grantee in p.ROLES|{'PUBLIC','postgres'},'MANAGED_GRANTEE_SCOPE')
        need(not option,'MANAGED_UNSUPPORTED_GRANT_OPTION:'+obj)
        groups.setdefault((owner,obj),[]).append((grantee,priv))
    for schema,grantor,grantee,priv,option in source['schema_acl']:
        add('SCHEMA '+ident(schema),schemas[schema],grantor,grantee,priv,option)
    for schema,name,grantor,grantee,priv,option in source['object_acl']:
        kind,owner=rels[schema,name]
        add(('SEQUENCE ' if kind=='S' else 'TABLE ')+relation(schema,name),owner,grantor,grantee,priv,option)
    for schema,name,args,grantor,grantee,priv,option in source['routine_acl']:
        add('FUNCTION '+relation(schema,name)+'('+args+')',funcs[schema,name,args],grantor,grantee,priv,option)
    # Owner implicit ACL defaults must be preserved, including objects with
    # no nonowner grants. Remove PUBLIC defaults before any commit.
    for (owner,obj),entries in sorted(groups.items(),key=lambda item:(not item[0][1].startswith('SCHEMA '),item[0])):
        q.append('SET ROLE '+ident(owner)+';')
        q.append('REVOKE ALL ON '+obj+' FROM PUBLIC;')
        q.append('REVOKE ALL ON '+obj+' FROM '+ident(owner)+';')
        for grantee,priv in sorted(entries):
            q.append('GRANT '+priv+' ON '+obj+' TO '+('PUBLIC' if grantee=='PUBLIC' else ident(grantee))+';')
        q.append('RESET ROLE;')
    for schema,name,col,grantor,grantee,priv,option in source['column_acl']:
        _,owner=rels[schema,name]
        need(grantor==owner and not option and grantee in p.ROLES|{'postgres'},'MANAGED_COLUMN_CHAIN')
        q.extend(('SET ROLE '+ident(owner)+';','GRANT '+priv+' ('+ident(col)+') ON TABLE '+relation(schema,name)+' TO '+ident(grantee)+';','RESET ROLE;'))
    return '\n'.join(q)+'\n'
def role_commands(members):
    # Preexisting platform roles are verified and never altered.
    check=','.join("'"+x+"'" for x in sorted(CUSTOM))
    names=','.join("'"+x+"'" for x in p.SCHEMAS)
    q=[f"""DO $guard$ BEGIN
 IF current_setting('naruv.managed_rehearsal',true) IS DISTINCT FROM 'DISPOSABLE_CI_ONLY'
 OR current_user<>'postgres' OR current_database()<>'postgres'
 OR current_setting('server_version_num')::int/10000<>17
 OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='postgres' AND NOT rolsuper AND rolcreaterole AND rolbypassrls)
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ({check}))
 OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspname IN ({names}))
 OR (SELECT count(*) FROM pg_roles WHERE rolname IN ('anon','authenticated','service_role'))<>3
 OR EXISTS(SELECT 1 FROM pg_default_acl WHERE defaclnamespace=0 AND defaclrole=(SELECT oid FROM pg_roles WHERE rolname='postgres'))
 THEN RAISE EXCEPTION 'MANAGED_INSTALL_GUARD'; END IF;
END $guard$;"""]
    for role in sorted(CUSTOM):
        q.append('CREATE ROLE '+ident(role)+' NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;')
        q.append('GRANT '+ident(role)+' TO postgres WITH INHERIT FALSE, SET TRUE;')
    for role,member,grantor,a,i,z in members:
        if member=='postgres':continue
        need(role in CUSTOM and member in CUSTOM and grantor=='postgres' and not a and not i and z,'MANAGED_RUNTIME_ROLE_GRAPH')
        q.append('GRANT '+ident(role)+' TO '+ident(member)+' WITH INHERIT FALSE, SET TRUE;')
    return '\n'.join(q)+'\n'
def audit_target(c,source,roles,members,platform):
    need(platform_snapshot(c)==platform,'MANAGED_PLATFORM_DRIFT')
    target=p.catalog(c)
    for key in source:
        if source[key]!=target[key]:
            l={repr(x) for x in source[key]};r={repr(x) for x in target[key]}
            print('MANAGED_DIFF '+key+' missing='+repr(sorted(l-r)[:3])+' extra='+repr(sorted(r-l)[:3]),flush=True)
            raise RuntimeError('MANAGED_CATALOG_DIFF:'+key)
    flags=c.execute('SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication FROM pg_roles WHERE rolname=ANY(%s)',(sorted(CUSTOM),)).fetchall()
    need(set(flags)=={(r,False,False,False,False,False,False,False) for r in CUSTOM},'MANAGED_CUSTOM_FLAGS')
    graph=c.execute("""SELECT r.rolname,u.rolname,m.admin_option,m.inherit_option,m.set_option
      FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member
      WHERE r.rolname=ANY(%s) AND u.rolname<>'postgres'""",(sorted(CUSTOM),)).fetchall()
    need(set(graph)=={(r,u,a,i,z) for r,u,g,a,i,z in members if u!='postgres'},'MANAGED_CUSTOM_RUNTIME_GRAPH')
    need(c.execute("SELECT count(*) FROM pg_roles WHERE rolname=ANY(%s) AND has_database_privilege(rolname,current_database(),'CREATE')",(sorted(CUSTOM),)).fetchone()==(0,),'MANAGED_TEMP_DB_CREATE')
    tables=c.execute("""SELECT n.nspname,t.relname,t.relrowsecurity,t.relforcerowsecurity FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
     WHERE n.nspname=ANY(%s) AND t.relkind IN ('r','p')""",(p.SCHEMAS,)).fetchall()
    need(len(tables)==65 and all(r and f for _,_,r,f in tables),'MANAGED_FORCE_RLS')
    for schema,table,_,_ in tables:
        need(c.execute(sql.SQL('SELECT count(*) FROM {}').format(sql.Identifier(schema,table))).fetchone()==(0,),'MANAGED_SOURCE_ROWS')
    need(c.execute("""SELECT count(*) FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace CROSS JOIN unnest(ARRAY['anon','authenticated','service_role','authenticator']) r
    WHERE n.nspname=ANY(%s) AND t.relkind IN ('r','p') AND (has_table_privilege(r,t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r,t.oid,'SELECT,INSERT,UPDATE,REFERENCES'))""",(p.SCHEMAS,)).fetchone()==(0,),'MANAGED_EXTERNAL_TABLE_GRANT')
    return len(tables)
def load_review(root):
    # Fresh synthetic users and chat, actual restored auth/messenger RPCs.
    # These credentials and rows never enter the package.
    csrf='m'*32; hashes={x:hashlib.sha256(('managed-review-'+x).encode()).hexdigest() for x in 'ab'}
    password=secrets.token_urlsafe(32);authpw=secrets.token_urlsafe(32)
    with psycopg.connect(root) as c:
        for x in 'ab':
            org='ci-'+x;actor='ci-u'+x
            c.execute("INSERT INTO jw_dev.organizations VALUES(%s,%s,clock_timestamp()::text)",(org,'Company '+x))
            c.execute("INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES(%s,%s,%s,'synthetic-unused',%s,'admin',clock_timestamp()::text)",(actor,org,x+'@invalid.test',actor))
            c.execute("INSERT INTO jw_dev.messenger_companies(org_id,business_number) VALUES(%s,%s)",(org,'synthetic-'+x))
            c.execute("INSERT INTO naruv_hosted_identity_review.organizations VALUES(%s,%s)",(org,'Company '+x))
            c.execute("INSERT INTO naruv_hosted_identity_review.users VALUES(%s,%s,'admin',true,0)",(actor,org))
        for role,pw in [('jw_ci_trade',password),('naruv_v85_cutover_ci',authpw)]:
            c.execute(sql.SQL('ALTER ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(role),sql.Literal(pw)))
    td=make_conninfo(p.TARGET,user='jw_ci_trade',password=password);ad=make_conninfo(p.TARGET,user='naruv_v85_cutover_ci',password=authpw)
    with psycopg.connect(ad,autocommit=True) as a:
        a.execute('SET ROLE jw_auth_stage_v85')
        for x in 'ab':need(bool(a.execute('SELECT jw_dev.v85_auth_issue_session(%s,%s,%s,NULL,NULL)',('ci-u'+x,hashes[x],csrf)).fetchone()[0]),'MANAGED_AUTH_ISSUE')
    with psycopg.connect(td) as c:
        b.bind(c,hashes['a']);chat=c.execute("SELECT jw_dev.v90_start_chat('ci-b')").fetchone()[0]
    def worker(i):
        who='ab'[i%2];times=[]
        with psycopg.connect(td,autocommit=True) as c:
            c.execute("SET statement_timeout='15s'")
            for j in range(20):
                start=time.perf_counter()
                with c.transaction():
                    b.bind(c,hashes[who])
                    rid='managed-load-'+str(i)+'-'+str(j)
                    first=c.execute('SELECT * FROM jw_dev.v90_send_text(%s,%s,%s,NULL,NULL,NULL)',(chat,rid,rid)).fetchone()
                    need(not first[2],'MANAGED_LOAD_DUPLICATE')
                    replay=c.execute('SELECT * FROM jw_dev.v90_send_text(%s,%s,%s,NULL,NULL,NULL)',(chat,rid,rid)).fetchone()
                    need(replay==(first[0],first[1],True),'MANAGED_LOAD_REPLAY')
                times.append((time.perf_counter()-start)*1000)
        return times
    started=time.perf_counter()
    with ThreadPoolExecutor(max_workers=4) as pool:times=sorted(x for batch in pool.map(worker,range(4)) for x in batch)
    elapsed=time.perf_counter()-started
    with psycopg.connect(td) as c:
        b.bind(c,hashes['b'])
        rows=c.execute('SELECT message_id,message_cursor,body FROM jw_dev.v90_sync_messages(%s,0,100)',(chat,)).fetchall()
        need(len(rows)==80 and len({r[0] for r in rows})==len({r[1] for r in rows})==80,'MANAGED_LOAD_ROWS')
        need([r[1] for r in rows]==sorted(r[1] for r in rows),'MANAGED_LOAD_ORDER')
        p.s.expect(c,'42501','SELECT * FROM jw_dev.messenger_messages')
    result={'operations':80,'replays':80,'workers':4,'elapsed_s':round(elapsed,3),'p50_ms':round(times[39],3),'p95_ms':round(times[75],3),'max_ms':round(times[-1],3),'scope':'local disposable messenger two-RPC transactions; not hosted SLA'}
    print('MANAGED_RESTORED_LOAD_PASS '+json.dumps(result,sort_keys=True),flush=True)
    return result
def main():
    base.preflight()
    b.pin(HERE/'naruv_portable_schema_review.py','f3089604cebf122c5d9312e4293096d53c9910ed')
    fixture,_=base.setup()
    p.b.install(fixture);p.s.install(fixture);p.v.install(fixture);p.o.install(fixture)
    with psycopg.connect(fixture.root_dsn) as c:
        c.execute("SET LOCAL naruv.profile_ci='DISPOSABLE_ONLY'");c.execute(b.pin(base.ROOT/'db/review/naruv_hr_profile_ci.sql','835b0d6b6210d0e6151d701848f9276f6f5a7be2'))
    p.install_messenger(fixture)
    root,platform=target_platform()
    with psycopg.connect(fixture.root_dsn) as c:source=p.catalog(c);roles,members=p.graph(c)
    archive=p.execute_container(p.SOURCE_CONTAINER,'pg_dump','-U','postgres','-d','postgres','--schema-only','--format=custom',*['--schema='+n for n in p.SCHEMAS],stdout=subprocess.PIPE).stdout
    plain=p.execute_container(p.SOURCE_CONTAINER,'pg_restore','--no-owner','--no-acl','--file=-',input=archive,stdout=subprocess.PIPE).stdout.decode()
    toc=p.execute_container(p.SOURCE_CONTAINER,'pg_restore','--list',input=archive,stdout=subprocess.PIPE).stdout.decode()
    need(not any(x in toc for x in (' TABLE DATA ',' SEQUENCE SET ',' BLOB DATA ',' LARGE OBJECT ')),'MANAGED_DATA_EXPORT')
    # psql runs one transaction: roles, DDL, owner and ACL application.
    package=role_commands(members)+plain+'\n'+owner_commands(source)
    p.execute_container(p.TARGET_CONTAINER,'psql','-X','-U','postgres','-d','postgres','--single-transaction','-v','ON_ERROR_STOP=1','-c',"SET naruv.managed_rehearsal='DISPOSABLE_CI_ONLY'",'-f','-',input=package.encode(),stdout=subprocess.PIPE)
    with psycopg.connect(p.TARGET) as c:tables=audit_target(c,source,roles,members,platform)
    print('MANAGED_PACKAGE_RESTORE_PASS schemas=16 tables='+str(tables)+' custom_roles='+str(len(CUSTOM))+' catalog_sections='+str(len(source))+' platform_unchanged=true admin_superuser=false',flush=True)
    load=load_review(root)
    dest=Path(os.environ['NARUV_PORTABLE_OUTPUT']).resolve()
    need(dest.parent==Path(os.environ['RUNNER_TEMP']).resolve() and not dest.exists(),'MANAGED_OUTPUT')
    dest.mkdir(mode=0o700)
    (dest/'managed-review-only.sql').write_text(package)
    (dest/'schema-only.toc.txt').write_text(toc)
    manifest={'kind':'LOCAL_MANAGED_ROLE_REHEARSAL_ONLY','source':base.SOURCE,'review':os.environ['EXPECTED_SHA'],'hosted_install':False,'production_authorized':False,
       'tables':tables,'schemas':p.SCHEMAS,'custom_roles':sorted(CUSTOM),'catalog_sections':len(source),'load':load,
       'sha256':{x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in sorted(dest.iterdir())}}
    (dest/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    print('MANAGED_PORTABLE_REVIEW_PASS production_authorized=false hosted_install=false gate5=BLOCKED',flush=True)
if __name__=='__main__':main()
