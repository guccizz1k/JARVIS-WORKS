"""Synthetic PG17 authorization catalog + effective RLS smoke.
No external data, keys, network, mounts or source DB. A separate CI runner is
required if no local Docker/PG17 exists. Only pass actual executed assertions.
"""
from pathlib import Path
import sys, json, os, re, secrets, shutil, time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from live_checks.pg17_catalog_smoke import command, require
from scripts import jw_independent_security_v223 as auth


def tenant_query(role, query):
    require(role in ('jw_a','jw_b','jw_owner'),'FIXTURE_ROLE_INVALID')
    # SET ROLE alone would leave session_user=postgres, so SET ROLE escalation
    # could succeed because of the original session user's superuser authority.
    return 'BEGIN; SET SESSION AUTHORIZATION '+role+'; '+query+'; ROLLBACK;'


def expected_denial(p, code=b'42501'):
    # SQLSTATE in a verbose PostgreSQL error, never generic nonzero status.
    return p.returncode!=0 and re.search(rb'(?m)^ERROR:\s+'+re.escape(code)+rb':',p.stderr) is not None


def main():
    result={'status':'BLOCKED','authz_mutations_passed':0,'rls_runtime_assertions_passed':0,'cleanup':'NOT_RUN','overall':'BLOCKED'}
    cid=None; name=None; created=False
    try:
        require(shutil.which('docker') is not None,'DOCKER_CLI_UNAVAILABLE')
        require(not os.environ.get('DOCKER_HOST') or os.environ['DOCKER_HOST'].startswith('unix://'),'REMOTE_DOCKER_BLOCKED')
        require(not os.environ.get('DOCKER_TLS_VERIFY'),'REMOTE_DOCKER_BLOCKED')
        p=command(['context','inspect','--format','{{.Endpoints.docker.Host}}'])
        require(p.returncode==0 and p.stdout.strip().startswith(b'unix://'),'NONLOCAL_DOCKER_BLOCKED')
        require(command(['image','inspect','postgres:17']).returncode==0,'PG17_IMAGE_NOT_CACHED')
        name='jw-authz-smoke-'+secrets.token_hex(12)
        p=command(['run','--rm','--pull','never','-d','--name',name,'--network','none','--publish-all=false','--tmpfs','/var/lib/postgresql/data:rw,size=1073741824','--tmpfs','/var/run/postgresql:rw,size=16777216','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17'])
        created=p.returncode==0
        require(created and re.fullmatch(rb'[a-f0-9]{64}',p.stdout.strip()),'CONTAINER_START_FAILED')
        cid=p.stdout.strip().decode('ascii')
        for _ in range(60):
            if command(['exec',cid,'sh','-c','test "$(cat /proc/1/comm)" = postgres && pg_isready -q -U postgres'],timeout=5).returncode==0:break
            time.sleep(.5)
        else:raise RuntimeError('PG17_NOT_READY')
        p=command(['exec',cid,'postgres','--version']);require(p.returncode==0 and re.search(rb'PostgreSQL\) 17\.',p.stdout),'PG17_VERSION_MISMATCH')
        db='jw_p1_offline_0'; require(command(['exec',cid,'createdb','-U','postgres',db]).returncode==0,'FIXTURE_DB_CREATE_FAILED')
        def exec_fn(c,args,timeout=45):
            require(c==cid,'CONTAINER_ID_MISMATCH');return command(['exec',cid,*args],timeout=timeout)
        def sql(query):
            return exec_fn(cid,['psql','-X','-qAt','-U','postgres','-d',db,'-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-c',query])
        def ok(query):
            p=sql(query);require(p.returncode==0,'FIXTURE_SQL_FAILED');return p.stdout.strip()
        ok('CREATE SCHEMA jw_dev; CREATE ROLE jw_a NOLOGIN; CREATE ROLE jw_b NOLOGIN; CREATE ROLE jw_group NOLOGIN; CREATE ROLE jw_owner NOLOGIN; '+''.join(f'CREATE TABLE jw_dev.t{i:02d}(id integer PRIMARY KEY, tenant integer NOT NULL);' for i in range(65))+'''INSERT INTO jw_dev.t00 VALUES(1,1),(2,2);
        ALTER TABLE jw_dev.t00 OWNER TO jw_owner;
        GRANT USAGE ON SCHEMA jw_dev TO jw_a,jw_b,jw_owner;
        GRANT SELECT,INSERT,UPDATE,DELETE ON jw_dev.t00 TO jw_a,jw_b;
        ALTER TABLE jw_dev.t00 ENABLE ROW LEVEL SECURITY;
        ALTER TABLE jw_dev.t00 FORCE ROW LEVEL SECURITY;
        CREATE POLICY pa ON jw_dev.t00 TO jw_a USING (tenant=1) WITH CHECK (tenant=1);
        CREATE POLICY pb ON jw_dev.t00 TO jw_b USING (tenant=2) WITH CHECK (tenant=2);
        CREATE POLICY po ON jw_dev.t00 TO jw_owner USING (tenant=1) WITH CHECK (tenant=1);''')
        def same(role,query,expected):
            p=sql(tenant_query(role,query))
            require(p.returncode==0 and p.stdout.strip()==expected,'RLS_RESULT_MISMATCH')
            result['rls_runtime_assertions_passed']+=1
        def denied(role,query,code=b'42501'):
            p=sql(tenant_query(role,query))
            require(expected_denial(p,code),'RLS_EXPECTED_SQLSTATE_MISMATCH')
            result['rls_runtime_assertions_passed']+=1
        same('jw_a','SELECT session_user::text || chr(58) || current_user::text',b'jw_a:jw_a')
        same('jw_b','SELECT session_user::text || chr(58) || current_user::text',b'jw_b:jw_b')
        same('jw_a','SELECT string_agg(id::text,\',\' ORDER BY id) FROM jw_dev.t00',b'1')
        same('jw_b','SELECT string_agg(id::text,\',\' ORDER BY id) FROM jw_dev.t00',b'2')
        same('jw_a','SELECT count(*) FROM jw_dev.t00 WHERE id=2',b'0')
        same('jw_b','SELECT count(*) FROM jw_dev.t00 WHERE id=1',b'0')
        same('jw_a','WITH x AS (UPDATE jw_dev.t00 SET tenant=1 WHERE id=2 RETURNING 1) SELECT count(*) FROM x',b'0')
        same('jw_b','WITH x AS (DELETE FROM jw_dev.t00 WHERE id=1 RETURNING 1) SELECT count(*) FROM x',b'0')
        same('jw_a','WITH x AS (INSERT INTO jw_dev.t00 VALUES(3,1) RETURNING 1) SELECT count(*) FROM x',b'1')
        denied('jw_a','INSERT INTO jw_dev.t00 VALUES(3,2)')
        denied('jw_b','UPDATE jw_dev.t00 SET tenant=1 WHERE id=2')
        denied('jw_a','SET LOCAL ROLE jw_b')
        same('jw_owner','SELECT count(*) FROM jw_dev.t00',b'1')
        ok('ALTER TABLE jw_dev.t00 NO FORCE ROW LEVEL SECURITY;')
        same('jw_owner','SELECT count(*) FROM jw_dev.t00',b'2') # detects owner bypass
        ok('ALTER TABLE jw_dev.t00 FORCE ROW LEVEL SECURITY;')
        ok('ALTER ROLE jw_a BYPASSRLS;')
        same('jw_a','SELECT count(*) FROM jw_dev.t00',b'2') # detects role bypass
        ok('ALTER ROLE jw_a NOBYPASSRLS;')
        same('jw_a','SELECT count(*) FROM jw_dev.t00',b'1')
        require(auth.probe(exec_fn,cid,db)==auth.probe(exec_fn,cid,db),'AUTHZ_UNSTABLE')
        mutations=[('owners','ALTER TABLE jw_dev.t01 OWNER TO jw_owner;'),('object_acl','GRANT SELECT ON jw_dev.t01 TO jw_a;'),('column_acl','GRANT SELECT(id) ON jw_dev.t02 TO jw_b;'),('default_acl','ALTER DEFAULT PRIVILEGES IN SCHEMA jw_dev GRANT SELECT ON TABLES TO jw_a;'),('role_attributes','ALTER ROLE jw_b BYPASSRLS;'),('role_memberships','GRANT jw_group TO jw_a WITH ADMIN OPTION;'),('role_settings','ALTER ROLE jw_a SET statement_timeout TO \'5s\';'),('database_acl','REVOKE CONNECT ON DATABASE jw_p1_offline_0 FROM PUBLIC;')]
        for section,query in mutations:
            before=auth.probe(exec_fn,cid,db);ok(query);after=auth.probe(exec_fn,cid,db)
            require(before[section]!=after[section],'AUTHZ_MUTATION_NOT_DETECTED');result['authz_mutations_passed']+=1
        result['status']='PASS_SYNTHETIC_PG17_AUTHZ_AND_RLS'
    except Exception as exc:
        msg=str(exc);result['blocker']=msg if re.fullmatch('[A-Z0-9_]{3,80}',msg) else 'PG17_AUTHZ_FAIL_CLOSED'
    finally:
        if created:
            try:result['cleanup']='PASS' if command(['rm','-f',cid or name]).returncode==0 else 'BLOCKED'
            except Exception:result['cleanup']='BLOCKED'
            if result['cleanup']!='PASS':result['status']='BLOCKED_CLEANUP'
    print(json.dumps(result,sort_keys=True));return 0 if result['status']=='PASS_SYNTHETIC_PG17_AUTHZ_AND_RLS' and result['cleanup']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
