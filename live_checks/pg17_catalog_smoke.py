"""Real PG17 catalog mutation smoke; synthetic only, no provider or source DB.
Run separately from pytest. Requires an existing cached postgres:17 image and
local Unix Docker daemon. Never pulls, mounts host data, exposes ports or uses
source keys. Exit 1 for blocked/fail. No raw database error/metadata printed.
"""
from pathlib import Path
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts import jw_independent_catalog_v223 as cat

def command(args,timeout=45):
    env={k:os.environ[k] for k in ('PATH','HOME','DOCKER_CONFIG','DOCKER_HOST','DOCKER_CONTEXT','XDG_RUNTIME_DIR') if k in os.environ}
    return subprocess.run(['docker',*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=timeout,check=False)

def require(ok,reason):
    if not ok: raise RuntimeError(reason)

def main():
    result={'status':'BLOCKED','catalog_mutations_passed':0,'cleanup':'NOT_RUN','overall':'BLOCKED'}
    cid=None; name=None; created=False
    try:
        require(shutil.which('docker') is not None,'DOCKER_CLI_UNAVAILABLE')
        require(not os.environ.get('DOCKER_HOST') or os.environ['DOCKER_HOST'].startswith('unix://'),'REMOTE_DOCKER_BLOCKED')
        require(not os.environ.get('DOCKER_TLS_VERIFY'),'REMOTE_DOCKER_BLOCKED')
        p=command(['context','inspect','--format','{{.Endpoints.docker.Host}}'])
        require(p.returncode==0 and p.stdout.strip().startswith(b'unix://'),'NONLOCAL_DOCKER_BLOCKED')
        require(command(['image','inspect','postgres:17']).returncode==0,'PG17_IMAGE_NOT_CACHED')
        name='jw-catalog-smoke-'+secrets.token_hex(12)
        p=command(['run','--rm','--pull','never','-d','--name',name,'--network','none','--publish-all=false','--tmpfs','/var/lib/postgresql/data:rw,size=1073741824','--tmpfs','/var/run/postgresql:rw,size=16777216','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17'])
        created=p.returncode==0
        require(created and re.fullmatch(rb'[a-f0-9]{64}',p.stdout.strip()) is not None,'CONTAINER_START_FAILED')
        cid=p.stdout.strip().decode('ascii')
        for _ in range(60):
            # TCP disabled by network=none; explicit socket and final postmaster
            # readiness check after the entrypoint temporary init server exits.
            p=command(['exec',cid,'sh','-c','test "$(cat /proc/1/comm)" = postgres && pg_isready -q -U postgres'],timeout=5)
            if p.returncode==0:break
            time.sleep(.5)
        else:raise RuntimeError('PG17_NOT_READY')
        p=command(['exec',cid,'postgres','--version']);require(p.returncode==0 and re.search(rb'PostgreSQL\) 17\.',p.stdout),'PG17_VERSION_MISMATCH')
        db='jw_p1_offline_0'
        require(command(['exec',cid,'createdb','-U','postgres',db]).returncode==0,'FIXTURE_DB_CREATE_FAILED')
        def exec_fn(c,args,timeout=45):
            require(c==cid,'CONTAINER_ID_MISMATCH');return command(['exec',cid,*args],timeout=timeout)
        def sql(query):
            p=exec_fn(cid,['psql','-X','-qAt','-U','postgres','-d',db,'-v','ON_ERROR_STOP=1','-c',query]);require(p.returncode==0,'FIXTURE_SQL_FAILED')
        sql('CREATE SCHEMA jw_dev; CREATE ROLE jw_catalog_tenant NOLOGIN; '+''.join(f'CREATE TABLE jw_dev.t{i:02d}(id integer PRIMARY KEY, tenant integer NOT NULL);' for i in range(65))+' ALTER TABLE jw_dev.t00 ENABLE ROW LEVEL SECURITY; CREATE POLICY tenant_scope ON jw_dev.t00 TO jw_catalog_tenant USING (tenant=1) WITH CHECK (tenant=1);')
        baseline=cat.probe(exec_fn,cid,db);require(baseline['rls_flags'][0]==65 and baseline['policies'][0]==1,'BASELINE_SCOPE_INVALID')
        mutations=[('rls_flags','ALTER TABLE jw_dev.t00 FORCE ROW LEVEL SECURITY;'),('policies','ALTER POLICY tenant_scope ON jw_dev.t00 USING (tenant=2);'),('columns','ALTER TABLE jw_dev.t01 ADD COLUMN note text;'),('constraints','ALTER TABLE jw_dev.t01 ADD CONSTRAINT nonnegative CHECK (tenant>=0);'),('indexes','CREATE INDEX jw_catalog_idx ON jw_dev.t01(tenant);'),('views','CREATE VIEW jw_dev.v1 AS SELECT id FROM jw_dev.t01;'),('sequences','CREATE SEQUENCE jw_dev.s1;'),('routines','CREATE FUNCTION jw_dev.f1() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$;'),('triggers','CREATE FUNCTION jw_dev.tr1() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$; CREATE TRIGGER tr1 BEFORE INSERT ON jw_dev.t01 FOR EACH ROW EXECUTE FUNCTION jw_dev.tr1();'),('relations','ALTER TABLE jw_dev.t02 SET (fillfactor=70);')]
        for section,query in mutations:
            before=cat.probe(exec_fn,cid,db);sql(query);after=cat.probe(exec_fn,cid,db)
            require(before[section]!=after[section],'CATALOG_MUTATION_NOT_DETECTED');result['catalog_mutations_passed']+=1
        require(cat.probe(exec_fn,cid,db)==cat.probe(exec_fn,cid,db),'CATALOG_UNSTABLE')
        result['status']='PASS_SYNTHETIC_PG17_CATALOG_MUTATIONS'
    except Exception as exc:
        msg=str(exc);result['blocker']=msg if re.fullmatch('[A-Z0-9_]{3,80}',msg) else 'PG17_SMOKE_FAIL_CLOSED'
    finally:
        if created:
            try:result['cleanup']='PASS' if command(['rm','-f',cid or name]).returncode==0 else 'BLOCKED'
            except Exception:result['cleanup']='BLOCKED'
            if result['cleanup']!='PASS':result['status']='BLOCKED_CLEANUP'
    print(json.dumps(result,sort_keys=True));return 0 if result['status']=='PASS_SYNTHETIC_PG17_CATALOG_MUTATIONS' and result['cleanup']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
