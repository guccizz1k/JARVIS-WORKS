"""Real synthetic PG17 mutation/reversal test, explicitly enabled on isolated CI."""
import os
import re
import secrets
import subprocess
import time
from scripts import jw_pg17_role_graph_v223 as graph


def test_global_role_graph_pg17():
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('GITHUB_REPOSITORY') == 'guccizz1k/JARVIS-WORKS'
    assert os.environ.get('JW_ROLE_GRAPH_SYNTHETIC_CI') == '1'
    assert not os.environ.get('DOCKER_TLS_VERIFY')
    assert not os.environ.get('DOCKER_HOST') or os.environ['DOCKER_HOST'].startswith('unix://')
    env = {k: os.environ[k] for k in ('PATH','HOME','DOCKER_CONFIG','DOCKER_HOST','DOCKER_CONTEXT','XDG_RUNTIME_DIR') if k in os.environ}
    def command(*args, check=True):
        p = subprocess.run(['docker',*args],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
        if check and p.returncode != 0:
            raise AssertionError('SYNTHETIC_DOCKER_COMMAND_FAILED')
        return p
    assert command('context','inspect','--format','{{.Endpoints.docker.Host}}').stdout.strip().startswith(b'unix://')
    command('image','inspect','postgres:17')
    name='jw-role-graph-'+secrets.token_hex(12)
    p=command('run','--rm','--pull','never','-d','--name',name,'--network','none','--tmpfs','/var/lib/postgresql/data:rw,size=1073741824','--tmpfs','/var/run/postgresql:rw,size=16777216','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17')
    cid=p.stdout.strip().decode('ascii')
    assert re.fullmatch('[0-9a-f]{64}',cid)
    try:
        for _ in range(60):
            if command('exec',cid,'sh','-c','test "$(cat /proc/1/comm)" = postgres && pg_isready -q -U postgres',check=False).returncode==0:
                break
            time.sleep(.5)
        else:
            raise AssertionError('PG17_NOT_READY')
        assert b'PostgreSQL) 17.' in command('exec',cid,'postgres','--version').stdout
        def sql(s):
            return command('exec',cid,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres','-c',s).stdout.strip()
        def checkpoint():
            return graph.canonical(graph.parse(sql(graph.SQL)))
        def matches(a,b):
            return graph.compare(a,b,expected_reference_pin=graph.pin(a))
        sql('CREATE ROLE jw_rg_parent NOLOGIN; CREATE ROLE jw_rg_member NOLOGIN; CREATE ROLE jw_rg_grantor NOLOGIN; GRANT jw_rg_parent TO jw_rg_grantor WITH ADMIN TRUE; GRANT jw_rg_parent TO jw_rg_member WITH ADMIN FALSE;')
        sql('CREATE DATABASE jw_rg_other')
        base=checkpoint()
        assert matches(base,checkpoint())['role_graph_checkpoint'].startswith('PASS_')
        changes=[
          ('roles','ALTER ROLE jw_rg_member BYPASSRLS','ALTER ROLE jw_rg_member NOBYPASSRLS'),
          ('memberships','GRANT jw_rg_parent TO jw_rg_member WITH ADMIN TRUE','GRANT jw_rg_parent TO jw_rg_member WITH ADMIN FALSE'),
          ('memberships','GRANT jw_rg_parent TO jw_rg_member WITH INHERIT FALSE','GRANT jw_rg_parent TO jw_rg_member WITH INHERIT TRUE'),
          ('memberships','GRANT jw_rg_parent TO jw_rg_member WITH SET FALSE','GRANT jw_rg_parent TO jw_rg_member WITH SET TRUE'),
          ('memberships','GRANT jw_rg_parent TO jw_rg_member GRANTED BY jw_rg_grantor','REVOKE jw_rg_parent FROM jw_rg_member GRANTED BY jw_rg_grantor'),
          ('all_database_role_settings',"ALTER ROLE jw_rg_member IN DATABASE jw_rg_other SET statement_timeout TO '7s'",'ALTER ROLE jw_rg_member IN DATABASE jw_rg_other RESET statement_timeout'),
          ('all_database_role_settings',"ALTER DATABASE jw_rg_other SET lock_timeout TO '3s'",'ALTER DATABASE jw_rg_other RESET lock_timeout'),
        ]
        for section,forward,reverse in changes:
            sql(forward)
            assert matches(base,checkpoint())['blocker']=='MISMATCH_'+section.upper()
            sql(reverse)
            assert matches(base,checkpoint())['role_graph_checkpoint'].startswith('PASS_')
        print('PASS_SYNTHETIC_PG17_GLOBAL_ROLE_GRAPH_7_MUTATIONS_AND_REVERSALS')
    finally:
        command('rm','-f',cid)
