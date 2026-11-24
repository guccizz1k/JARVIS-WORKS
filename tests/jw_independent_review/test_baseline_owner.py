import base64, json, os
from types import SimpleNamespace
import pytest
from scripts import jw_historical_baseline_owner_v223 as o
from scripts import jw_historical_baseline_v223 as b
from scripts import jw_independent_equivalence_v223 as eq
from scripts import jw_independent_catalog_v223 as cat


def test_pipe_keys():
    a,w=os.pipe();c,v=os.pipe()
    try:
        os.write(w,base64.urlsafe_b64encode(b'a'*32));os.close(w);w=None
        os.write(v,base64.urlsafe_b64encode(b'b'*32));os.close(v);v=None
        assert o.keys_from_pipes(a,c)==(b'a'*32,b'b'*32)
    finally:
        for fd in (a,w,c,v):
            if fd is not None:os.close(fd)


def test_pipe_alias():
    a,w=os.pipe();c=os.dup(a)
    try:
        with pytest.raises(eq.Blocked,match='PIPE_ALIAS'):o.keys_from_pipes(a,c)
    finally:
        for fd in (a,w,c):os.close(fd)


def test_file_mode(tmp_path):
    f=tmp_path/'input';f.write_bytes(b'hello');f.chmod(0o600);assert o.private_read(f)==b'hello';f.chmod(0o644)
    with pytest.raises(eq.Blocked):o.private_read(f)


def test_candidate_no_overwrite(tmp_path):
    tmp_path.chmod(0o700);f=tmp_path/'out';o.write_candidate(f,b'hello');assert f.read_bytes()==b'hello'
    with pytest.raises(FileExistsError):o.write_candidate(f,b'changed')
    assert f.read_bytes()==b'hello'


def test_candidate_symlink(tmp_path):
    tmp_path.chmod(0o700);f=tmp_path/'out';t=tmp_path/'target';t.write_bytes(b'unchanged');f.symlink_to(t)
    with pytest.raises(OSError):o.write_candidate(f,b'changed')
    assert t.read_bytes()==b'unchanged'


def test_env_sanitize(monkeypatch):
    monkeypatch.setattr(os,'environ',{'CODESPACES':'true','JW_OWNER_BASELINE_ACK':o.ACK,'PATH':'/usr/bin','GH_TOKEN':'synthetic','JW_PG_BACKUP_KEY':'synthetic-secret','DATABASE_URL':'synthetic','HTTPS_PROXY':'synthetic'})
    o.sanitize_environment();assert set(os.environ)<=o.ALLOW_ENV|{'GH_PROMPT_DISABLED','GH_NO_UPDATE_NOTIFIER','GIT_TERMINAL_PROMPT'}
    assert not any(k in os.environ for k in ('JW_PG_BACKUP_KEY','DATABASE_URL','HTTPS_PROXY'))


@pytest.mark.parametrize('env',[{}, {'CODESPACES':'false','JW_OWNER_BASELINE_ACK':o.ACK},{'CODESPACES':'true','JW_OWNER_BASELINE_ACK':o.ACK,'DOCKER_HOST':'tcp://example'},{'CODESPACES':'true','JW_OWNER_BASELINE_ACK':o.ACK,'DOCKER_TLS_VERIFY':'1'}])
def test_env_reject(monkeypatch,env):
    monkeypatch.setattr(os,'environ',env)
    with pytest.raises(eq.Blocked):o.sanitize_environment()


@pytest.fixture
def docker(monkeypatch):
    calls=[];state={'container':'f'*64,'token':None,'name':None,'cleanup_fail':False,'label_wrong':False,'version':b'postgres (PostgreSQL) 17.8','wrong_callback':False}
    def cmd(args,**kw):
        calls.append(args)
        if args[0]=='context':out=b'unix:///var/run/docker.sock'
        elif args[0]=='run':
            state['token']=args[args.index('--label')+1].split('=')[1];state['name']=args[args.index('--name')+1];out=state['container'].encode()
        elif args[0]=='inspect':out=(state['container']+' '+('x' if state['label_wrong'] else state['token'])).encode()
        elif args[0]=='rm':return SimpleNamespace(returncode=int(state['cleanup_fail']),stdout=b'')
        else:out=b'ok'
        return SimpleNamespace(returncode=0,stdout=out)
    def restore(c,p,i,catalog_probe):
        catalog_probe(c,'bad' if state['wrong_callback'] else 'jw_p1_offline_'+str(i));return 'test'
    off=SimpleNamespace(IMAGE='postgres:17',_docker=cmd,_final_pg17_ready=lambda c:True,_exec=lambda *a,**k:SimpleNamespace(returncode=0,stdout=state['version']),_restore_one=restore)
    monkeypatch.setattr(cat,'probe',lambda *a: 'catalog');return o.RestoreAdapter(off),calls,state


def test_real_adapter_contract(docker):
    a,c,s=docker;assert a.restore(bytearray(b'PGDMP'),0)==('test','catalog');run=next(x for x in c if x[0]=='run');assert run[run.index('--network')+1]=='none' and '--publish-all=false' in run and '--tmpfs' in run
    assert a.cleanup()=='PASS' and c[-1]==['rm','-f',s['container']]


def test_no_container_cleanup(docker):
    a,c,_=docker;assert a.cleanup()=='PASS' and not c


def test_cleanup_label_mismatch(docker):
    a,c,s=docker;a.restore(bytearray(b'PGDMP'),0);s['label_wrong']=True;assert a.cleanup()=='BLOCKED' and not any(x[0]=='rm' for x in c)


def test_cleanup_failure(docker):
    a,c,s=docker;a.restore(bytearray(b'PGDMP'),0);s['cleanup_fail']=True;assert a.cleanup()=='BLOCKED'


def test_pg_version_mismatch(docker):
    a,c,s=docker;s['version']=b'postgres (PostgreSQL) 16.9'
    with pytest.raises(eq.Blocked,match='PG17_VERSION'):a.restore(bytearray(b'PGDMP'),0)
    assert a.cleanup()=='PASS'


def test_wrong_callback(docker):
    a,c,s=docker;s['wrong_callback']=True
    with pytest.raises(eq.Blocked,match='CALLBACK_TARGET'):a.restore(bytearray(b'PGDMP'),0)
    assert a.cleanup()=='PASS'


def test_tree_adapter(monkeypatch):
    rows=[{'type':'blob','mode':'100644','sha':f'{i:040x}','size':100,'path':f'x/{i}.jwpgbk'} for i in range(11)]
    def api(endpoint,*a):return {'sha':'a'*40,'tree':{'sha':'b'*40}} if '/commits/' in endpoint else {'sha':'b'*40,'truncated':False,'tree':rows}
    monkeypatch.setattr(o,'api',api);assert len(o.tree('a'*40))==11
    rows[0]['mode']='120000'
    with pytest.raises(eq.Blocked):o.tree('a'*40)


def test_fetch_adapter(monkeypatch):
    raw=b'X'*100;blob=b.git_blob(raw);digest=b.sha(raw);d={'sha':blob,'size':len(raw),'encoding':'base64','content':base64.b64encode(raw).decode()}
    monkeypatch.setattr(o,'api',lambda *a:d);assert o.fetch(blob,digest)==raw
    d['content']=base64.b64encode(b'Y'*100).decode()
    with pytest.raises(eq.Blocked,match='CIPHER_HASH'):o.fetch(blob,digest)
