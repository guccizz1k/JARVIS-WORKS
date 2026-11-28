import pytest
from qa_probe import assess
OK=(0,200,0,b'{"status":"ok","version":"2.2.0-candidate"}','')
AUTH=(0,401,0,b'', 'WWW-Authenticate: Basic realm="JARVIS-WORKS isolated review"\r\n')
TIMEOUT=(28,0,0,b'','')

def run(seq):
    seq=iter(seq); t=[0]; paths=[]
    def fetch(path, timeout):
        paths.append(path); t[0]+=min(timeout,1); return next(seq)
    def sleep(s):t[0]+=s
    r=assess(fetch,lambda:t[0],sleep)
    assert r['release_authorized'] is False and r['database_verified'] is False
    return r,paths

def test_cold_start_recovery():
    r,p=run([TIMEOUT,TIMEOUT,OK,AUTH]);assert r['status'].endswith('_PASS');assert p==['/api/health']*3+['/']

def test_warm():assert run([OK,AUTH])[0]['status'].endswith('_PASS')
@pytest.mark.parametrize('x', [(60,0,1,b'',''),(127,0,-1,b'',''),(0,200,1,b'','')])
def test_hard_transport(x):assert run([x])[0]['status']=='BLOCKED_TRANSPORT'
@pytest.mark.parametrize('body',[b'html',b'{}',b'{"status":"ok","version":"wrong"}',b'{"status":"ok","version":"2.2.0-candidate","extra":1}'])
def test_health_payload(body):assert run([(0,200,0,body,'')])[0]['status']=='BLOCKED_HEALTH_PAYLOAD'
@pytest.mark.parametrize('status',[301,302,401,403,404,429,500])
def test_nontransient(status):assert run([(0,status,0,b'','')])[0]['status']=='BLOCKED_HEALTH_HTTP'
@pytest.mark.parametrize('status',[502,503,504])
def test_transient(status):assert run([(0,status,0,b'',''),OK,AUTH])[0]['status'].endswith('_PASS')
@pytest.mark.parametrize('x',[(0,200,0,b'',''),(0,401,0,b'',''),(0,403,0,b'',''),(0,401,0,b'','WWW-Authenticate: Bearer'),(0,401,0,b'','WWW-Authenticate: Basic realm="wrong"')])
def test_barrier_fail_closed(x):assert run([OK,x])[0]['status']=='BLOCKED_AUTH_BARRIER'
def test_barrier_timeout():assert run([OK,TIMEOUT])[0]['status']=='BLOCKED_AUTH_TRANSPORT'
def test_bounded_attempts():assert run([TIMEOUT]*4)[0]['status']=='BLOCKED_STARTUP_OR_TRANSPORT'
def test_deadline():
    t=[0]
    def fetch(path,timeout):t[0]+=timeout;return TIMEOUT
    r=assess(fetch,lambda:t[0],lambda n:t.__setitem__(0,t[0]+n),budget=10)
    assert r['status']=='BLOCKED_STARTUP_OR_TRANSPORT';assert t[0]<=10
@pytest.mark.parametrize('n',[0,121,True,10.5])
def test_invalid_budget(n):
    with pytest.raises(ValueError):assess(budget=n)
