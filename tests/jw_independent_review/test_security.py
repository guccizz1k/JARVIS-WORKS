import copy
import hashlib
import json
from types import SimpleNamespace
import pytest
from scripts import jw_independent_security_v223 as s
from scripts import jw_independent_equivalence_v223 as eq

def hx(i,n=64):return f'{i:0{n}x}'
def sections():return {k:[65 if k in ('owners','object_acl','column_acl') else 1,hx(i+1)] for i,k in enumerate(s.SECTIONS)}
def fixture():
    pairs=[(hx(i+1,40),hx(i+1)) for i in range(11)]
    scope=eq.owner_scope(b for b,c in pairs); vault=hx(111,40)
    doc={'format':s.FORMAT,'algorithm':s.ALGORITHM,'vault':vault,'scope':scope,'archives':[{'blob':b,'cipher':c,'sections':sections()} for b,c in pairs]}
    return doc,pairs,vault,scope

def load(doc,pairs,vault,scope,pin=None):
    raw=eq.canonical(doc)
    return s.load_reference(raw,expected_sha=pin or hashlib.sha256(raw).hexdigest(),vault=vault,scope=scope,pairs=pairs)
def test_full_and_cleanup():
    doc,pairs,vault,scope=fixture(); r=s.AuthorizationComparison(load(doc,pairs,vault,scope))
    for b,c in pairs:r.compare(b,c,sections())
    assert r.receipt(cleanup='PASS')['scoped_authorization_checkpoint_comparison']=='PASS_11_SCOPED_AUTHZ_CHECKPOINTS'
    assert r.receipt(cleanup='BLOCKED')['scoped_authorization_checkpoint_comparison']=='BLOCKED'
    assert r.receipt(cleanup='PASS')['overall']=='BLOCKED'
    assert r.receipt(cleanup='PASS')['original_owner_acl_equivalence']=='NOT_ATTESTED'

@pytest.mark.parametrize('section',s.SECTIONS)
@pytest.mark.parametrize('field',[0,1])
def test_every_mutation(section,field):
    doc,pairs,vault,scope=fixture();r=s.AuthorizationComparison(load(doc,pairs,vault,scope)); b,c=pairs[0]
    obs=sections();obs[section][field]=obs[section][field]+1 if field==0 else hx(999)
    with pytest.raises(eq.Blocked,match='AUTHZ_'+section.upper()+'_MISMATCH'):r.compare(b,c,obs)
    with pytest.raises(eq.Blocked,match='AUTHZ_REPLAY_OR_FAILED'):r.compare(b,c,sections())
    assert r.receipt(cleanup='PASS')['scoped_authorization_checkpoint_comparison']=='BLOCKED'

@pytest.mark.parametrize('count',[0,1,10])
def test_partial(count):
    doc,pairs,vault,scope=fixture();r=s.AuthorizationComparison(load(doc,pairs,vault,scope))
    for b,c in pairs[:count]:r.compare(b,c,sections())
    assert r.receipt(cleanup='PASS')['scoped_authorization_checkpoint_comparison']=='BLOCKED'

@pytest.mark.parametrize('change',['pin','vault','scope','format','algorithm','short','duplicate','substitute','cipher','extra','providerduplicate','providerwrong','providercipherduplicate'])
def test_invalid_reference(change):
    doc,pairs,vault,scope=fixture();pin=None
    if change=='pin':pin=hx(999)
    elif change in ('vault','scope','format','algorithm'):doc[change]='wrong'
    elif change=='short':doc['archives'].pop()
    elif change=='duplicate':doc['archives'][-1]=copy.deepcopy(doc['archives'][0])
    elif change=='substitute':doc['archives'][-1]['blob']=hx(999,40)
    elif change=='cipher':doc['archives'][-1]['cipher']=hx(999)
    elif change=='extra':doc['extra']=True
    elif change=='providerduplicate':pairs[-1]=pairs[0]
    elif change=='providerwrong':pairs[-1]=(hx(999,40),hx(999))
    elif change=='providercipherduplicate':pairs[-1]=(pairs[-1][0],pairs[0][1])
    with pytest.raises(eq.Blocked):load(doc,pairs,vault,scope,pin)

@pytest.mark.parametrize('bad',[True,-1,100001,'65',None,1.2])
def test_count_validation(bad):
    v=sections();v['owners'][0]=bad
    with pytest.raises(eq.Blocked):s.parse_sections(v)
@pytest.mark.parametrize('bad',[None,'a'*63,'A'*64,True,'z'*64])
def test_digest_validation(bad):
    v=sections();v['owners'][1]=bad
    with pytest.raises(eq.Blocked):s.parse_sections(v)

@pytest.mark.parametrize('name',['owners','column_acl','object_acl','role_attributes','database_acl'])
def test_empty_mandatory_scope(name):
    v=sections();v[name][0]=0
    with pytest.raises(eq.Blocked):s.parse_sections(v)

def test_probe_contract():
    calls=[]
    def run(c,args,timeout):
        calls.append((c,args,timeout));return SimpleNamespace(returncode=0,stdout=eq.canonical(sections()))
    assert s.probe(run,hx(10),'jw_p1_offline_10')==s.parse_sections(sections())
    assert len(calls)==1 and calls[0][1][-1]==s.SQL and calls[0][2]==50
    assert 'READ ONLY' in s.SQL and 'rolpassword' not in s.SQL and 'pg_authid' not in s.SQL
@pytest.mark.parametrize('db',['postgres','jw_p1_offline_11','jw_p1_offline_01','jw_p1_offline_0; DROP TABLE x',None])
def test_probe_bad_target(db):
    def no(*a,**k):pytest.fail('unsafe invocation')
    with pytest.raises(eq.Blocked):s.probe(no,hx(10),db)
@pytest.mark.parametrize('response',[b'',b'{}',b'not JSON',b'\xff',b'x'*16385,b'{"owners":1,"owners":2}'])
def test_probe_invalid_response(response):
    with pytest.raises(eq.Blocked):s.probe(lambda *a,**k:SimpleNamespace(returncode=0,stdout=response),hx(10),'jw_p1_offline_0')

def test_replay_poison():
    doc,pairs,vault,scope=fixture();r=s.AuthorizationComparison(load(doc,pairs,vault,scope));b,c=pairs[0];r.compare(b,c,sections())
    with pytest.raises(eq.Blocked):r.compare(b,c,sections())
    assert r.receipt(cleanup='PASS')['overall']=='BLOCKED'

def test_reference_duplicate_json_key():
    doc,pairs,vault,scope=fixture();raw=b'{"format":1,'+eq.canonical(doc)[1:]
    with pytest.raises(eq.Blocked):s.load_reference(raw,expected_sha=hashlib.sha256(raw).hexdigest(),vault=vault,scope=scope,pairs=pairs)

from live_checks import pg17_authorization_smoke as smoke
@pytest.mark.parametrize('role',['jw_a','jw_b','jw_owner'])
def test_real_session_identity_command(role):
    q=smoke.tenant_query(role,'SELECT 1')
    assert q=='BEGIN; SET SESSION AUTHORIZATION '+role+'; SELECT 1; ROLLBACK;'
@pytest.mark.parametrize('role',['postgres','jw_a;SET ROLE postgres',None,'jw_c'])
def test_smoke_role_guard(role):
    with pytest.raises(RuntimeError,match='FIXTURE_ROLE_INVALID'):smoke.tenant_query(role,'SELECT 1')
@pytest.mark.parametrize('rc,err,want',[(1,b'ERROR:  42501: denied\n',True),(0,b'ERROR:  42501: denied',False),(1,b'ERROR:  42P01: missing',False),(1,b'connection refused',False),(1,b'not ERROR: 42501: injection',False),(1,b'ERROR: 425010: wrong code',False)])
def test_expected_denial(rc,err,want):
    assert smoke.expected_denial(SimpleNamespace(returncode=rc,stderr=err)) is want
