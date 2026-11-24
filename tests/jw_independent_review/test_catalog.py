import copy
import hashlib
import json
from types import SimpleNamespace
import pytest
from scripts import jw_independent_catalog_v223 as cat
from scripts import jw_independent_equivalence_v223 as eq
from test_jw_independent_equivalence_v223 import fixture, observation, H
from test_equivalence_runner import scenario

def make_catalog(n=0):
    return {k:[65 if k in ('relations','columns','rls_flags') else n,H(f'{k}-{n}')] for k in cat.SECTIONS}

def make_reference(data=None):
    d,p=fixture() if data is None else (data,[(x['git_blob_sha1'],x['cipher_sha256']) for x in data['archives']])
    return {'format':cat.FORMAT,'algorithm':cat.ALGORITHM,'data_reference':d,'catalog_archives':[{'git_blob_sha1':r['git_blob_sha1'],'cipher_sha256':r['cipher_sha256'],'sections':make_catalog(i)} for i,r in enumerate(d['archives'])]},p

def load(d=None,p=None,**kw):
    default,dp=make_reference();d=default if d is None else d;p=dp if p is None else p
    raw=eq.canonical(d);opts=dict(expected_reference_sha256=hashlib.sha256(raw).hexdigest(),expected_vault='a'*40,expected_scope=eq.owner_scope(b for b,c in dp),provider_pairs=p);opts.update(kw)
    return cat.load_reference(raw,**opts)

def test_complete_scoped_only():
    rows,c=load();g=cat.CatalogComparison(rows,c)
    for r in rows:g.compare(r.git_blob_sha1,r.cipher_sha256,observation(r),c[r.git_blob_sha1])
    a=g.receipt(cleanup='PASS')
    assert a['normalized_catalog_comparison']=='PASS_11_SCOPED_CATALOG_CHECKPOINTS'
    assert a['rls_policy_definition_comparison']=='PASS_11_ARCHIVE_POLICY_AND_FLAGS'
    assert a['rls_effective_enforcement']=='NOT_RUN' and a['overall']=='BLOCKED'
    assert a['original_owner_acl_equivalence'].startswith('NOT_RUN') and a['role_membership_equivalence'].startswith('NOT_ATTESTED')
    assert g.receipt(cleanup='FAIL')['normalized_catalog_comparison']=='BLOCKED'

@pytest.mark.parametrize('section',cat.SECTIONS)
@pytest.mark.parametrize('kind',['hash','count'])
def test_catalog_mismatch(section,kind):
    rows,c=load();g=cat.CatalogComparison(rows,c);r=rows[0];o=dict(c[r.git_blob_sha1]);a,b=o[section];o[section]=(a+1,b) if kind=='count' else (a,H('changed'))
    with pytest.raises(eq.Blocked,match='CATALOG_'+section.upper()+'_MISMATCH'):g.compare(r.git_blob_sha1,r.cipher_sha256,observation(r),o)
    assert g.receipt(cleanup='PASS')['normalized_archive_comparison']=='BLOCKED'
    with pytest.raises(eq.Blocked,match='CATALOG_RUN_FAILED'):g.compare(r.git_blob_sha1,r.cipher_sha256,observation(r),c[r.git_blob_sha1])

@pytest.mark.parametrize('mutation',['missing','extra','duplicate','cipher','unknown_blob','wrong_algorithm','wrong_format','wrong_pin','scope','wrong_vault','invalid_hash','boolean_count','negative_count','too_many','rls_missing_table','column_missing','missing_section','unknown_section'])
def test_bad_reference(mutation):
    d,p=make_reference();a=d['catalog_archives'];opts={}
    if mutation=='missing':a.pop()
    elif mutation=='extra':a.append(copy.deepcopy(a[0]))
    elif mutation=='duplicate':a[1]=copy.deepcopy(a[0])
    elif mutation=='cipher':a[0]['cipher_sha256']=H('wrong')
    elif mutation=='unknown_blob':a[0]['git_blob_sha1']='f'*40
    elif mutation=='wrong_algorithm':d['algorithm']='x'
    elif mutation=='wrong_format':d['format']='x'
    elif mutation=='wrong_pin':opts['expected_reference_sha256']='0'*64
    elif mutation=='scope':opts['expected_scope']='0'*64
    elif mutation=='wrong_vault':opts['expected_vault']='f'*40
    elif mutation=='invalid_hash':a[0]['sections']['policies'][1]='x'
    elif mutation=='boolean_count':a[0]['sections']['policies'][0]=True
    elif mutation=='negative_count':a[0]['sections']['policies'][0]=-1
    elif mutation=='too_many':a[0]['sections']['policies'][0]=100001
    elif mutation=='rls_missing_table':a[0]['sections']['rls_flags'][0]=64
    elif mutation=='column_missing':a[0]['sections']['columns'][0]=0
    elif mutation=='missing_section':del a[0]['sections']['policies']
    elif mutation=='unknown_section':a[0]['sections']['acl']=[0,H('fake')]
    with pytest.raises(eq.Blocked):load(d,p,**opts)

@pytest.mark.parametrize('kind',['missing','replay','cross_archive','invalid_observation','forged_boolean'])
def test_incomplete_or_replay(kind):
    rows,c=load();g=cat.CatalogComparison(rows,c);r=rows[0];o=c[r.git_blob_sha1]
    g.compare(r.git_blob_sha1,r.cipher_sha256,observation(r),o)
    if kind!='missing':
        s=r if kind=='replay' else rows[1]; bad=c[s.git_blob_sha1]
        if kind=='cross_archive':bad=o
        elif kind=='invalid_observation':bad=None
        elif kind=='forged_boolean':bad=dict(bad);bad['policies']=(True,bad['policies'][1])
        with pytest.raises(eq.Blocked):g.compare(s.git_blob_sha1,s.cipher_sha256,observation(s),bad)
    assert g.receipt(cleanup='PASS')['normalized_catalog_comparison']=='BLOCKED'

def test_probe_fixed_target_and_no_raw_output():
    calls=[]
    def run(*args,**kwargs):calls.append((args,kwargs));return SimpleNamespace(returncode=0,stdout=json.dumps(make_catalog()).encode())
    assert cat.probe(run,'f'*64,'jw_p1_offline_10')==cat.parse_catalog(make_catalog())
    a,k=calls[0];assert a[1][0:3]==['psql','-X','-qAt'] and a[1][-1]==cat.SQL and k['timeout']==50
    assert 'READ ONLY' in cat.SQL and 'relforcerowsecurity' in cat.SQL and 'polwithcheck' in cat.SQL

@pytest.mark.parametrize('db,container',[('postgres','f'*64),('jw_p1_offline_11','f'*64),('jw_p1_offline_1;drop','f'*64),('jw_p1_offline_1','--help')])
def test_invalid_probe_target(db,container):
    with pytest.raises(eq.Blocked):cat.probe(lambda *_:pytest.fail('executed'),container,db)

@pytest.mark.parametrize('rc,stdout',[(1,b'secret'),(0,b''),(0,b'x'*16385),(0,b'{"a":1,"a":2}'),(0,b'{}'),(0,b'\xff')])
def test_bad_probe_output(rc,stdout):
    with pytest.raises(eq.Blocked) as e:cat.probe(lambda *a,**k:SimpleNamespace(returncode=rc,stdout=stdout),'f'*64,'jw_p1_offline_1')
    assert 'secret' not in str(e.value)

@pytest.mark.parametrize('mode',['success','mismatch','missing_hook','replay_hook','wrong_target','cleanup_failure','bad_pin'])
def test_runner_catalog(scenario,monkeypatch,mode):
    s=scenario;d,p=make_reference(json.loads(s.raw));raw=eq.canonical(d);pin=hashlib.sha256(raw).hexdigest()
    calls=[];old=s.offline._restore_one
    def probe(execfn,c,db):
        i=int(db.rsplit('_',1)[1]);calls.append(i);observed=cat.parse_catalog(make_catalog(i))
        if mode=='mismatch' and i==3:observed['policies']=(0,H('bad'))
        return observed
    def restore(c,plain,i,*,catalog_probe):
        result=old(c,plain,i)
        if mode!='missing_hook':catalog_probe(c,'postgres' if mode=='wrong_target' else f'jw_p1_offline_{i}')
        if mode=='replay_hook':catalog_probe(c,f'jw_p1_offline_{i}')
        return result
    monkeypatch.setattr(s.runner.catalog,'probe',probe);monkeypatch.setattr(s.offline,'_restore_one',restore)
    if mode=='cleanup_failure':
        original=s.offline._docker
        monkeypatch.setattr(s.offline,'_docker',lambda a,**kw: SimpleNamespace(returncode=1,stdout=b'') if a[0]=='rm' else original(a,**kw))
    r=s.run(raw,'0'*64 if mode=='bad_pin' else pin,catalog_required=True)
    assert r['overall']=='BLOCKED'
    assert (r['normalized_catalog_comparison']=='PASS_11_SCOPED_CATALOG_CHECKPOINTS')==(mode=='success')
    if mode=='success':assert len(calls)==11 and r['catalog_matched_archives']==11
    if mode=='mismatch':assert calls==list(range(4)) and r['catalog_matched_archives']==3
    if mode=='bad_pin':assert not calls and not s.calls

def test_copy_reference_prevents_post_admission_mutation():
    rows,c=load();g=cat.CatalogComparison(rows,c);r=rows[0]
    original=dict(c[r.git_blob_sha1]);c[r.git_blob_sha1]['policies']=(999,H('mutated'))
    g.compare(r.git_blob_sha1,r.cipher_sha256,observation(r),original)
    assert len(g.done)==1

@pytest.mark.parametrize('kind',['missing','duplicate','wrong_blob','syntax'])
def test_offline_hook_anchor_guard(kind):
    import offline_hook
    sig=offline_hook.ANCHORS[0][0]
    ret=offline_hook.ANCHORS[1][0]
    src='def example('+sig+'\n    try:\n        if True:\n'+ret+' None\n    finally:\n        pass\n'
    if kind=='missing':src=src.replace('schema_probe =','different =')
    elif kind=='duplicate':src+=src
    elif kind=='syntax':src+='\n!bad'
    if kind=='wrong_blob':
        with pytest.raises(ValueError,match='SOURCE_BLOB_MISMATCH'):offline_hook.check(src.encode())
    else:
        with pytest.raises((ValueError,SyntaxError)):offline_hook.transform(src)

def test_offline_hook_callback_before_return_and_finally():
    import offline_hook
    sig=offline_hook.ANCHORS[0][0]; ret=offline_hook.ANCHORS[1][0]
    src='def example(container,db,'+sig+'\n    try:\n        if True:\n'+ret+' None\n    finally:\n        cleanup()\n'
    calls=[];ns={'cleanup':lambda:calls.append('cleanup')};exec(offline_hook.transform(src),ns)
    assert ns['example']('container','db',catalog_probe=lambda c,d:calls.append('probe'))[0]=='LOCAL_DISPOSABLE_RESTORED'
    assert calls==['probe','cleanup']
    calls.clear()
    def fail(*a):calls.append('failed');raise RuntimeError('probe error')
    with pytest.raises(RuntimeError):ns['example']('container','db',catalog_probe=fail)
    assert calls==['failed','cleanup']
