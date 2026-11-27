import hashlib
import pytest
from scripts import naruv_runner_evidence_review as m
from scripts import naruv_future_receipt_review as v

@pytest.fixture
def binding(monkeypatch):
    for k,value in {'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':'guccizz1k/JARVIS-WORKS',
                    'NARUV_RUNNER_EVIDENCE_CI':'1','NARUV_EXPECTED_RUNNER_SHA':'a'*40}.items():
        monkeypatch.setenv(k,value)
    ref=b'review-reference';manifest=b'review-manifest'
    doc=dict(scope='legacy',run_id='1'*32,challenge='2'*64,
             manifest_sha256=hashlib.sha256(manifest).hexdigest(),
             reference_sha256=hashlib.sha256(ref).hexdigest(),runner_commit='a'*40,
             archives=[f'{i:064x}' for i in range(11)])
    staged=(manifest,doc['manifest_sha256'],'unused','legacy')
    return doc,ref,staged

def start(doc,ref,staged,**kw):
    return m.prepare(v.canonical(doc),ref,doc['reference_sha256'],staged,
                     **dict({'catalog_required':True,'owner_controlled':True},**kw))

def report():
    return dict(owner_site_restore='PASS_ELEVEN_OWNER_SITE_CIPHERS',
                normalized_catalog_comparison='PASS_11_SCOPED_CATALOG_CHECKPOINTS',
                normalized_archive_comparison='PASS_11_ARCHIVE_CHECKPOINTS',
                disposable_pg17_removed='PASS',review_cleanup_absence_verified=True,b2_staged_scope_bound=True,
                owner_scope_pin_checked=True,decrypted_dump_written_to_host=False,
                verified_provider_cipher_count=11,restored_pg17_archive_count=11,
                restored_65_table_archive_count=11,restore_failures=0)

@pytest.mark.parametrize('bad',['ci','scope','manifest','reference','commit','catalog','owner'])
def test_preflight(binding,monkeypatch,bad):
    doc,ref,staged=binding;kw={}
    if bad=='ci':monkeypatch.delenv('NARUV_RUNNER_EVIDENCE_CI')
    elif bad=='scope':doc['scope']='staged'
    elif bad=='manifest':doc['manifest_sha256']='b'*64
    elif bad=='reference':doc['reference_sha256']='b'*64
    elif bad=='commit':doc['runner_commit']='b'*40
    elif bad=='catalog':kw['catalog_required']=False
    elif bad=='owner':kw['owner_controlled']=False
    with pytest.raises(ValueError,match='REVIEW_'):start(doc,ref,staged,**kw)

def test_exact_archive_binding(binding):
    doc,ref,staged=binding;cap=start(doc,ref,staged)
    pairs=[(f'{i:040x}',h) for i,h in enumerate(doc['archives'])]
    m.check_archive_set(cap,pairs)
    with pytest.raises(ValueError,match='REVIEW_ARCHIVE_SET_MISMATCH'):m.check_archive_set(cap,pairs[:-1]+[pairs[0]])

@pytest.mark.parametrize('bad',['cleanup','absence','catalog','archive','count','failures','owner','scope','plaintext','missing','duplicate','wrong'])
def test_no_partial_success(binding,bad):
    doc,ref,staged=binding;cap=start(doc,ref,staged)
    r=report();observed=list(doc['archives'])
    changes={'absence':('review_cleanup_absence_verified',False),'cleanup':('disposable_pg17_removed','BLOCKED'),'catalog':('normalized_catalog_comparison','BLOCKED'),
             'archive':('normalized_archive_comparison','BLOCKED'),'count':('restored_pg17_archive_count',10),
             'failures':('restore_failures',1),'owner':('owner_site_restore','BLOCKED'),
             'scope':('owner_scope_pin_checked',False),'plaintext':('decrypted_dump_written_to_host',True)}
    if bad in changes:
        k,x=changes[bad];r[k]=x
    elif bad=='missing':observed.pop()
    elif bad=='duplicate':observed[-1]=observed[0]
    elif bad=='wrong':observed[-1]='f'*64
    out=m.finish(cap,observed,r)
    assert out['status']=='BLOCKED' and out['archive_results']==[] and out['signature']=='NOT_CREATED'

def test_immutable_bound_capture(binding):
    doc,ref,staged=binding;cap=start(doc,ref,staged)
    original=list(doc['archives']);doc['archives'].clear()
    out=m.finish(cap,list(reversed(original)),report())
    assert out['status']=='PASS_ARCHIVE_OBSERVATIONS_ONLY'
    assert [x['archive_sha256'] for x in out['archive_results']]==original
    assert out['host_isolation']=='NOT_ATTESTED' and not out['production_authorized']
