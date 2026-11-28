"""Fresh PG17 integration only; prior Wave11 test functions are not collected."""
import copy,hashlib,json,os,time
from datetime import datetime,timedelta,timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from functools import partial
import ast
import pytest
import psycopg
from fastapi import FastAPI
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import test_wave11_db as old
from app import naruv_draft_review as drafts,naruv_native_write_review as write,naruv_native_file_preview as preview,pg_v90_integrated_entry as v90
from scripts import ci_v90_postgres_browser as fixture
from receipt_api import register_review
from queue_integrity import BoundStore,BoundQueue,read_bound,encode,sha
from queue_bridge import process_review_job,ACK
from local_queue_store import FixtureStore,filename
from review_gates import Blocked
from load_evidence import summarize
from clamav_fixture_scan import scan_fixture
from prospective_acl import AUTHZ,ROLES,BEHAVIOR,canonical,compare
from policy_approval import message
from combined_recovery import combine
from pinned.naruv_recovery_custody_review import custody_evidence_message
from korean_observations import observations
from pinned.naruv_document_review import review_document

pg=old.pg
paid=old.paid
receipt=old.receipt
queue_db=old.queue_db
HERE=Path(__file__).resolve().parent

@pytest.fixture(scope='module')
def api(pg,paid,receipt):
    from scripts.naruv_native_write_review_ci import NativeWrite
    os.environ.update({f'NARUV_{k}_REVIEW':'ISOLATED_SYNTHETIC_ONLY' for k in ('INVENTORY','TRADE','FINANCE','ACCOUNTING','BUNDLE','QUOTE_BUNDLE','PRODUCTION','VALUATION','DRAFT','HR')})
    os.environ[drafts.KR_FLAG]='DISPOSABLE_FIXTURE_ONLY'
    args=dict(drafts=drafts,write=write,preview=preview,v90=v90)
    os.environ.pop('NARUV_RECEIPT_API_CI',None)
    assert not register_review(FastAPI(),**args)
    os.environ['NARUV_RECEIPT_API_CI']='DISPOSABLE_FIXTURE_ONLY'
    assert register_review(NativeWrite.app,**args)
    return NativeWrite.app

def request(api,paid,receipt,who='A',extra=None,change=None,raw=None,suffix=''):
    a,d,conf=paid
    body=dict(confirmation_pin=conf,receipt_pin=receipt,draft=copy.deepcopy(d))
    if change:change(body)
    with TestClient(api,base_url='https://testserver') as client:
        if who is not None:client.cookies.set('__Host-jw_session',fixture.TOKENS[who])
        headers={'origin':'https://testserver','x-csrf-token':fixture.CSRF[who or 'A'],'content-type':'application/json'}
        headers.update(extra or {})
        return client.post(drafts.PREFIX+'/payroll/'+a['worker']+'/'+a['period']+'/receipt-review'+suffix,headers=headers,content=json.dumps(body,separators=(',',':')).encode() if raw is None else raw)

def success(r):
    assert r.status_code==200,r.text
    assert r.headers['cache-control']=='no-store' and r.headers['x-content-type-options']=='nosniff'
    b=r.json()
    assert b['source_integrity_verified'] is True and all(b[k] is False for k in ('statutory_validated','payment_authorized','delivery_authorized','production_authorized'))
    return b

def test_real_api_receipt_errors_and_scope(api,paid,receipt):
    baseline=success(request(api,paid,receipt))
    assert success(request(api,paid,receipt))==baseline
    def bad_draft(b):b['draft']['gross_krw']+=1;b['draft']['net_krw']+=1
    cases=[(dict(who=None),401),(dict(who='B'),404),(dict(extra={'origin':'https://other.invalid'}),403),
        (dict(extra={'x-csrf-token':'wrong'}),403),(dict(extra={'content-type':'text/plain'}),415),
        (dict(suffix='?org_id=ci-b'),422),(dict(change=lambda b:b.update(receipt_pin='0'*64)),409),
        (dict(change=lambda b:b.update(confirmation_pin='0'*64)),409),(dict(change=bad_draft),409),
        (dict(raw=b'{"receipt_pin":"x","receipt_pin":"y"}'),422),(dict(raw=b'x'*32769),413)]
    for kwargs,code in cases:
        r=request(api,paid,receipt,**kwargs);assert r.status_code==code,(kwargs,r.status_code,r.text)
        assert r.headers['cache-control']=='no-store'
    with psycopg.connect(fixture.root_dsn) as c:c.execute("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'")
    try:assert request(api,paid,receipt).status_code==403
    finally:
        with psycopg.connect(fixture.root_dsn) as c:c.execute("UPDATE jw_dev.users SET role='admin' WHERE id='ci-ua'")
    os.environ.pop('NARUV_RECEIPT_API_CI')
    try:assert request(api,paid,receipt).status_code==404
    finally:os.environ['NARUV_RECEIPT_API_CI']='DISPOSABLE_FIXTURE_ONLY'
    assert success(request(api,paid,receipt))==baseline
    print('WAVE12_REAL_PG17_RECEIPT_HTTP_BOUNDARY_PASS')

def test_actual_api_pg_request_load(api,paid,receipt):
    plan=dict(run_id='wave12-ci',sha=os.environ['REVIEW_SHA'],environment='DISPOSABLE_LOCAL',request_ids=[f'r{i}' for i in range(24)],concurrency=4)
    def one(i):
        t=time.perf_counter()
        try:
            r=request(api,paid,receipt);b=r.json()
            return dict(id=i,run_id=plan['run_id'],sha=plan['sha'],ms=(time.perf_counter()-t)*1000,status=r.status_code,scope_ok=r.status_code==200 and b.get('source_integrity_verified') is True and b.get('payment_authorized') is False)
        except Exception:
            return dict(id=i,run_id=plan['run_id'],sha=plan['sha'],ms=(time.perf_counter()-t)*1000,status=0,scope_ok=False)
    started=datetime.now(timezone.utc)
    with ThreadPoolExecutor(max_workers=4) as pool:samples=list(pool.map(one,plan['request_ids']))
    ended=datetime.now(timezone.utc)
    result=summarize(plan=plan,samples=samples,started=started,ended=ended,now=datetime.now(timezone.utc))
    assert result['status']=='LOCAL_MEASUREMENT_ONLY' and result['successful']==24 and not result['hosted_sla_verified'],result
    print('WAVE12_AUTHENTICATED_API_PG17_LOAD '+json.dumps(result,sort_keys=True))

@pytest.fixture(scope='module')
def digest_queue(queue_db):
    dsn,a,b=queue_db
    with psycopg.connect(dsn) as c:old.install(c,HERE/'queue_result_digest_ci.sql','naruv.ocr_digest_ci')
    return queue_db

@pytest.fixture
def scanner(tmp_path):
    marker=b'NARUV-WAVE12-SYNTHETIC-MARKER-ONLY'
    database=tmp_path/'fixture.ndb'
    database.write_text('Naruv.Wave12.Fixture:0:*:'+marker.hex()+'\n',encoding='ascii')
    scan=partial(scan_fixture,database=database,pin=sha(database.read_bytes()))
    assert scan(b'benign fixture') is True
    assert scan(marker) is False
    # Distinguish actual detection (exit 1 and custom signature) from engine failure.
    import subprocess
    sample=tmp_path/'marker.fixture';sample.write_bytes(marker)
    cp=subprocess.run(['/usr/bin/clamscan','--database='+str(database),'--no-summary',str(sample)],capture_output=True,timeout=10,check=False)
    assert cp.returncode==1 and b'Naruv.Wave12.Fixture' in cp.stdout
    assert not scan_fixture(b'benign',database=database,pin='0'*64)
    return scan,marker

def test_real_queue_ocr_digest_and_engine(digest_queue,scanner,tmp_path):
    root,a,b=digest_queue;qa=old.queue(a);scan,marker=scanner
    directory=tmp_path/'objects';directory.mkdir(mode=0o700);fd=os.open(directory,os.O_DIRECTORY|os.O_RDONLY)
    try:
        with FixtureStore(fd) as store:
            lines=['문서종류: 견적서','거래처코드: 123456','작성일: 2026-11-28','문서번호: 987654','공급가액: 200,000 원','부가세: 20,000 원','합계금액: 220,000 원']
            raw=old.image(lines,'PNG');key='tenant/ci-a/'+'d'*32
            old.seed(directory,'ci-a',key,raw)
            job,created=old.submit(qa,'ci-a',key,raw,'wave12-clean-01','png','ci-ua');assert created
            bs=BoundStore(store);q=BoundQueue(qa,lambda:psycopg.connect(a,connect_timeout=5),bs)
            assert process_review_job(q,bs,ack=ACK,scan=scan)=='NEEDS_REVIEW'
            with psycopg.connect(a) as c:
                result=read_bound(c.cursor(),store,tenant='ci-a',job_id=job)
                path,pin=c.execute('SELECT result_key,result_sha256 FROM jw_dev.ocr_jobs_v112 WHERE id=%s',(job,)).fetchone()
            expected=review_document(tenant='ci-a',source_bytes=raw,registered_sha256=sha(raw),observations=observations(['\n'.join(lines)]))
            assert result['review_sha256']==expected['review_sha256'] or result.get('id_preview',{}).get('review_sha256')==expected['review_sha256']
            assert result['network_fence']=='SOCKET_SYSCALL_DENIAL_ONLY' and result['posting_authorized'] is False
            output=directory/filename('ci-a',path,True);original=output.read_bytes()
            assert sha(original)==pin==sha(encode(result))
            changed=dict(result,issues=['changed']);output.write_bytes(encode(changed))
            with psycopg.connect(a) as c:
                with pytest.raises(Blocked,match='QUEUE_RESULT_STORAGE_CHANGED'):read_bound(c.cursor(),store,tenant='ci-a',job_id=job)
            output.write_bytes(original)
            with psycopg.connect(a) as c:
                with pytest.raises(psycopg.Error,match='OCR_JOB_RESULT_LEASE|OCR_RESULT_IMMUTABLE'):
                    c.execute("UPDATE jw_dev.ocr_jobs_v112 SET result_sha256=%s WHERE id=%s",('0'*64,job))
            # The predecessor lease trigger runs first for changes to completed rows.
            # Leaving needs_review would evade that branch; the new trigger must block it.
            with psycopg.connect(a) as c:
                with pytest.raises(psycopg.Error,match='OCR_RESULT_IMMUTABLE'):
                    c.execute("UPDATE jw_dev.ocr_jobs_v112 SET state='queued',result_key=NULL,result_sha256=NULL,completed_at=NULL WHERE id=%s",(job,))
            with psycopg.connect(b) as c:
                with pytest.raises(Blocked,match='QUEUE_RESULT_NOT_COMMITTED'):read_bound(c.cursor(),store,tenant='ci-a',job_id=job)
            # Safe synthetic signature detection, BEFORE the document parser.
            badkey='tenant/ci-a/'+'e'*32
            old.seed(directory,'ci-a',badkey,marker)
            rejected,_=old.submit(qa,'ci-a',badkey,marker,'wave12-scan-01','png','ci-ua')
            bs=BoundStore(store);q=BoundQueue(qa,lambda:psycopg.connect(a),bs)
            def never(**kw):raise AssertionError('scanner must reject before parser')
            assert process_review_job(q,bs,ack=ACK,scan=scan,parser=never)=='RETRY_OR_FAILED'
            with psycopg.connect(a) as c:
                assert c.execute('SELECT last_error_code,result_sha256 FROM jw_dev.ocr_jobs_v112 WHERE id=%s',(rejected,)).fetchone()==('SCAN_REJECTED',None)
            assert bs.binding is None
            # Isolate subsequent lease tests from a timed retry of this rejected fixture.
            with psycopg.connect(root) as c:
                c.execute("UPDATE jw_dev.ocr_jobs_v112 SET available_at=clock_timestamp()+interval '1 hour' WHERE id=%s",(rejected,))
            print('WAVE12_REAL_CLAMAV_CUSTOM_SIGNATURE_AND_PG17_OCR_DIGEST_PASS')
    finally:os.close(fd)

def test_stale_digest_completion(digest_queue,tmp_path):
    root,a,b=digest_queue;qa=old.queue(a)
    directory=tmp_path/'objects';directory.mkdir(mode=0o700);fd=os.open(directory,os.O_DIRECTORY|os.O_RDONLY)
    try:
        with FixtureStore(fd) as store:
            raw=b'fixture';key='tenant/ci-a/'+'f'*32;old.seed(directory,'ci-a',key,raw)
            j,_=old.submit(qa,'ci-a',key,raw,'wave12-stale-01','png','ci-ua')
            first=qa.claim();assert first.id==j
            k=f'tenant/ci-a/ocr-result/{j}/{first.lease_token}'
            r=dict(source_sha256=sha(raw),review_sha256='a'*64,status='MANUAL_CORRECTION_REQUIRED',posting_authorized=False,recognition_authorized=False,requires_human_review=True,issues=['fixture'])
            bs=BoundStore(store);bs.write_proposal('ci-a',k,r);q=BoundQueue(qa,lambda:psycopg.connect(a),bs)
            f=directory/filename('ci-a',k,True);f.write_bytes(encode(dict(r,issues=['changed'])))
            with pytest.raises(Blocked,match='QUEUE_RESULT_STORAGE_CHANGED'):q.complete(first,result_key=k)
            f.write_bytes(encode(r))
            with psycopg.connect(root) as c:c.execute("UPDATE jw_dev.ocr_jobs_v112 SET lease_until=clock_timestamp()-interval '1 second' WHERE id=%s",(j,))
            second=qa.claim();assert second.id==j and second.lease_token!=first.lease_token
            assert q.complete(first,result_key=k) is False
            newkey=f'tenant/ci-a/ocr-result/{j}/{second.lease_token}'
            bs=BoundStore(store);bs.write_proposal('ci-a',newkey,r);q=BoundQueue(qa,lambda:psycopg.connect(a),bs)
            assert q.complete(second,result_key=newkey)
            with psycopg.connect(a) as c:
                assert read_bound(c.cursor(),store,tenant='ci-a',job_id=j)==r
                assert c.execute('SELECT result_key,result_sha256 FROM jw_dev.ocr_jobs_v112 WHERE id=%s',(j,)).fetchone()==(newkey,sha(encode(r)))
            assert f.is_file()
            print('WAVE12_REAL_STALE_LEASE_AND_PRECOMMIT_DIGEST_PASS')
    finally:os.close(fd)

def query_from(path):
    # Extract exact, already reviewed catalog SELECT without importing or executing script.
    tree=ast.parse(path.read_text())
    values=[ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SQL' for t in n.targets)]
    assert len(values)==1
    start=values[0].index('WITH ');end=values[0].rindex(';\nROLLBACK;')
    return values[0][start:end]

def test_actual_catalog_drift_and_signed_composition(digest_queue,tmp_path):
    root,a,b=digest_queue
    scripts=Path(os.environ['REVIEW_SCRIPTS'])
    aq=query_from(scripts/'jw_independent_security_v223.py')
    rq=query_from(scripts/'jw_pg17_role_graph_v223.py')
    def observed(c):
        authz=c.execute(aq).fetchone()[0];roles=c.execute(rq).fetchone()[0]
        assert roles['server_major']==17 and roles['unresolved_refs']==0
        assert set(authz)==set(AUTHZ) and set(roles['sections'])==set(ROLES)
        return dict(server_major=17,authz=authz,roles=roles['sections'])
    def snapshot():
        with psycopg.connect(root) as c:
            c.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            c.execute('SET LOCAL search_path=pg_catalog')
            return observed(c)
    initial=snapshot()
    # Nine actual synthetic environment behaviors, no self-declared operational policy.
    qa=old.queue(a);raw=b'acl';key='tenant/ci-a/'+'1'*32
    jid,created=old.submit(qa,'ci-a',key,raw,'wave12-acl-01','png','ci-ua');assert created
    with psycopg.connect(a) as c:assert c.execute('SELECT count(*) FROM jw_dev.ocr_jobs_v112 WHERE id=%s',(jid,)).fetchone()==(1,)
    with psycopg.connect(b) as c:assert c.execute('SELECT count(*) FROM jw_dev.ocr_jobs_v112 WHERE id=%s',(jid,)).fetchone()==(0,)
    with pytest.raises(psycopg.Error):old.submit(old.queue(b),'ci-a',key,raw,'wave12-acl-cross','png','ci-ua')
    with psycopg.connect(root) as c:
        c.execute('SET LOCAL ROLE wave11_ocr_owner')
        assert c.execute('SELECT count(*) FROM jw_dev.ocr_jobs_v112').fetchone()==(0,)
    with psycopg.connect(a) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):c.execute('SET ROLE wave11_ocr_owner')
    with psycopg.connect(a) as c:assert c.execute("SELECT has_table_privilege(current_user,'jw_dev.ocr_jobs_v112','SELECT WITH GRANT OPTION')").fetchone()==(False,)
    with psycopg.connect(root) as c:
        c.execute('SET LOCAL search_path=pg_catalog')
        c.execute('GRANT SELECT ON jw_dev.organizations TO wave11_queue_a')
        drift=observed(c)
        assert drift['authz']['object_acl']!=initial['authz']['object_acl']
        c.rollback()
    after=snapshot();assert after==initial
    ref=dict(schema='NARUV_PROSPECTIVE_ACL_V1',scope='wave12-ephemeral',migration_sha=os.environ['REVIEW_SHA'],authz=initial['authz'],roles=initial['roles'],behavior_required=list(BEHAVIOR))
    pin=sha(canonical(ref));behavior={k:True for k in BEHAVIOR}
    rejected=compare(reference=ref,reference_pin=pin,observed=drift,observed_scope=ref['scope'],behavior=behavior,expected_migration_sha=ref['migration_sha'])
    assert rejected['status']=='BLOCKED' and 'ACL_MISMATCH_OBJECT_ACL' in rejected['reasons']
    now=datetime.now(timezone.utc);challenge='e'*64
    names=('policy_owner','independent_reviewer','inventory','custodian')
    keys={k:Ed25519PrivateKey.generate() for k in names};pub={k:v.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw) for k,v in keys.items()}
    start=now-timedelta(seconds=1);end=now+timedelta(minutes=5);roles=names[:2]
    m=message(reference_pin=pin,scope=ref['scope'],migration=ref['migration_sha'],challenge=challenge,issued_at=start,expires_at=end)
    policy=dict(reference=ref,reference_pin=pin,expected_scope=ref['scope'],expected_migration=ref['migration_sha'],expected_challenge=challenge,challenge=challenge,issued_at=start,expires_at=end,public_keys={k:pub[k] for k in roles},fingerprints={k:sha(pub[k]) for k in roles},signatures={k:keys[k].sign(k.encode()+b':'+m) for k in roles},observed=after,behavior=behavior)
    ek={'k1':dict(state='ACTIVE',expected_assets={'a':'a'*64}),'k2':dict(state='RECOVERY_ONLY',expected_assets={'b':'b'*64})}
    obs=[dict(key_id=i,state=x['state'],site_id='s2',custody_receipt_sha256='c'*64,restores=[dict(asset_id=a,ciphertext_sha256=h,restore_evidence_sha256='d'*64,full_authentication=True,restore_ok=True,network_isolated=True) for a,h in x['expected_assets'].items()]) for i,x in ek.items()]
    e=dict(tenant='ci-a',expected_keys=ek,observations=obs,trust=dict(primary_site='s1',independent_site='s2',inventory_fingerprint=sha(pub['inventory']),custodian_fingerprint=sha(pub['custodian'])),challenge=challenge,issued_at=now)
    cp=sha(canonical(['NARUV_CUSTODY_TRUST_PIN_V1',e['tenant'],e['expected_keys'],e['trust']]));m=custody_evidence_message(**e);e.update(inventory_public_key=pub['inventory'],custodian_public_key=pub['custodian'],inventory_signature=keys['inventory'].sign(b'inventory:'+m),custodian_signature=keys['custodian'].sign(b'custodian:'+m))
    exp={'k1/a':'a'*64,'k2/b':'b'*64};rows=[dict(asset_id=i,ciphertext_sha256=h,version_id=str(j)) for j,(i,h) in enumerate(exp.items())]
    kw=dict(policy=policy,custody=e,expected_scope=ref['scope'],expected_tenant='ci-a',expected_challenge=challenge,expected_policy_pin=pin,expected_custody_pin=cp,expected_policy_signers=copy.deepcopy(policy['fingerprints']),expected=exp,vault=copy.deepcopy(rows),b2=copy.deepcopy(rows))
    tmp_path.chmod(0o700);fd=os.open(tmp_path,os.O_DIRECTORY|os.O_RDONLY)
    try:
        bad=copy.deepcopy(kw);bad['policy']['observed']=drift
        with pytest.raises(Blocked,match='COMBINED_POLICY_BLOCKED'):combine(fd,**bad)
        assert not list(tmp_path.iterdir())
        out=combine(fd,**kw)
        assert out['challenge_consumed'] and not out['physical_custody_verified'] and not out['operational_policy_authorized'] and not out['production_authorized']
        with pytest.raises(Blocked,match='COMBINED_REPLAY'):combine(fd,**kw)
    finally:os.close(fd)
    print('WAVE12_ACTUAL_PG17_CATALOG_DRIFT_AND_SYNTHETIC_SIGNED_REVIEW_PASS')
