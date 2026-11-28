"""One focused disposable PG17 + actual document and custody integration suite."""
import copy
import hashlib
import io
import json
import os
import tempfile
from datetime import datetime, timezone, date, timedelta
from pathlib import Path
import pytest
import psycopg
from reportlab.pdfgen import canvas
from openpyxl import Workbook
from app.erp_migration_xlsx import parse_xlsx
from app.naruv_document_review import review_document
from app.naruv_recovery_custody_review import custody_evidence_message, review_custody_evidence
from app.naruv_operational_readiness import custody_trust_pin, review_and_consume_local_challenge
from app.naruv_kr_payroll_review import DEDUCTIONS
from app import naruv_draft_review as drafts, naruv_hr_review as hr
from scripts import ci_v90_postgres_browser as fixture
from scripts.naruv_native_write_review_ci import NativeWrite
from review_gates import operations_gate, reconcile_restore_inventory, Blocked
from document_candidates import review_candidates

def sha(b):return hashlib.sha256(b).hexdigest()
VALUES={'document_kind':'invoice','counterparty_id':'C001','document_date':'2026-11-28','reference_number':'001','subtotal':'1000','vat':'100','gross_amount':'1100'}
def make_doc(fmt,values):
    f=io.BytesIO()
    if fmt=='pdf':
        c=canvas.Canvas(f);t=c.beginText(50,750)
        for k,v in values.items():t.textLine(f'{k}: {v}')
        c.drawText(t);c.showPage();c.save()
    else:
        w=Workbook();w.active.append(['field','value'])
        for k,v in values.items():w.active.append([k,v])
        w.save(f);w.close()
    return f.getvalue()

@pytest.mark.parametrize('fmt',['pdf','xlsx'])
@pytest.mark.parametrize('case',['normal','mismatch','missing','source_change'])
def test_actual_parser_and_review(fmt,case):
    vals=dict(VALUES)
    if case=='mismatch':vals['gross_amount']='1099'
    if case=='missing':del vals['vat']
    raw=make_doc(fmt,vals);h=sha(raw)
    kwargs=dict(tenant='tenant',raw=raw,registered=h,format=fmt,review_document=review_document,strict_parser=parse_xlsx)
    if case=='source_change':
        with pytest.raises(Blocked,match='DOC_SOURCE_CHANGED'):review_candidates(**dict(kwargs,registered='0'*64))
        return
    r=review_candidates(**kwargs)
    assert r['requires_human_review'] and not r['posting_authorized']
    assert r['status']==('ORIGINAL_REVIEW_REQUIRED' if case=='normal' else 'MANUAL_CORRECTION_REQUIRED')
    if case=='mismatch':assert 'AMOUNT_MISMATCH' in r['issues']
    if case=='missing':assert 'MISSING_VAT' in r['issues']
    if case=='normal':assert r['field_count']==7

def test_real_parser_rejects_numeric_cells():
    raw=make_doc('xlsx',dict(VALUES,subtotal=1000))
    with pytest.raises(Blocked,match='DOC_XLSX_PARSE'):review_candidates(tenant='tenant',raw=raw,registered=sha(raw),format='xlsx',review_document=review_document,strict_parser=parse_xlsx)

def test_signed_inventory_and_consumed_challenge():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    ik,ck=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    ip,cp=[k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw) for k in (ik,ck)]
    now=datetime.now(timezone.utc)
    keys={'k1':dict(state='ACTIVE',expected_assets={'a':'a'*64}),'k2':dict(state='RECOVERY_ONLY',expected_assets={'b':'b'*64})}
    obs=[dict(key_id=k,state=v['state'],site_id='site2',custody_receipt_sha256='c'*64,restores=[dict(asset_id=a,ciphertext_sha256=h,restore_evidence_sha256='d'*64,full_authentication=True,restore_ok=True,network_isolated=True) for a,h in v['expected_assets'].items()]) for k,v in keys.items()]
    args=dict(tenant='tenant',expected_keys=keys,observations=obs,trust=dict(primary_site='site1',independent_site='site2',inventory_fingerprint=sha(ip),custodian_fingerprint=sha(cp)),challenge='e'*64,issued_at=now)
    msg=custody_evidence_message(**args)
    sigs=dict(inventory_public_key=ip,custodian_public_key=cp,inventory_signature=ik.sign(b'inventory:'+msg),custodian_signature=ck.sign(b'custodian:'+msg))
    expected={'k1/a':'a'*64,'k2/b':'b'*64}
    rows=[dict(asset_id=k,ciphertext_sha256=v,version_id=str(i)) for i,(k,v) in enumerate(expected.items())]
    verified=review_custody_evidence(**args,**sigs,as_of=now)
    kw=dict(expected=expected,vault=copy.deepcopy(rows),b2=copy.deepcopy(rows),signed_review=verified,trusted_evidence_sha256=sha(msg),signed_message=msg)
    assert reconcile_restore_inventory(**kw)['asset_count']==2
    bad=copy.deepcopy(kw);bad['b2'][0]['ciphertext_sha256']='f'*64
    with pytest.raises(Blocked,match='RESTORE_DIGEST'):reconcile_restore_inventory(**bad)
    pin=custody_trust_pin(tenant=args['tenant'],expected_keys=keys,trust=args['trust'])
    with tempfile.TemporaryDirectory(prefix='naruv-custody-',dir='/tmp') as d:
        result=review_and_consume_local_challenge(journal_dir=d,expected_trust_pin=pin,expected_challenge=args['challenge'],**args,**sigs)
        assert result['local_challenge_consumed'] and not result['physical_custody_verified'] and not result['production_authorized']
        with pytest.raises(ValueError,match='CUSTODY_LOCAL_REPLAY'):review_and_consume_local_challenge(journal_dir=d,expected_trust_pin=pin,expected_challenge=args['challenge'],**args,**sigs)
    with pytest.raises(ValueError,match='CUSTODY_SIGNATURE'):review_custody_evidence(**args,**dict(sigs,custodian_signature=b'x'*64),as_of=now)

@pytest.fixture(scope='module')
def pg():
    # Existing bootstrap insists on a fresh, localhost PG17 CI service.
    NativeWrite.setUpClass()
    os.environ.update({f'NARUV_{k}_REVIEW':'ISOLATED_SYNTHETIC_ONLY' for k in ('INVENTORY','TRADE','FINANCE','ACCOUNTING','BUNDLE','QUOTE_BUNDLE','PRODUCTION','VALUATION','DRAFT','HR')})
    os.environ[drafts.KR_FLAG]='DISPOSABLE_FIXTURE_ONLY'
    root=Path.cwd()
    with psycopg.connect(fixture.root_dsn) as c:
        c.execute("SELECT set_config('naruv.draft_ci','DISPOSABLE_ONLY',true)")
        c.execute((root/'db/review/naruv_draft_ci.sql').read_text())
    with psycopg.connect(fixture.root_dsn) as c:
        c.execute("SELECT set_config('naruv.hr_ci','DISPOSABLE_ONLY',true)")
        c.execute((root/'db/review/naruv_hr_ci.sql').read_text())
    assert drafts.register_drafts(NativeWrite.app)
    assert hr.register_hr(NativeWrite.app)
    return NativeWrite('test_csv_full_flow_and_exact_retry')

def call(pg,path,payload=None,who='A',extra=None):
    h={'content-type':'application/json','x-naruv-confirm':'yes'}
    if extra:h.update(extra)
    raw=b'' if payload is None else json.dumps(payload,separators=(',',':')).encode()
    return pg.req(path,who=who,raw=raw,extra=h)
def ok(r):
    assert r.status_code==200,r.text
    return r.json()

def test_confirmed_pg17_statement_route(pg):
    worker='/hr/workers/wave7-worker';period=worker+'/periods/2026-07'
    ok(call(pg,worker+'/register/w7-register'))
    ok(call(pg,period+'/create/w7-policy',dict(revision='w7-v1',hourly_krw=100000,additional_bps=15000)))
    for i,day in enumerate(('2026-07-01','2026-07-02')):
        ok(call(pg,period+'/attendance/w7-att'+str(i),dict(date=day,regular=480,additional=0)))
    paypath='/drafts/payroll/wave7-worker/2026-07'
    assert call(pg,paypath).status_code==404
    preview=ok(call(pg,period+'/review'))
    ok(call(pg,period+'/confirm/w7-confirm',dict(review_sha256=preview['review_sha256'])))
    gross=ok(call(pg,paypath))
    assert gross['gross_krw']==1600000
    path=paypath+'/kr-review'
    manual=dict(expected_draft_sha256=gross['draft_sha256'],ordinary_hourly=100000,classification_sha256='a'*64,
        classified_days=[dict(date=d,regular=480,overtime=0,holiday_first8=0,holiday_after8=0,night=0) for d in ('2026-07-01','2026-07-02')],
        deductions={k:dict(amount_krw=1000,evidence_sha256='b'*64,assessment='ASSESSED') for k in DEDUCTIONS},pension_assessed_base_krw=410000)
    weeks=[]
    for w in range(5):
        monday=date(2026,6,29)+timedelta(days=7*w);entries=[]
        for j in range(7):
            d=monday+timedelta(days=j)
            worked=d.isoformat() in ('2026-07-01','2026-07-02') or d.month==6
            state=('PRESENT' if worked else 'APPROVED_FULL_DAY_ANNUAL_LEAVE' if d.isoformat()=='2026-07-03' else 'ABSENT') if j<5 else ('WEEKLY_REST' if j==6 else 'NON_WORK_DAY')
            entries.append(dict(date=d.isoformat(),status=state,actual_minutes=480 if state=='PRESENT' else 0,evidence_sha256='a'*64))
        weeks.append(dict(monday=monday.isoformat(),employed_full_week=True,days=entries))
    paid=dict(schedule_sha256='b'*64,attendance_sha256='c'*64,weeks=weeks,scope='HOURLY_MON_FRI_40H_SUNDAY_REST_ORDINARY_LEAVE_RATE')
    data=dict(manual,fixed_week_paid_review=paid)
    baseline=ok(call(pg,path,data))['fixed_week_paid_reference']
    s=dict(payment_date='2026-08-10',completeness_assessment_sha256='c'*64,expected_monthly_review_sha256=baseline['review_sha256'])
    payload=dict(data,fixed_week_statement_review=s)
    resp=call(pg,path,payload);out=ok(resp);st=out['fixed_week_statement_reference']
    assert resp.headers['cache-control']=='no-store'
    assert st['gross_krw']==3200000 and st['gross_krw']-st['deductions_krw']==st['net_krw']
    assert all(st[k] is False for k in ('completeness_verified','payment_date_verified','statutory_validated','payment_authorized','delivery_authorized','production_authorized'))
    assert ok(call(pg,path,payload))==out
    assert call(pg,path,dict(payload,fixed_week_statement_review=dict(s,expected_monthly_review_sha256='0'*64))).status_code==409
    assert call(pg,path,dict(manual,fixed_week_statement_review=s)).status_code==422
    assert call(pg,path,dict(payload,wage_statement_review={})).status_code==422
    assert call(pg,path,payload,who='B').status_code==404
    assert call(pg,path,payload,who=None).status_code==401
    assert call(pg,path,payload,extra={'origin':'https://other.test'}).status_code==403
    assert call(pg,path,payload,extra={'x-csrf-token':'wrong'}).status_code==403
    with psycopg.connect(fixture.root_dsn) as c:
        assert c.execute("SELECT count(*) FROM naruv_draft.period_confirmations WHERE org_id='ci-a' AND worker_id='wave7-worker'").fetchone()[0]==1
        c.execute("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'")
    try:assert call(pg,path,payload).status_code==403
    finally:
        with psycopg.connect(fixture.root_dsn) as c:c.execute("UPDATE jw_dev.users SET role='admin' WHERE id='ci-ua'")
    os.environ.pop(drafts.KR_FLAG)
    try:assert call(pg,path,payload).status_code==404
    finally:os.environ[drafts.KR_FLAG]='DISPOSABLE_FIXTURE_ONLY'
    print('WAVE7_REAL_PG17_STATEMENT_AND_AUTH_BOUNDARY_PASS')

def test_ops_receipt_cannot_authorize_business():
    now=datetime.now(timezone.utc)
    p=dict(status='QA_HEALTH_AND_UNAUTHENTICATED_BARRIER_PASS',observations=[dict(path='health',curl_exit=0,http=200,tls=0),dict(path='root',curl_exit=0,http=401,tls=0)],release_authorized=False,database_verified=False,deployed_sha_verified=False,production_sla_verified=False)
    a=dict(expected_sha='a'*40,observed_sha='a'*40,observed_at=now,now=now,deployment_live=True,probe=p)
    r=operations_gate(**a)
    assert r['status']=='TRANSPORT_AND_DEPLOY_METADATA_MATCH_ONLY' and not r['authenticated_business_verified']
    assert operations_gate(**dict(a,observed_at=now-timedelta(seconds=301)))['status']=='BLOCKED_EVIDENCE'
