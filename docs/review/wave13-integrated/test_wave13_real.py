"""Wave13 new integration cases only. All databases, records, and keys are synthetic."""
import copy,hashlib,io,json,os,subprocess
from pathlib import Path
from datetime import datetime,timezone
import pytest
import psycopg
from psycopg.types.json import Jsonb
from PIL import Image,ImageDraw,ImageFont
import test_wave11_db as old
from scripts import ci_v90_postgres_browser as fixture
from app.naruv_kr_payroll_review import fixed_week_wage_statement_draft_2026 as statement,fixed_week_monthly_payroll_review_2026 as monthly,verify_fixed_week_statement_source_2026 as verify,PayrollBlocked
from app.naruv_payroll_draft import draft_gross
from payroll_correction import compare
import scan_snapshot as scan
from review_gates import Blocked
import grid_process,ocr_grid,release_evidence as release
from pinned.naruv_document_review import review_document
from queue_integrity import BoundStore,BoundQueue,read_bound
from local_queue_store import FixtureStore
from queue_bridge import process_review_job,ACK

pg=old.pg
queue_db=old.queue_db
HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()

def calculate(a,snapshot,assessment):
    a=copy.deepcopy(a)
    a.update(policy_revision=snapshot['policy_revision'],base_hourly=snapshot['hourly_krw'],additional_bps=snapshot['additional_bps'],minutes_by_day=[dict(date=d,regular=r,additional=x) for d,r,x in snapshot['days']],completeness_assessment_sha256=assessment)
    a['expected_draft_sha256']=draft_gross(tenant=a['tenant'],worker=a['worker'],period=a['period'],policy_revision=a['policy_revision'],hourly_krw=a['base_hourly'],minutes_by_day=a['minutes_by_day'],multiplier_bps={'regular':10000,'additional':a['additional_bps']})['draft_sha256']
    base={k:v for k,v in a.items() if k not in ('payment_date','completeness_assessment_sha256','expected_monthly_review_sha256')}
    a['expected_monthly_review_sha256']=monthly(**base)['review_sha256']
    return statement(**a)

def test_actual_pg_amendment_and_payroll_comparison(pg):
    a=old.paid_fixture();a['worker']='wave13-worker';w,p=a['worker'],a['period']
    with old.business(fixture.TRADE_DSN) as (cur,csrf):
        old.rpc(cur,'setup_worker',(w,None,'w13-reg',None,None,None,True,csrf))
        old.rpc(cur,'setup_worker',(w,p,'w13-period',a['policy_revision'],a['base_hourly'],a['additional_bps'],True,csrf))
        for i,d in enumerate(a['minutes_by_day']):
            old.rpc(cur,'admit_attendance',(w,p,f'w13-day-{i}',d['date'],d['regular'],d['additional'],True,csrf))
        previous=old.rpc(cur,'review_period',(w,p,None,None,False,csrf))
        assert previous['confirmed'] is False
    previous_draft=calculate(a,previous,'a'*64)
    with old.business(fixture.TRADE_DSN) as (cur,csrf):
        args=(w,p,'w13-amend',previous['review_sha256'],'policy',Jsonb(dict(revision='r2',hourly_krw=a['base_hourly']-100,additional_bps=a['additional_bps'])),True,csrf)
        amended=old.rpc(cur,'amend_period',args)
        assert amended['status']=='PERIOD_AMENDED'
        assert old.rpc(cur,'amend_period',args)==amended
        current=old.rpc(cur,'review_period',(w,p,None,None,False,csrf))
        assert current['review_sha256']==amended['review_sha256']!=previous['review_sha256']
        assert current['confirmed'] is False
        final=old.rpc(cur,'review_period',(w,p,'w13-confirm',current['review_sha256'],True,csrf))
        assert final['confirmed']
    current_draft=calculate(a,current,'b'*64)
    with psycopg.connect(fixture.root_dsn) as c:
        before,after=c.execute("SELECT before_values,after_values FROM naruv_draft.period_amendments WHERE worker_id=%s",(w,)).fetchone()
        assert before==previous and after==current
    kw=dict(previous=previous_draft,current=current_draft,old_pin=previous_draft['review_sha256'],new_pin=current_draft['review_sha256'],tenant=a['tenant'],worker=w,period=p,old_assessment='a'*64,new_assessment='b'*64,verifier=verify)
    result=compare(**kw)
    assert result['net_delta_krw']==current_draft['net_krw']-previous_draft['net_krw']<0
    assert result['issues']==['NEGATIVE_NET_DELTA_MANUAL_REVIEW'] and not result['recovery_authorized']
    bad=copy.deepcopy(current_draft);bad['gross_krw']+=1;bad['net_krw']+=1
    with pytest.raises(PayrollBlocked):compare(**dict(kw,current=bad))
    with old.business(fixture.TRADE_DSN) as (cur,csrf):
        with pytest.raises(psycopg.Error,match='HR_PERIOD_CONFIRMED'):
            old.rpc(cur,'amend_period',(w,p,'w13-after-confirm',current['review_sha256'],'policy',Jsonb(dict(revision='r3',hourly_krw=a['base_hourly'],additional_bps=a['additional_bps'])),True,csrf))
    print('WAVE13_REAL_PG_PRECONFIRM_AMENDMENT_AND_CORRECTION_PASS '+json.dumps({'net_delta_krw':result['net_delta_krw'],'postconfirm_mutation_blocked':True,'statutory_validated':False}))

@pytest.fixture(scope='module')
def digest_queue(queue_db):
    dsn,a,b=queue_db
    with psycopg.connect(dsn) as c:old.install(c,HERE.parent/'wave12-integrated'/'queue_result_digest_ci.sql','naruv.ocr_digest_ci')
    return queue_db

def form():
    values=dict(document_kind='견적서',counterparty_id='C001',document_date='2026-11-28',reference_number='Q001',subtotal='100000',vat='10000',gross_amount='110000')
    labels=['문서종류','거래처코드','작성일','문서번호','공급가액','부가세','합계금액']
    im=Image.new('RGB',(1200,800),'white');d=ImageDraw.Draw(im);font=ImageFont.truetype('/usr/share/fonts/truetype/nanum/NanumGothic.ttf',52);cells={}
    for i,(field,val) in enumerate(values.items()):
        y=30+i*105;d.rectangle((20,y,1170,y+92),outline='black',width=2);d.line((420,y,420,y+92),fill='black',width=2);d.text((40,y+14),labels[i],font=font,fill='black');d.text((450,y+14),val,font=font,fill='black');cells[field]=[430,y+4,1160,y+88]
    b=io.BytesIO();im.save(b,format='PNG')
    return b.getvalue(),dict(width=1200,height=800,cells=cells),values

def test_real_grid_queue_digest(digest_queue,tmp_path):
    root,a,b=digest_queue;qa=old.queue(a)
    raw,t,vals=form();h=sha(raw);key='tenant/ci-a/'+'7'*32
    tmp_path.chmod(0o700);fd=os.open(tmp_path,os.O_DIRECTORY|os.O_RDONLY)
    try:
        with FixtureStore(fd) as store:
            old.seed(tmp_path,'ci-a',key,raw)
            job,created=old.submit(qa,'ci-a',key,raw,'wave13-grid-01','png','ci-ua');assert created
            bs=BoundStore(store);q=BoundQueue(qa,lambda:psycopg.connect(a),bs)
            def parser(*,raw,registered,tenant,format,timeout):
                assert format=='png'
                return grid_process.review(raw,template=t,expected_pin=ocr_grid.pin(t),registered=registered,tenant=tenant,ack=ACK,timeout=30)
            # Fixture equality is not antivirus; the scanner case is separate.
            assert process_review_job(q,bs,ack=ACK,scan=lambda x:x==raw,parser=parser)=='NEEDS_REVIEW'
            with psycopg.connect(a) as c:result=read_bound(c.cursor(),store,tenant='ci-a',job_id=job)
            expected=review_document(tenant='ci-a',source_bytes=raw,registered_sha256=h,observations=[dict(field=k,value=ocr_grid.value(k,v),page=1) for k,v in vals.items()])
            assert result['review_sha256']==expected['review_sha256'] and result['field_count']==7 and result['template_sha256']==ocr_grid.pin(t)
            assert result['posting_authorized'] is False and result['network_fence']=='SOCKET_SYSCALL_DENIAL_ONLY'
            print('WAVE13_REAL_GRID_OCR_PG17_DIGEST_PASS')
    finally:os.close(fd)

def test_real_vendor_reject_forged_cvd(tmp_path):
    # Verify the actual installed C API is callable, not a missing-library false positive.
    import ctypes,ctypes.util
    lib=ctypes.CDLL(ctypes.util.find_library('clamav'))
    lib.cl_init.argtypes=[ctypes.c_uint];lib.cl_init.restype=ctypes.c_int
    assert lib.cl_init(0)==0
    lib.cl_cvdverify.argtypes=[ctypes.c_char_p];lib.cl_cvdverify.restype=ctypes.c_int
    fake=tmp_path/'daily.cvd'
    build=datetime.now(timezone.utc).replace(microsecond=0)
    fake.write_bytes(f'ClamAV-VDB:fixture:1:100:1:hash:signature:builder:{int(build.timestamp())}'.encode().ljust(512,b' ')+b'x'*512)
    assert lib.cl_cvdverify(bytes(fake))!=0 and scan.vendor_cvd_verify(fake) is False
    print('WAVE13_REAL_LIBCLAMAV_FORGED_CVD_REJECTED')

def test_release_actual_lab_cannot_substitute():
    # Real CI run identity is a lab artifact, not externally authorized evidence.
    now=datetime.now(timezone.utc);candidate=os.environ['REVIEW_SHA']
    r=dict(kind='hosted_auth_load',scope='DISPOSABLE_LOCAL',candidate_sha=candidate,environment='qa',observed_at=now.isoformat(),artifact_sha256=sha(os.environ['GITHUB_RUN_ID'].encode()),result='PASS')
    out=release.check(candidate_sha=candidate,environment='qa',expected_pins={'hosted_auth_load':release.sha(r)},receipts={'hosted_auth_load':r},now=now)
    assert out['status']=='BLOCKED' and out['findings']['hosted_auth_load']=='BLOCKED_SCOPE_OR_RESULT' and not out['release_authorized']
    assert len(out['findings'])==9
    print('WAVE13_LAB_RELEASE_EVIDENCE_REJECTED')
