"""New isolated PG17 receipt and OCR queue integration; never use real data."""
import copy, hashlib, importlib.util, io, json, os, secrets, time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
import pytest
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
from PIL import Image, ImageDraw, ImageFont
from app.naruv_kr_payroll_review import fixed_week_wage_statement_draft_2026 as statement, fixed_week_monthly_payroll_review_2026 as monthly, verify_fixed_week_statement_source_2026 as verify, PayrollBlocked
from app.naruv_payroll_draft import draft_gross
from app.pg_v112_ocr_queue import PgOcrQueue
from scripts import ci_v90_postgres_browser as fixture
from pg_receipt_adapter import read_review
from queue_bridge import process_review_job, ACK
from queue_result import read_committed
from local_queue_store import FixtureStore, filename
from korean_observations import observations
from pinned.naruv_document_review import review_document
from review_gates import Blocked

ROOT=Path.cwd()
CANDIDATE=Path(__file__).resolve().parent

def sha(raw):return hashlib.sha256(raw).hexdigest()

@contextmanager
def business(dsn,who='A'):
    with psycopg.connect(dsn,connect_timeout=5) as c:
        with c.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout='8s'")
            cur.execute("SET LOCAL lock_timeout='4s'")
            cur.execute("SET LOCAL ROLE jw_app_dev")
            cur.execute("SELECT set_config('jw.session_hash',%s,true)",(sha(fixture.TOKENS[who].encode()),))
            yield cur,fixture.CSRF[who]

def rpc(cur,func,args):
    cur.execute(sql.SQL("SELECT naruv_draft.{}({})").format(sql.Identifier(func),sql.SQL(',').join([sql.Placeholder()]*len(args))),args)
    return cur.fetchone()[0]

def install(c,name,setting):
    c.execute("SELECT set_config(%s,'DISPOSABLE_ONLY',true)",(setting,))
    c.execute(name.read_text())

def paid_fixture():
    spec=importlib.util.spec_from_file_location('paid_fixture',Path(os.environ['WAVE2_DIR'])/'test_paid_statement.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    a=mod.PaidStatement().fixture()
    a.update(tenant='ci-a',worker='wave11-worker')
    a['expected_draft_sha256']=draft_gross(tenant=a['tenant'],worker=a['worker'],period=a['period'],policy_revision=a['policy_revision'],hourly_krw=a['base_hourly'],minutes_by_day=a['minutes_by_day'],multiplier_bps={'regular':10000,'additional':a['additional_bps']})['draft_sha256']
    base={k:v for k,v in a.items() if k not in ('payment_date','completeness_assessment_sha256','expected_monthly_review_sha256')}
    a['expected_monthly_review_sha256']=monthly(**base)['review_sha256']
    return a

@pytest.fixture(scope='module')
def pg():
    # Local import prevents pytest from auto-collecting predecessor unittest classes.
    from scripts.naruv_native_write_review_ci import NativeWrite
    NativeWrite.setUpClass()
    with psycopg.connect(fixture.root_dsn) as c:
        install(c,ROOT/'db/review/naruv_draft_ci.sql','naruv.draft_ci')
        install(c,ROOT/'db/review/naruv_hr_ci.sql','naruv.hr_ci')
        install(c,CANDIDATE/'payroll_receipts_ci.sql','naruv.hr_evidence_ci')
        password=secrets.token_urlsafe(36)
        c.execute(sql.SQL("CREATE ROLE wave11_publisher LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD {}").format(sql.Literal(password)))
        c.execute("GRANT jw_app_dev TO wave11_publisher WITH INHERIT FALSE, SET TRUE")
        c.execute("GRANT naruv_hr_evidence_publisher TO wave11_publisher WITH INHERIT FALSE, SET FALSE")
    return make_conninfo(fixture.root_dsn,user='wave11_publisher',password=password)

@pytest.fixture(scope='module')
def paid(pg):
    a=paid_fixture();w,p=a['worker'],a['period']
    with business(fixture.TRADE_DSN) as (c,csrf):
        rpc(c,'setup_worker',(w,None,'w11-reg',None,None,None,True,csrf))
        rpc(c,'setup_worker',(w,p,'w11-period',a['policy_revision'],a['base_hourly'],a['additional_bps'],True,csrf))
        for i,d in enumerate(a['minutes_by_day']):
            rpc(c,'admit_attendance',(w,p,f'w11-day-{i}',d['date'],d['regular'],d['additional'],True,csrf))
        before=rpc(c,'review_period',(w,p,None,None,False,csrf))
        confirmed=rpc(c,'review_period',(w,p,'w11-confirm',before['review_sha256'],True,csrf))
        assert confirmed['confirmed'] and confirmed['review_sha256']==before['review_sha256']
        c.execute("SELECT * FROM naruv_draft.pay_source(%s,%s,%s)",(w,p,csrf))
        revision,rate,bps,days=c.fetchone()
        assert (revision,rate,bps,days)==(a['policy_revision'],a['base_hourly'],a['additional_bps'],a['minutes_by_day'])
    draft=statement(**a)
    return a,draft,confirmed['review_sha256']

def publish(dsn,paid,*,who='A',change=None):
    a,draft,pin=paid
    args=[a['worker'],a['period'],pin,a['completeness_assessment_sha256'],draft['review_sha256'],draft['source_review_sha256']]
    if change is not None:args[change[0]]=change[1]
    with business(dsn,who) as (c,csrf):return rpc(c,'payroll_review_receipt',tuple(args)+(csrf,))

@pytest.fixture(scope='module')
def receipt(pg,paid):
    # Normal business credential must not publish, even with a valid session.
    with pytest.raises(psycopg.errors.InsufficientPrivilege,match='HR_EVIDENCE_PUBLISHER_REQUIRED'):
        publish(fixture.TRADE_DSN,paid)
    # Rollback a valid publication before the concurrent committed retries.
    class IntentionalRollback(Exception):pass
    a,draft,pin=paid
    with pytest.raises(IntentionalRollback):
        with business(pg) as (cur,csrf):
            first=rpc(cur,'payroll_review_receipt',(a['worker'],a['period'],pin,a['completeness_assessment_sha256'],draft['review_sha256'],draft['source_review_sha256'],csrf))
            assert first['created']
            raise IntentionalRollback()
    with psycopg.connect(fixture.root_dsn) as conn:
        assert conn.execute('SELECT count(*) FROM naruv_draft.payroll_review_receipts').fetchone()==(0,)
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows=list(pool.map(lambda _:publish(pg,paid),range(8)))
    assert sum(x['created'] for x in rows)==1 and len({x['receipt_sha256'] for x in rows})==1
    assert all(x['status']=='REVIEW_RECEIPT_ONLY' and x['payment_authorized'] is False and x['statutory_validated'] is False and x['production_authorized'] is False for x in rows)
    with pytest.raises(psycopg.Error,match='HR_EVIDENCE_CONFLICT'):publish(pg,paid,change=(3,'e'*64))
    with pytest.raises(psycopg.Error,match='HR_EVIDENCE_CONFIRMATION'):publish(pg,paid,change=(2,'0'*64))
    with psycopg.connect(fixture.root_dsn) as c:
        assert c.execute('SELECT count(*) FROM naruv_draft.payroll_review_receipts').fetchone()==(1,)
    return rows[0]['receipt_sha256']

def load_receipt(paid,receipt,*,who='A',pin=None,draft=None):
    a,d,conf=paid
    with business(fixture.TRADE_DSN,who) as (c,csrf):
        return read_review(c,tenant='ci-a',worker=a['worker'],period=a['period'],confirmation_pin=conf,receipt_pin=receipt if pin is None else pin,csrf=csrf,draft=d if draft is None else draft,verifier=verify)

def test_payroll_real_persistence_and_tamper(pg,paid,receipt):
    r=load_receipt(paid,receipt)
    assert r['source_integrity_verified'] and not r['payment_authorized'] and not r['statutory_validated']
    with pytest.raises(psycopg.Error,match='HR_EVIDENCE_NOT_FOUND_OR_CHANGED'):load_receipt(paid,receipt,pin='0'*64)
    bad=copy.deepcopy(paid[1]);bad['gross_krw']+=1;bad['net_krw']+=1
    with pytest.raises(PayrollBlocked):load_receipt(paid,receipt,draft=bad)
    with pytest.raises(psycopg.Error,match='HR_NOT_FOUND'):load_receipt(paid,receipt,who='B')
    with psycopg.connect(fixture.root_dsn) as c:
        assert c.execute('SELECT count(*) FROM naruv_draft.payroll_review_receipts').fetchone()==(1,)
    print('WAVE11_PG17_RECEIPT_CONCURRENCY_AND_INTEGRITY_PASS')

def test_payroll_effective_roles(pg,paid,receipt):
    with business(fixture.TRADE_DSN) as (c,csrf):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute('SELECT * FROM naruv_draft.payroll_review_receipts')
    with psycopg.connect(pg) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):c.execute('SET ROLE naruv_native_owner')
    with psycopg.connect(fixture.root_dsn) as c:
        assert c.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='naruv_draft.payroll_review_receipts'::regclass").fetchone()==(True,True)
    with psycopg.connect(fixture.root_dsn) as c:
        c.execute('SET LOCAL ROLE naruv_native_owner')
        c.execute("SELECT set_config('jw.session_hash',%s,true)",(sha(fixture.TOKENS['B'].encode()),))
        assert c.execute('SELECT count(*) FROM naruv_draft.payroll_review_receipts').fetchone()==(0,)
    with psycopg.connect(fixture.root_dsn) as c:
        with pytest.raises(psycopg.Error,match='NARUV_IMMUTABLE'):
            c.execute('UPDATE naruv_draft.payroll_review_receipts SET receipt_sha256=receipt_sha256')
    # Verify the original publisher capability can be withdrawn without deleting receipts.
    with psycopg.connect(fixture.root_dsn) as c:c.execute('REVOKE naruv_hr_evidence_publisher FROM wave11_publisher')
    with pytest.raises(psycopg.errors.InsufficientPrivilege,match='HR_EVIDENCE_PUBLISHER_REQUIRED'):publish(pg,paid)
    assert load_receipt(paid,receipt)['source_integrity_verified']
    print('WAVE11_PG17_EFFECTIVE_RECEIPT_ROLE_BOUNDARIES_PASS')

def test_bounded_authenticated_db_read_load(paid,receipt):
    def one(_):
        start=time.perf_counter()
        r=load_receipt(paid,receipt)
        assert r['source_integrity_verified'] and r['payment_authorized'] is False
        return (time.perf_counter()-start)*1000
    start=time.perf_counter()
    with ThreadPoolExecutor(max_workers=4) as pool:ms=list(pool.map(one,range(24)))
    elapsed=time.perf_counter()-start
    ms.sort()
    print('WAVE11_ISOLATED_AUTHENTICATED_DB_LOAD '+json.dumps({'requests':len(ms),'concurrency':4,'p95_ms':round(ms[22],3),'max_ms':round(ms[-1],3),'rps':round(len(ms)/elapsed,3),'hosted_sla_verified':False}))
    assert len(ms)==24

@pytest.fixture(scope='module')
def queue_db(pg):
    name='jw_v112_ci_'+secrets.token_hex(6)
    with psycopg.connect(fixture.root_dsn,autocommit=True) as root:
        root.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
        passwords={}
        for role in ('wave11_queue_a','wave11_queue_b'):
            passwords[role]=secrets.token_urlsafe(36)
            root.execute(sql.SQL('CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD {}').format(sql.Identifier(role),sql.Literal(passwords[role])))
    dsn=make_conninfo(fixture.root_dsn,dbname=name)
    with psycopg.connect(dsn) as c:install(c,CANDIDATE/'queue_schema_ci.sql','naruv.ocr_queue_ci')
    a,b=[make_conninfo(dsn,user=role,password=passwords[role]) for role in ('wave11_queue_a','wave11_queue_b')]
    return dsn,a,b

def queue(dsn):return PgOcrQueue(lambda:psycopg.connect(dsn,connect_timeout=5))

TEXT=['문서종류: 견적서','거래처코드: C001','작성일: 2026-11-28','문서번호: Q001','공급가액: 100,000 원','부가세: 10,000 원','합계금액: 110,000 원']
def image(lines,fmt):
    im=Image.new('RGB',(1500,800),'white')
    draw=ImageDraw.Draw(im);font=ImageFont.truetype('/usr/share/fonts/truetype/nanum/NanumGothic.ttf',52)
    for i,line in enumerate(lines):draw.text((60,40+i*100),line,fill='black',font=font)
    b=io.BytesIO();im.save(b,format=fmt);return b.getvalue()

def seed(root,tenant,key,raw):
    p=root/filename(tenant,key,False)
    p.write_bytes(raw);p.chmod(0o600)

def submit(q,tenant,key,raw,rid,fmt,actor):
    return q.submit(org_id=tenant,object_key=key,filename='sample.'+fmt,sha256=sha(raw),request_id=rid,actor_id=actor)

def test_pg17_ocr_queue_actual_worker_and_lease(queue_db,tmp_path):
    root,a,b=queue_db;qa,qb=queue(a),queue(b)
    tmp_path.chmod(0o700);fd=os.open(tmp_path,os.O_DIRECTORY|os.O_RDONLY)
    try:
        with FixtureStore(fd) as store:
            actual={}
            for tenant,actor,dsn,q,fmt,code,keypart in (('ci-a','ci-ua',a,qa,'PNG','C001','a'),('ci-b','ci-ub',b,qb,'JPEG','C002','b')):
                lines=TEXT[:];lines[1]='거래처코드: '+code
                raw=image(lines,fmt);key='tenant/'+tenant+'/'+keypart*32
                seed(tmp_path,tenant,key,raw)
                rid='w11-request-'+keypart
                j,created=submit(q,tenant,key,raw,rid,fmt.lower(),actor)
                assert created and submit(q,tenant,key,raw,rid,fmt.lower(),actor)==(j,False)
                with pytest.raises(ValueError):submit(q,tenant,key,raw+b'x',rid,fmt.lower(),actor)
                # The scan callback is a synthetic fixture predicate, not antivirus.
                assert process_review_job(q,store,ack=ACK,scan=lambda x:x==raw)=='NEEDS_REVIEW'
                with psycopg.connect(dsn) as c:
                    r=read_committed(c.cursor(),store,tenant=tenant,job_id=j)
                expected=review_document(tenant=tenant,source_bytes=raw,registered_sha256=sha(raw),observations=observations(['\n'.join(lines)]))
                assert r['review_sha256']==expected['review_sha256'] or r.get('id_preview',{}).get('review_sha256')==expected['review_sha256'],r
                assert r['network_fence']=='SOCKET_SYSCALL_DENIAL_ONLY' and r['requires_human_review'] and not r['posting_authorized']
                actual[tenant]=(j,raw,key,r)
            j,raw,key,r=actual['ci-a']
            other=actual['ci-b'][0]
            with psycopg.connect(a) as c:
                assert c.execute('SELECT count(*) FROM jw_dev.ocr_jobs_v112 WHERE id=%s',(other,)).fetchone()==(0,)
                with pytest.raises(Blocked,match='QUEUE_RESULT_NOT_COMMITTED'):read_committed(c.cursor(),store,tenant='ci-b',job_id=other)
            with pytest.raises(psycopg.Error):submit(qa,'ci-a',key,raw,'w11-wrong-actor','png','ci-ub')
            with pytest.raises(psycopg.Error):submit(qa,'ci-b','tenant/ci-b/'+'d'*32,raw,'w11-cross-write','png','ci-ub')
            stale,created=submit(qa,'ci-a',key,raw,'w11-stale-lease','png','ci-ua');assert created
            first=qa.claim();assert first.id==stale
            oldkey=f'tenant/ci-a/ocr-result/{first.id}/{first.lease_token}'
            store.write_proposal('ci-a',oldkey,r)
            with psycopg.connect(root) as c:c.execute("UPDATE jw_dev.ocr_jobs_v112 SET lease_until=clock_timestamp()-interval '1 second' WHERE id=%s",(stale,))
            second=qa.claim();assert second.id==stale and second.lease_token!=first.lease_token
            assert qa.complete(first,result_key=oldkey) is False
            with psycopg.connect(a) as c:
                with pytest.raises(Blocked,match='QUEUE_RESULT_NOT_COMMITTED'):read_committed(c.cursor(),store,tenant='ci-a',job_id=stale)
            newkey=f'tenant/ci-a/ocr-result/{second.id}/{second.lease_token}'
            store.write_proposal('ci-a',newkey,r)
            assert qa.complete(second,result_key=newkey) is True
            with psycopg.connect(a) as c:
                assert read_committed(c.cursor(),store,tenant='ci-a',job_id=stale)==r
                assert c.execute('SELECT result_key FROM jw_dev.ocr_jobs_v112 WHERE id=%s',(stale,)).fetchone()==(newkey,)
            assert (tmp_path/filename('ci-a',oldkey,True)).is_file() # preserve orphan, no deletion
            assert qb.claim() is None
            with psycopg.connect(root) as c:
                c.execute('SET LOCAL ROLE wave11_ocr_owner')
                assert c.execute('SELECT count(*) FROM jw_dev.ocr_jobs_v112').fetchone()==(0,)
            print('WAVE11_REAL_PG17_OCR_QUEUE_AND_STALE_RESULT_FENCE_PASS')
    finally:os.close(fd)
