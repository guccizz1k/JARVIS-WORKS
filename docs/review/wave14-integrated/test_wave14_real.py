"""First real PG17 integration of post-confirmation proposals. Synthetic only."""
import copy,hashlib,json,os
from datetime import datetime,timezone,timedelta
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest,psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.naruv_kr_payroll_review import fixed_week_wage_statement_draft_2026 as statement,fixed_week_monthly_payroll_review_2026 as monthly,verify_fixed_week_statement_source_2026 as verify,PayrollBlocked
from app.naruv_payroll_draft import draft_gross
from scripts import ci_v90_postgres_browser as fixture
import test_wave11_db as old
import postconfirm_adjustment as adj
import adjustment_view as view
import independent_receipts as evidence
from release_evidence import REQUIRED
from review_gates import Blocked
from provider_metrics import classify

pg=old.pg
paid=old.paid
receipt=old.receipt
HERE=Path(__file__).resolve().parent

@pytest.fixture(scope='module')
def adjustment(pg,paid,receipt):
    with psycopg.connect(fixture.root_dsn) as c:old.install(c,HERE/'postconfirm_adjustment_ci.sql','naruv.adjustment_ci')
    a,original,confirmation=paid
    w,p=a['worker'],a['period']
    with old.business(fixture.TRADE_DSN) as (cur,csrf):
        r=adj.load_original(cur,tenant=a['tenant'],worker=w,period=p,confirmation_pin=confirmation,receipt_pin=receipt,csrf=csrf)
        snap=old.rpc(cur,'review_period',(w,p,None,None,False,csrf))
    # Synthetic newly assessed rate; do not alter the confirmed original DB source.
    b=copy.deepcopy(a);b['base_hourly']-=100;b['policy_revision']='r2';b['completeness_assessment_sha256']='b'*64
    b['expected_draft_sha256']=draft_gross(tenant=b['tenant'],worker=w,period=p,policy_revision=b['policy_revision'],hourly_krw=b['base_hourly'],minutes_by_day=b['minutes_by_day'],multiplier_bps={'regular':10000,'additional':b['additional_bps']})['draft_sha256']
    base={k:v for k,v in b.items() if k not in ('payment_date','completeness_assessment_sha256','expected_monthly_review_sha256')}
    b['expected_monthly_review_sha256']=monthly(**base)['review_sha256']
    proposed=statement(**b)
    args=dict(tenant=a['tenant'],worker=w,period=p,original=original,old_receipt=r,old_receipt_pin=receipt,proposed=proposed,new_assessment_pin=b['completeness_assessment_sha256'],new_review_pin=proposed['review_sha256'],reason_pin='c'*64,verifier=verify)
    record=adj.proposal(**args)
    assert record['comparison']['net_delta_krw']==proposed['net_krw']-original['net_krw']<0
    assert not record['recovery_authorized'] and not record['payment_authorized']
    bad=copy.deepcopy(proposed);bad['gross_krw']+=1;bad['net_krw']+=1
    with pytest.raises(PayrollBlocked):adj.proposal(**dict(args,proposed=bad))
    return record,snap,confirmation

def write(dsn,record,confirmation,rid='wave14-adjustment',who='A'):
    with old.business(dsn,who) as (cur,csrf):return adj.persist(cur,request_id=rid,confirmation_pin=confirmation,csrf=csrf,record=record)

def read(dsn,record,rid='wave14-adjustment',who='A',pin=None):
    with old.business(dsn,who) as (cur,csrf):return adj.read_proposal(cur,tenant=record['tenant'],worker=record['worker'],period=record['period'],request_id=rid,proposal_pin=record['proposal_sha256'] if pin is None else pin,csrf=csrf)

def test_pg17_actual_adjustment_persistence(pg,adjustment):
    r,snapshot,confirmation=adjustment
    with pytest.raises(psycopg.errors.InsufficientPrivilege,match='HR_EVIDENCE_PUBLISHER_REQUIRED'):write(fixture.TRADE_DSN,r,confirmation)
    class Rollback(Exception):pass
    with pytest.raises(Rollback):
        with old.business(pg) as (cur,csrf):
            assert adj.persist(cur,request_id='wave14-adjustment',confirmation_pin=confirmation,csrf=csrf,record=r)['created']
            raise Rollback()
    with psycopg.connect(fixture.root_dsn) as c:assert c.execute('SELECT count(*) FROM naruv_draft.postconfirm_adjustment_proposals').fetchone()==(0,)
    with ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(lambda _:write(pg,r,confirmation),range(8)))
    assert sum(x['created'] for x in results)==1 and all(x['proposal_sha256']==r['proposal_sha256'] for x in results)
    assert read(fixture.TRADE_DSN,r)==r
    with pytest.raises(psycopg.Error,match='ADJUSTMENT_CONFLICT'):write(pg,r,confirmation,rid='wave14-other-id')
    with pytest.raises(psycopg.Error,match='ADJUSTMENT_NOT_FOUND'):read(fixture.TRADE_DSN,r,who='B')
    with pytest.raises(psycopg.Error,match='ADJUSTMENT_NOT_FOUND'):read(fixture.TRADE_DSN,r,pin='0'*64)
    with old.business(fixture.TRADE_DSN) as (cur,csrf):
        assert old.rpc(cur,'review_period',(r['worker'],r['period'],None,None,False,csrf))==snapshot
    with psycopg.connect(fixture.root_dsn) as c:
        assert c.execute('SELECT count(*) FROM naruv_draft.postconfirm_adjustment_proposals').fetchone()==(1,)
        assert c.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='naruv_draft.postconfirm_adjustment_proposals'::regclass").fetchone()==(True,True)
    print('WAVE14_REAL_PG17_ADJUSTMENT_ROLLBACK_CONCURRENCY_PASS')

def test_pg17_readonly_view_and_revocation(pg,adjustment):
    r,snapshot,confirmation=adjustment
    actual=read(fixture.TRADE_DSN,r)
    html=view.render(actual)
    assert '환수 금지' in html and '정정 차액' in html and '<button' not in html and '<form' not in html and '<script' not in html
    assert r['worker'] not in html and format(r['comparison']['net_delta_krw'],',') in html
    tampered=copy.deepcopy(actual);tampered['comparison']['net_delta_krw']+=1
    with pytest.raises(Blocked,match='VIEW_PIN'):view.render(tampered)
    with old.business(fixture.TRADE_DSN) as (cur,csrf):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):cur.execute('SELECT * FROM naruv_draft.postconfirm_adjustment_proposals')
    with psycopg.connect(fixture.root_dsn) as c:
        c.execute('SET LOCAL ROLE naruv_native_owner')
        c.execute("SELECT set_config('jw.session_hash',%s,true)",(old.sha(fixture.TOKENS['B'].encode()),))
        assert c.execute('SELECT count(*) FROM naruv_draft.postconfirm_adjustment_proposals').fetchone()==(0,)
    with psycopg.connect(fixture.root_dsn) as c:
        with pytest.raises(psycopg.Error,match='NARUV_IMMUTABLE'):c.execute('UPDATE naruv_draft.postconfirm_adjustment_proposals SET proposal_sha256=proposal_sha256')
    with psycopg.connect(fixture.root_dsn) as c:c.execute('REVOKE naruv_hr_evidence_publisher FROM wave11_publisher')
    with pytest.raises(psycopg.errors.InsufficientPrivilege):write(pg,r,confirmation)
    assert read(fixture.TRADE_DSN,r)==r
    print('WAVE14_PG17_ADJUSTMENT_VIEW_AUTHORITY_PASS')

def test_signed_release_evidence_and_provider_boundary():
    now=datetime.now(timezone.utc);candidate=os.environ['REVIEW_SHA'];keys={k:Ed25519PrivateKey.generate() for k in REQUIRED}
    pub={k:v.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw) for k,v in keys.items()}
    policy=dict(candidate_sha=candidate,tenant='ci-a',requirements={k:dict(scope=s,environment='synthetic-review',signer_pin=evidence.sha(pub[k]),artifact_pin=evidence.sha(k.encode()),max_age_hours=1) for k,s in REQUIRED.items()})
    p=evidence.sha(evidence.canonical(policy));receipts={}
    for k,r in policy['requirements'].items():
        claim=dict(kind=k,scope=r['scope'],environment=r['environment'],candidate_sha=candidate,tenant='ci-a',artifact_sha256=r['artifact_pin'],observed_at=now.isoformat(),result='PASS')
        receipts[k]=dict(claim=claim,public_key=pub[k],signature=keys[k].sign(b'NARUV_EXTERNAL_EVIDENCE_V1\0'+bytes.fromhex(p)+evidence.canonical(claim)))
    result=evidence.assess(policy=policy,policy_pin=p,receipts=receipts,now=now)
    assert result['status']=='SIGNED_ASSERTIONS_REVIEW_REQUIRED' and all(v=='SIGNED_ASSERTION_ONLY' for v in result['findings'].values()) and not result['release_authorized']
    bad=copy.deepcopy(receipts);bad['offline_key_access']['claim']['tenant']='ci-b'
    assert evidence.assess(policy=policy,policy_pin=p,receipts=bad,now=now)['findings']['offline_key_access']=='BLOCKED_INVALID'
    assert evidence.assess(policy=policy,policy_pin=p,receipts=receipts,now=now+timedelta(hours=2))['status']=='BLOCKED'
    empty=dict(resourceId='fixture',timeRange=dict(start=(now-timedelta(minutes=1)).isoformat(),end=now.isoformat()),metrics=[dict(type='http_request_count',data=[]),dict(type='http_latency',data=[])])
    assert classify(empty,service='fixture',expected_start=now-timedelta(minutes=1),expected_end=now)['status']=='BLOCKED_EMPTY_METRIC_SERIES'
    print('WAVE14_SYNTHETIC_SIGNED_EVIDENCE_AND_PROVIDER_BOUNDARY_PASS')
