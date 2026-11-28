"""New real PG17 approval boundary and authenticated read-only API; synthetic only."""
import copy,os,secrets,json
from datetime import datetime,timezone,timedelta
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest,psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import test_wave11_db as old
import test_wave14_real as prior
from scripts import ci_v90_postgres_browser as fixture
from app import naruv_draft_review as drafts,naruv_native_write_review as write,naruv_native_file_preview as preview,pg_v90_integrated_entry as v90
import correction_approval as ca
import reviewer_issuer as issuer
import adjustment_api as api
import scanner_readiness as scan
import hosted_preflight as host
from review_gates import Blocked
from postconfirm_adjustment import persist

pg=old.pg
paid=old.paid
receipt=old.receipt
adjustment=prior.adjustment
HERE=Path(__file__).resolve().parent
RID='wave15-review'

@pytest.fixture(scope='module')
def reviewer(pg,adjustment):
    password=secrets.token_urlsafe(36)
    with psycopg.connect(fixture.root_dsn) as c:
        old.install(c,HERE/'approval_boundary_ci.sql','naruv.adjustment_approval_ci')
        c.execute(sql.SQL("CREATE ROLE wave15_reviewer LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD {}").format(sql.Literal(password)))
        c.execute("GRANT jw_app_dev TO wave15_reviewer WITH INHERIT FALSE, SET TRUE")
        c.execute("GRANT naruv_adjustment_reviewer TO wave15_reviewer WITH INHERIT FALSE, SET FALSE")
    return make_conninfo(fixture.root_dsn,user='wave15_reviewer',password=password)

@pytest.fixture(scope='module')
def signed(reviewer,adjustment):
    r,snap,conf=adjustment;now=datetime.now(timezone.utc)
    key=Ed25519PrivateKey.generate();pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    publisher=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    p=dict(tenant=r['tenant'],candidate_sha=os.environ['REVIEW_SHA'],reviewer_pin=ca.hash_bytes(pub),publisher_pin=ca.hash_bytes(publisher),max_age_seconds=300)
    pin=ca.hash_bytes(ca.canonical(p))
    claim=dict(tenant=r['tenant'],worker=r['worker'],period=r['period'],candidate_sha=p['candidate_sha'],request_id=RID,confirmation_sha256=conf,proposal_sha256=r['proposal_sha256'],assessment_sha256=r['new_assessment_sha256'],reason_sha256=r['reason_sha256'],decision='REVIEW_PROPOSAL_ONLY',issued_at=(now-timedelta(seconds=1)).isoformat(),expires_at=(now+timedelta(minutes=4)).isoformat())
    sig=key.sign(b'NARUV_CORRECTION_APPROVAL_V1\0'+bytes.fromhex(pin)+ca.canonical(claim))
    return dict(record=r,confirmation_pin=conf,request_id=RID,policy=p,policy_pin=pin,claim=claim,public_key=pub,signature=sig,now=now)

def publish(dsn,signed):
    with old.business(dsn) as (cur,csrf):
        return ca.publish_review(cur,csrf=csrf,**dict(signed,now=datetime.now(timezone.utc)))

def assert_review(dsn,signed,who='A'):
    with old.business(dsn,who) as (cur,csrf):return issuer.issue(cur,csrf=csrf,**signed)

def direct(dsn,signed,func='propose_postconfirm_adjustment',rid=None,record=None):
    r=signed['record'] if record is None else record
    with old.business(dsn) as (cur,csrf):
        return old.rpc(cur,func,(r['worker'],r['period'],rid or signed['request_id'],signed['confirmation_pin'],r['original_receipt_sha256'],r['proposal_sha256'],psycopg.types.json.Jsonb(r),csrf))

@pytest.fixture(scope='module')
def committed(pg,reviewer,signed,adjustment):
    # The previous app-only signature wrapper can no longer bypass the independent DB assertion.
    with pytest.raises(psycopg.errors.InsufficientPrivilege,match='ADJUSTMENT_APPROVAL_REQUIRED'):publish(pg,signed)
    with pytest.raises(psycopg.errors.InsufficientPrivilege,match='ADJUSTMENT_APPROVAL_REQUIRED'):direct(pg,signed)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):direct(pg,signed,func='internal_postconfirm_adjustment_v14')
    with pytest.raises(psycopg.errors.InsufficientPrivilege,match='ADJUSTMENT_INDEPENDENT_REVIEWER_REQUIRED'):assert_review(pg,signed)
    with pytest.raises(psycopg.errors.InsufficientPrivilege,match='ADJUSTMENT_SEPARATE_PUBLISHER_REQUIRED'):direct(reviewer,signed)
    with pytest.raises(Blocked,match='CORRECTION_APPROVAL_SIGNATURE'):assert_review(reviewer,dict(signed,signature=b'x'*64))
    with psycopg.connect(fixture.root_dsn) as c:assert c.execute('SELECT count(*) FROM naruv_draft.adjustment_approval_assertions').fetchone()==(0,)
    with pytest.raises(psycopg.Error,match='ADJUSTMENT_APPROVAL_INPUT'):assert_review(reviewer,signed,who='B')
    a=assert_review(reviewer,signed);assert a['created'] and not a['production_authorized']
    assert not assert_review(reviewer,signed)['created']
    # Exact whole-record binding, not just the client-supplied proposal hash.
    changed=copy.deepcopy(signed['record']);changed['comparison']['net_delta_krw']+=1
    with pytest.raises(psycopg.errors.InsufficientPrivilege,match='ADJUSTMENT_APPROVAL_REQUIRED'):direct(pg,signed,record=changed)
    with pytest.raises(psycopg.errors.InsufficientPrivilege,match='ADJUSTMENT_APPROVAL_REQUIRED'):direct(pg,signed,rid='another-id')
    class Rollback(Exception):pass
    with pytest.raises(Rollback):
        with old.business(pg) as (cur,csrf):
            assert ca.publish_review(cur,csrf=csrf,**dict(signed,now=datetime.now(timezone.utc)))['receipt']['created']
            raise Rollback()
    with psycopg.connect(fixture.root_dsn) as c:assert c.execute('SELECT count(*) FROM naruv_draft.postconfirm_adjustment_proposals').fetchone()==(0,)
    with ThreadPoolExecutor(max_workers=4) as pool:rows=list(pool.map(lambda _:publish(pg,signed),range(8)))
    assert sum(x['receipt']['created'] for x in rows)==1 and all(not x['production_authorized'] for x in rows)
    return signed['record']

def test_pg17_approval_isolation_and_immutable(pg,reviewer,signed,committed,adjustment):
    r=committed;_,snapshot,conf=adjustment
    with psycopg.connect(fixture.root_dsn) as c:
        assert c.execute('SELECT count(*) FROM naruv_draft.adjustment_approval_assertions').fetchone()==(1,)
        assert c.execute('SELECT count(*) FROM naruv_draft.postconfirm_adjustment_proposals').fetchone()==(1,)
        assert c.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='naruv_draft.adjustment_approval_assertions'::regclass").fetchone()==(True,True)
    for dsn in (pg,reviewer,fixture.TRADE_DSN):
        with old.business(dsn) as (cur,csrf):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):cur.execute('SELECT * FROM naruv_draft.adjustment_approval_assertions')
    with psycopg.connect(fixture.root_dsn) as c:
        with pytest.raises(psycopg.Error,match='NARUV_IMMUTABLE'):c.execute('UPDATE naruv_draft.adjustment_approval_assertions SET expires_at=expires_at')
    with old.business(fixture.TRADE_DSN) as (cur,csrf):assert old.rpc(cur,'review_period',(r['worker'],r['period'],None,None,False,csrf))==snapshot
    with psycopg.connect(fixture.root_dsn) as c:c.execute('GRANT naruv_hr_evidence_publisher TO wave15_reviewer WITH INHERIT FALSE, SET FALSE')
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege,match='ADJUSTMENT_INDEPENDENT_REVIEWER_REQUIRED'):assert_review(reviewer,signed)
        with pytest.raises(psycopg.errors.InsufficientPrivilege,match='ADJUSTMENT_SEPARATE_PUBLISHER_REQUIRED'):direct(reviewer,signed)
        with pytest.raises(psycopg.errors.InsufficientPrivilege,match='ADJUSTMENT_APPROVAL_REQUIRED'):direct(pg,signed)
    finally:
        with psycopg.connect(fixture.root_dsn) as c:c.execute('REVOKE naruv_hr_evidence_publisher FROM wave15_reviewer')
    with psycopg.connect(fixture.root_dsn) as c:c.execute('REVOKE naruv_adjustment_reviewer FROM wave15_reviewer')
    with pytest.raises(psycopg.errors.InsufficientPrivilege,match='ADJUSTMENT_APPROVAL_REQUIRED'):direct(pg,signed)
    assert prior.read(fixture.TRADE_DSN,r,rid=RID)==r
    print('WAVE15_PG17_APPROVAL_REQUIRED_SEPARATION_AND_REVOCATION_PASS')

def test_real_authenticated_adjustment_api(committed):
    from scripts.naruv_native_write_review_ci import NativeWrite
    r=committed
    os.environ.update({f'NARUV_{k}_REVIEW':'ISOLATED_SYNTHETIC_ONLY' for k in ('INVENTORY','TRADE','FINANCE','ACCOUNTING','BUNDLE','QUOTE_BUNDLE','PRODUCTION','VALUATION','DRAFT','HR')})
    os.environ[drafts.KR_FLAG]='DISPOSABLE_FIXTURE_ONLY'
    os.environ['NARUV_ADJUSTMENT_API_CI']='DISPOSABLE_FIXTURE_ONLY'
    v90._origins()
    def resolve_pin(**kw):
        return r['proposal_sha256'] if kw==dict(tenant=r['tenant'],worker=r['worker'],period=r['period'],request_id=RID) else None
    NativeWrite.app.include_router(api.create_router(prefix=drafts.PREFIX,original_enabled=drafts.kr_enabled,request_scope=write._request,auth=write._auth,validated_cursor=v90._pg_validated_cursor,verify_identity=preview._verify_identity,resolve_pin=resolve_pin,db_error_type=psycopg.Error,db_error=write._db_error))
    url=drafts.PREFIX+'/payroll/'+r['worker']+'/'+r['period']+'/adjustment/'+RID+'/review'
    def request(who='A',extra=None,body=b'',suffix=''):
        with TestClient(NativeWrite.app,base_url='https://testserver') as client:
            if who is not None:client.cookies.set('__Host-jw_session',fixture.TOKENS[who])
            headers={'origin':'https://testserver','x-csrf-token':fixture.CSRF[who or 'A']}
            headers.update(extra or {})
            return client.post(url+suffix,headers=headers,content=body)
    response=request();assert response.status_code==200,response.text
    assert '환수 금지' in response.text and '<button' not in response.text and r['worker'] not in response.text and response.headers['cache-control']=='no-store' and response.headers['x-frame-options']=='DENY'
    for kwargs,status in [(dict(who=None),401),(dict(who='B'),404),(dict(extra={'origin':'https://other.invalid'}),403),(dict(extra={'x-csrf-token':'bad'}),403),(dict(body=b'{}'),422),(dict(suffix='?pin=bad'),422)]:
        resp=request(**kwargs);assert resp.status_code==status,(kwargs,resp.status_code,resp.text)
        assert resp.headers['cache-control']=='no-store' and '환수 금지' not in resp.text
    os.environ.pop('NARUV_ADJUSTMENT_API_CI')
    assert request().status_code==404
    print('WAVE15_REAL_PG17_AUTHENTICATED_READONLY_ADJUSTMENT_API_PASS')

def test_historical_scanner_and_hosted_preflight():
    now=datetime.fromisoformat('2026-11-28T13:56:21+00:00')
    r=scan.assess(header=dict(version=28194,build_at='2026-11-25T06:26:59+00:00',observed_at='2026-11-28T13:56:20.288516+00:00'),available=list(scan.NAMES),cert_count=1,modern_checks={},now=now)
    assert {'DAILY_BUILD_OLDER_THAN_48H','DETACHED_OR_DATABASE_FILES_MISSING','DETACHED_SIGNATURE_CHECK_NOT_COMPLETE'}<=set(r['reasons']) and not r['scan_authorized']
    plan=dict(sha=os.environ['REVIEW_SHA'],service='srv-qa',deployment='dep-qa',origin='https://synthetic-qa.onrender.com',fixture_sha256='a'*64,requests=24,concurrency=4,scope='ISOLATED_SYNTHETIC_QA')
    obs={k:plan[k] for k in ('sha','service','deployment','origin','fixture_sha256')};obs.update(live=True,isolated_qa=False,auth_fixture_verified=False,observed_at=now)
    out=host.assess(plan=plan,expected_pin=host.pin(plan),observed=obs,now=now)
    assert out['status']=='BLOCKED' and not out['network_executed']
    print('WAVE15_HISTORICAL_SCANNER_AND_HOSTED_NEGATIVE_CONTROL_PASS')
