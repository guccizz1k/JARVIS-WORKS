"""Disposable PG17 only: separate witness admission and retained proof."""
import os
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import threading
import pytest
import psycopg
from scripts import naruv_future_receipt_review as v
from scripts import naruv_pg_signed_receipt_review as old
from scripts import naruv_receipt_witness_bridge_review as bridge
from scripts import naruv_pg_witness_ledger_review as m
from tests.test_naruv_pg_signed_receipt_review import witness_fixture

DSN="host=127.0.0.1 port=55439 dbname=postgres user=postgres password=synthetic_review_only connect_timeout=4"

@contextmanager
def conn(role=None):
    assert os.environ.get('GITHUB_ACTIONS')=='true'
    assert os.environ.get('GITHUB_REPOSITORY')=='guccizz1k/JARVIS-WORKS'
    assert os.environ.get('NARUV_WITNESS_LEDGER_CI')=='1'
    with psycopg.connect(DSN,autocommit=True) as c:
        assert c.info.server_version//10000==17
        c.execute("SET statement_timeout='15s'")
        if role:
            assert role in (m.REGISTRAR,m.VERIFIER,m.READER,old.REGISTRAR,old.CONSUMER)
            c.execute("SET ROLE "+role)
        yield c

@pytest.fixture(scope='module',autouse=True)
def schema():
    with conn() as c:
        assert c.execute("SELECT to_regnamespace(%s)",(m.SCHEMA,)).fetchone()==(None,)
        assert c.execute("SELECT to_regnamespace(%s)",(old.SCHEMA,)).fetchone()==(None,)
        with c.transaction():
            c.execute(old.DDL)
            c.execute(m.DDL)
        try:
            yield
        finally:
            c.execute("DROP SCHEMA naruv_witness_ledger_ci,naruv_signed_receipt_ci CASCADE")
            c.execute("DROP ROLE naruv_witness_registrar_ci,naruv_witness_verifier_ci,naruv_witness_reader_ci,naruv_signed_registrar_ci,naruv_signed_consumer_ci")

@pytest.fixture(autouse=True)
def reset(schema):
    with conn() as c:
        c.execute("TRUNCATE naruv_witness_ledger_ci.evidence,naruv_witness_ledger_ci.run,naruv_witness_ledger_ci.approval,naruv_signed_receipt_ci.receipt,naruv_signed_receipt_ci.run,naruv_signed_receipt_ci.approval")

def bundle(monkeypatch):
    raw,policy,obs,wit,signer,witness=witness_fixture(monkeypatch)
    reports,_=bridge.build_pair(raw,policy,obs,wit,signer)
    return raw,policy,obs,wit,reports,signer,witness

def register(raw,policy):
    with conn(m.REGISTRAR) as c:return m.register(c,raw,policy)

def consume(pin,obs,wit,r):
    with conn(m.VERIFIER) as c:return m.consume(c,pin,obs,wit,r)

def status(pin):
    with conn(m.READER) as c:return m.inspect_status(c,pin)

def counts():
    with conn() as c:return tuple(c.execute('SELECT count(*) FROM naruv_witness_ledger_ci.'+t).fetchone()[0] for t in ('approval','run','evidence'))

def test_exact_retention_and_replay(monkeypatch):
    raw,policy,obs,wit,r,_,_=bundle(monkeypatch)
    pin=register(raw,policy)
    assert status(pin)['state']=='REGISTERED'
    result=consume(pin,obs,wit,r)
    assert result['receipt_consumption']=='PASS_WITNESS_LEDGER_REVIEW'
    assert result['gate5']=='BLOCKED' and result['actual_host_isolation']=='NOT_ATTESTED'
    assert counts()==(1,2,1)
    # Public verification of stored evidence does not require the current signing policy environment pin.
    monkeypatch.delenv('NARUV_EXPECTED_WITNESS_POLICY_SHA256')
    assert status(pin)['state']=='CONSUMED'
    assert status(pin)['witness_sha256']=={s:bridge.digest(wit[s]) for s in v.SCOPES}
    assert status(pin)['receipt_sha256']=={s:bridge.digest(r[s]) for s in v.SCOPES}
    with pytest.raises(ValueError,match='ALREADY_CONSUMED'):consume(pin,obs,wit,r)
    with conn() as c:
        row=c.execute('SELECT legacy_observation,staged_observation,legacy_witness,staged_witness,legacy_receipt,staged_receipt FROM naruv_witness_ledger_ci.evidence WHERE pin=%s',(pin,)).fetchone()
        assert tuple(map(bytes,row))==tuple(d[s] for d in (obs,wit,r) for s in v.SCOPES)

@pytest.mark.parametrize('bad,code',[
    ('missing','EVIDENCE_SCOPES'),('swap','WITNESS_BINDING'),
    ('wrong_signature','SIGNATURE_INVALID'),('signed_time_change','RECEIPT_WITNESS_PAYLOAD_MISMATCH'),
    ('observation_change','OBSERVATION_ARCHIVES'),('noncanonical','NONCANONICAL_EVIDENCE')])
def test_invalid_bundle_is_never_persisted(monkeypatch,bad,code):
    raw,policy,obs,wit,r,signer,_=bundle(monkeypatch)
    pin=register(raw,policy)
    if bad=='missing':wit.pop('staged')
    elif bad=='swap':wit['staged']=wit['legacy']
    elif bad=='wrong_signature':
        d=v.decode(r['staged']);d['signature_hex']='0'*128;r['staged']=v.canonical(d)
    elif bad=='signed_time_change':
        p=v.decode(r['staged'])['payload'];p['ended_at']='2026-11-27T00:00:03Z'
        r['staged']=v.canonical(dict(payload=p,signature_hex=signer.sign(v.DOMAIN+v.canonical(p)).hex()))
    elif bad=='observation_change':
        d=v.decode(obs['staged']);d['archive_results'][0]['rows_match']=False;obs['staged']=v.canonical(d)
    else:r['staged']=b' '+r['staged']
    with pytest.raises(ValueError,match=code):consume(pin,obs,wit,r)
    assert counts()==(1,2,0) and status(pin)['state']=='REGISTERED'

def test_legacy_path_cannot_authorize_new_ledger(monkeypatch):
    raw,policy,obs,wit,r,_,_=bundle(monkeypatch)
    pin=register(raw,policy)
    with conn(old.REGISTRAR) as c:assert old.register(c,raw)==pin
    with conn(old.CONSUMER) as c:
        assert old.consume(c,pin,r['legacy'],r['staged'])['receipt_consumption']=='PASS_ATOMIC_PG17_REVIEW'
        with pytest.raises(ValueError,match='ROLE_DENIED'):m.consume(c,pin,obs,wit,r)
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as ex:
            c.execute('SELECT * FROM naruv_witness_ledger_ci.evidence')
        assert ex.value.sqlstate=='42501'
    assert status(pin)['state']=='REGISTERED' and counts()==(1,2,0)

def test_acl_append_only(monkeypatch):
    raw,policy,obs,wit,r,_,_=bundle(monkeypatch)
    pin=register(raw,policy)
    for role in (m.READER,m.REGISTRAR):
        with conn(role) as c:
            with pytest.raises(ValueError,match='ROLE_DENIED'):m.consume(c,pin,obs,wit,r)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute('INSERT INTO naruv_witness_ledger_ci.evidence SELECT * FROM naruv_witness_ledger_ci.evidence')
    consume(pin,obs,wit,r)
    with conn(m.VERIFIER) as c:
        for q in ('UPDATE naruv_witness_ledger_ci.evidence SET legacy_receipt=legacy_receipt',
                  'DELETE FROM naruv_witness_ledger_ci.evidence',
                  'TRUNCATE naruv_witness_ledger_ci.evidence',
                  'UPDATE naruv_witness_ledger_ci.approval SET policy=policy',
                  'DELETE FROM naruv_witness_ledger_ci.run'):
            with pytest.raises(psycopg.errors.InsufficientPrivilege) as ex:c.execute(q)
            assert ex.value.sqlstate=='42501'
    assert status(pin)['state']=='CONSUMED'

def test_concurrent_bundle_once(monkeypatch):
    raw,policy,obs,wit,r,_,_=bundle(monkeypatch)
    pin=register(raw,policy)
    barrier=threading.Barrier(8,timeout=10)
    def worker(_):
        barrier.wait()
        try:consume(pin,obs,wit,r);return 'PASS'
        except ValueError as exc:
            assert str(exc)=='ALREADY_CONSUMED'
            return str(exc)
    with ThreadPoolExecutor(max_workers=8) as pool:out=list(pool.map(worker,range(8)))
    assert out.count('PASS')==1 and out.count('ALREADY_CONSUMED')==7
    assert counts()==(1,2,1) and status(pin)['state']=='CONSUMED'

def test_duplicate_registration_and_rollback(monkeypatch):
    raw,policy,_,_,_,_,_=bundle(monkeypatch)
    pin=register(raw,policy)
    with pytest.raises(ValueError,match='UNIQUE_VIOLATION'):register(raw,policy)
    changed=v.decode(raw);changed['end']='2026-11-27T02:00:00Z'
    raw2=v.canonical(changed)
    p=v.decode(policy);p['approval_pin']=old.parse_approval(raw2)[0];p2=v.canonical(p)
    monkeypatch.setenv('NARUV_EXPECTED_WITNESS_POLICY_SHA256',bridge.digest(p2))
    with pytest.raises(ValueError,match='UNIQUE_VIOLATION'):register(raw2,p2)
    assert counts()==(1,2,0) and status(pin)['state']=='REGISTERED'

def test_readback_detects_privileged_mutation(monkeypatch):
    raw,policy,obs,wit,r,_,_=bundle(monkeypatch)
    pin=register(raw,policy);consume(pin,obs,wit,r)
    with conn() as c:
        c.execute('UPDATE naruv_witness_ledger_ci.evidence SET staged_witness=legacy_witness WHERE pin=%s',(pin,))
    with pytest.raises(ValueError,match='WITNESS_BINDING'):status(pin)
