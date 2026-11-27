"""Signed-byte to durable PostgreSQL review tests; only disposable CI DB."""
import hashlib
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import pytest
import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import naruv_future_receipt_review as v
from scripts import naruv_pg_signed_receipt_review as m

DSN="host=127.0.0.1 port=55439 dbname=postgres user=postgres password=synthetic_review_only connect_timeout=4"

@contextmanager
def connection(role=None):
    assert os.environ.get('GITHUB_ACTIONS')=='true'
    assert os.environ.get('GITHUB_REPOSITORY')=='guccizz1k/JARVIS-WORKS'
    assert os.environ.get('NARUV_SIGNED_PG17_CI')=='1'
    with psycopg.connect(DSN,autocommit=True) as c:
        assert c.info.server_version//10000==17
        c.execute("SET statement_timeout='15s'")
        c.execute("SET idle_in_transaction_session_timeout='20s'")
        if role:
            assert role in (m.REGISTRAR,m.CONSUMER)
            c.execute("SET ROLE "+role)
        yield c

@pytest.fixture(scope='module',autouse=True)
def schema():
    with connection() as c:
        assert c.execute("SELECT to_regnamespace(%s)",(m.SCHEMA,)).fetchone()==(None,)
        c.execute(m.DDL)
        try:
            yield
        finally:
            c.execute("DROP SCHEMA naruv_signed_receipt_ci CASCADE")
            c.execute("DROP ROLE naruv_signed_registrar_ci,naruv_signed_consumer_ci")

@pytest.fixture(autouse=True)
def reset(schema):
    with connection() as c:
        c.execute("TRUNCATE naruv_signed_receipt_ci.receipt,naruv_signed_receipt_ci.run,naruv_signed_receipt_ci.approval")

def fixture(tag='a'):
    k=Ed25519PrivateKey.generate()
    def digest(x):return hashlib.sha256(f'{tag}/{x}'.encode()).hexdigest()
    e={s:dict(scope=s,run_id=digest(s+'run')[:32],challenge=digest(s+'challenge'),
              manifest_sha256=digest('manifest'),reference_sha256=digest(s+'ref'),
              runner_commit=digest('runner')[:40],archives=sorted(digest(f'{s}/{j}') for j in range(11))) for s in v.SCOPES}
    doc=dict(expected=e,public_key=k.public_key().public_bytes_raw().hex(),start='2026-11-27T00:00:00Z',end='2026-11-27T01:00:00Z')
    def sign(p,key=k):return v.canonical(dict(payload=p,signature_hex=key.sign(v.DOMAIN+v.canonical(p)).hex()))
    r={s:sign(dict(e[s],version=4,started_at='2026-11-27T00:00:01Z',ended_at='2026-11-27T00:00:02Z',
                   results=[dict(archive_sha256=x,authenticated=True,restored=True,rows_match=True,catalog_match=True) for x in e[s]['archives']],
                   environment=dict.fromkeys(v.ENV,True),cleanup=dict.fromkeys(v.CLEANUP,True))) for s in v.SCOPES}
    return v.canonical(doc),r,sign

def register(raw):
    with connection(m.REGISTRAR) as c:return m.register(c,raw)

def status(pin):
    with connection(m.CONSUMER) as c:return m.inspect_status(c,pin)

def consume(pin,r):
    with connection(m.CONSUMER) as c:return m.consume(c,pin,r['legacy'],r['staged'])

def counts():
    with connection() as c:return tuple(c.execute("SELECT count(*) FROM naruv_signed_receipt_ci."+t).fetchone()[0] for t in ('approval','run','receipt'))

def test_signed_commit_and_replay():
    raw,r,_=fixture();pin=register(raw)
    assert status(pin)['state']=='REGISTERED'
    out=consume(pin,r)
    assert out['receipt_consumption']=='PASS_ATOMIC_PG17_REVIEW' and out['gate5']=='BLOCKED'
    assert not out['production_authorized'] and counts()==(1,2,2)
    assert status(pin)['receipt_sha256']=={s:hashlib.sha256(r[s]).hexdigest() for s in v.SCOPES}
    with pytest.raises(ValueError,match='UNREGISTERED_OR_CONSUMED'):consume(pin,r)
    assert counts()==(1,2,2)

@pytest.mark.parametrize('attack',['foreign_key','changed_binding','second_signature','outside_window','same_receipt','cleanup_false','duplicate_json'])
def test_invalid_signed_pair_never_consumes(attack):
    raw,r,sign=fixture();pin=register(raw)
    p=v.decode(r['staged'])['payload']
    if attack=='foreign_key':r['staged']=sign(p,Ed25519PrivateKey.generate())
    elif attack=='changed_binding':
        p['challenge']='f'*64;r['staged']=sign(p)
    elif attack=='second_signature':r['staged']=v.canonical(dict(payload=p,signature_hex='0'*128))
    elif attack=='outside_window':
        p['ended_at']='2026-11-28T00:00:00Z';r['staged']=sign(p)
    elif attack=='same_receipt':r['staged']=r['legacy']
    elif attack=='cleanup_false':
        p['cleanup']['plaintext_workspace_removed']=False;r['staged']=sign(p)
    else:r['staged']=b'{"payload":{},"payload":{}}'
    with pytest.raises(ValueError):consume(pin,r)
    assert counts()==(1,2,0) and status(pin)['state']=='REGISTERED'

def test_registration_collision_atomic():
    raw,_,_=fixture();register(raw)
    with pytest.raises(ValueError,match='UNIQUE_VIOLATION'):register(raw)
    raw2,_,_=fixture('b');d=v.decode(raw2)
    d['expected']['staged']['challenge']=v.decode(raw)['expected']['legacy']['challenge']
    with pytest.raises(ValueError,match='UNIQUE_VIOLATION'):register(v.canonical(d))
    assert counts()==(1,2,0)

def test_unregistered_and_noncanonical():
    raw,r,_=fixture();pin,_=m.parse_approval(raw)
    assert status(pin)['state']=='NOT_REGISTERED'
    with pytest.raises(ValueError,match='UNREGISTERED_OR_CONSUMED'):consume(pin,r)
    with pytest.raises(ValueError,match='APPROVAL_NOT_CANONICAL'):register(b' '+raw)
    assert counts()==(0,0,0)

def test_8_concurrent_verified_consumers():
    raw,r,_=fixture();pin=register(raw)
    barrier=threading.Barrier(8,timeout=10)
    def worker(_):
        with connection(m.CONSUMER) as c:
            barrier.wait()
            try:m.consume(c,pin,r['legacy'],r['staged']);return 'PASS'
            except ValueError as exc:
                assert str(exc)=='UNREGISTERED_OR_CONSUMED'
                return str(exc)
    with ThreadPoolExecutor(max_workers=8) as pool:out=list(pool.map(worker,range(8)))
    assert out.count('PASS')==1 and out.count('UNREGISTERED_OR_CONSUMED')==7
    assert counts()==(1,2,2) and status(pin)['state']=='CONSUMED'

def test_second_digest_failure_and_retry():
    raw,r,_=fixture();pin=register(raw)
    other,_,_=fixture('b');other_pin=register(other)
    # Deliberately inject a conflicting hash under another synthetic approval.
    with connection() as c:
        c.execute("INSERT INTO naruv_signed_receipt_ci.receipt VALUES(%s,%s,'legacy')",(hashlib.sha256(r['staged']).hexdigest(),other_pin))
    with pytest.raises(ValueError,match='UNIQUE_VIOLATION'):consume(pin,r)
    assert status(pin)['state']=='REGISTERED' and counts()==(2,4,1)
    with connection() as c:c.execute("DELETE FROM naruv_signed_receipt_ci.receipt WHERE pin=%s",(other_pin,))
    assert consume(pin,r)['receipt_consumption']=='PASS_ATOMIC_PG17_REVIEW'

def test_role_and_transaction_boundaries():
    raw,r,_=fixture();pin=register(raw)
    with connection(m.CONSUMER) as c:
        with pytest.raises(ValueError,match='ROLE_DENIED'):m.register(c,raw)
        for q in ("UPDATE naruv_signed_receipt_ci.approval SET document=document",
                  "DELETE FROM naruv_signed_receipt_ci.run",
                  "INSERT INTO naruv_signed_receipt_ci.approval(pin,document) VALUES('x','x')"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege) as ex:c.execute(q)
            assert ex.value.sqlstate=='42501'
        with c.transaction():
            with pytest.raises(ValueError,match='TRANSACTION_BOUNDARY'):m.consume(c,pin,r['legacy'],r['staged'])
    with connection(m.REGISTRAR) as c:
        with pytest.raises(ValueError,match='ROLE_DENIED'):m.consume(c,pin,r['legacy'],r['staged'])
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("UPDATE naruv_signed_receipt_ci.approval SET consumed=true")
    assert status(pin)['state']=='REGISTERED'

def test_inconsistent_pair_and_policy_tamper():
    raw,r,_=fixture();pin=register(raw)
    with connection() as c:
        c.execute("UPDATE naruv_signed_receipt_ci.approval SET consumed=true WHERE pin=%s",(pin,))
    with pytest.raises(ValueError,match='LEDGER_PAIR_INCONSISTENT'):status(pin)
    with connection() as c:
        d=v.decode(raw);d['end']='2026-11-27T02:00:00Z'
        c.execute("UPDATE naruv_signed_receipt_ci.approval SET consumed=false,document=%s WHERE pin=%s",(v.canonical(d),pin))
    with pytest.raises(ValueError,match='APPROVAL_PIN_MISMATCH'):consume(pin,r)
    assert counts()==(1,2,0)
