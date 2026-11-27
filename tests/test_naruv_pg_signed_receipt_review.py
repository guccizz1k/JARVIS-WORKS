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


# The bridge tests use synthetic witness claims, not actual host attestation.
from scripts import naruv_receipt_witness_bridge_review as bridge
from scripts import naruv_runner_evidence_review as capture

def witness_fixture(monkeypatch):
    raw,_,_=fixture()
    doc=v.decode(raw)
    signer=Ed25519PrivateKey.generate()
    witness=Ed25519PrivateKey.generate()
    doc['public_key']=signer.public_key().public_bytes_raw().hex()
    raw=v.canonical(doc)
    pin,_=m.parse_approval(raw)
    policy=v.canonical(dict(approval_pin=pin,witness_public_key=witness.public_key().public_bytes_raw().hex()))
    monkeypatch.setenv('NARUV_WITNESS_BRIDGE_CI','1')
    monkeypatch.setenv('NARUV_EXPECTED_WITNESS_POLICY_SHA256',bridge.digest(policy))
    observations={}
    witnesses={}
    for s in v.SCOPES:
        b=doc['expected'][s]
        report=dict(owner_site_restore='PASS_ELEVEN_OWNER_SITE_CIPHERS',
                    normalized_catalog_comparison='PASS_11_SCOPED_CATALOG_CHECKPOINTS',
                    normalized_archive_comparison='PASS_11_ARCHIVE_CHECKPOINTS',
                    disposable_pg17_removed='PASS',review_cleanup_absence_verified=True,
                    b2_staged_scope_bound=True,owner_scope_pin_checked=True,
                    decrypted_dump_written_to_host=False,verified_provider_cipher_count=11,
                    restored_pg17_archive_count=11,restored_65_table_archive_count=11,restore_failures=0)
        observations[s]=v.canonical(capture.finish(v.canonical(b),b['archives'],report))
        w=dict(version=1,approval_pin=pin,binding_sha256=bridge.digest(v.canonical(b)),
               observation_sha256=bridge.digest(observations[s]),started_at='2026-11-27T00:00:01Z',
               ended_at='2026-11-27T00:00:02Z',environment=dict.fromkeys(v.ENV,True),cleanup=dict.fromkeys(v.CLEANUP,True))
        witnesses[s]=v.canonical(dict(payload=w,signature_hex=witness.sign(bridge.DOMAIN+v.canonical(w)).hex()))
    return raw,policy,observations,witnesses,signer,witness

def test_witness_bridge_atomic_pg17(monkeypatch):
    raw,policy,obs,wit,signer,_=witness_fixture(monkeypatch)
    pin=register(raw)
    pair,proof=bridge.build_pair(raw,policy,obs,wit,signer)
    assert proof['witness_claims']=='PASS_SIGNATURE_AND_BINDING_ONLY'
    assert proof['actual_host_isolation']=='NOT_ATTESTED' and proof['independent_witness_control']=='NOT_ATTESTED'
    assert proof['witness_sha256']=={s:bridge.digest(wit[s]) for s in v.SCOPES}
    result=consume(pin,pair)
    assert result['receipt_consumption']=='PASS_ATOMIC_PG17_REVIEW'
    assert result['gate5']=='BLOCKED' and counts()==(1,2,2)
    assert status(pin)['receipt_sha256']=={s:bridge.digest(pair[s]) for s in v.SCOPES}
    with pytest.raises(ValueError,match='UNREGISTERED_OR_CONSUMED'):
        consume(pin,pair)
    assert counts()==(1,2,2)

@pytest.mark.parametrize('bad,code',[
 ('missing','WITNESS_SCOPES'),('wrong_key','WITNESS_SIGNATURE_INVALID'),
 ('swap','WITNESS_BINDING'),('different_observation','WITNESS_BINDING'),
 ('false_flag','WITNESS_STATUS_NOT_PASS'),('late','WITNESS_WINDOW'),
 ('forged_observation','OBSERVATION_STATUS'),('wrong_policy','WITNESS_POLICY_PIN'),
 ('same_key','WITNESS_KEY_SEPARATION'),('wrong_signer','RECEIPT_SIGNER_KEY'),
 ('bad_archive','OBSERVATION_ARCHIVES'),('wrong_approval','WITNESS_APPROVAL_PIN'),
 ('disabled','WITNESS_BRIDGE_CI_ONLY')])
def test_witness_bridge_rejects_invalid_claims(monkeypatch,bad,code):
    raw,policy,obs,wit,signer,witness=witness_fixture(monkeypatch)
    pin=register(raw)
    d=v.decode(wit['staged'])['payload']
    def sign_witness(key=witness):
        wit['staged']=v.canonical(dict(payload=d,signature_hex=key.sign(bridge.DOMAIN+v.canonical(d)).hex()))
    def policy_change(**changes):
        p=v.decode(policy);p.update(changes)
        return v.canonical(p)
    if bad=='missing':wit.pop('staged')
    elif bad=='wrong_key':sign_witness(Ed25519PrivateKey.generate())
    elif bad=='swap':wit['staged']=wit['legacy']
    elif bad=='different_observation':
        d['observation_sha256']='0'*64;sign_witness()
    elif bad=='false_flag':
        d['environment']['swap_disabled']=False;sign_witness()
    elif bad=='late':
        d['ended_at']='2026-11-28T00:00:00Z';sign_witness()
    elif bad=='forged_observation':
        o=v.decode(obs['staged']);o['host_isolation']='PASS';obs['staged']=v.canonical(o)
    elif bad=='wrong_policy':policy=policy_change(witness_public_key='1'*64)
    elif bad=='same_key':
        policy=policy_change(witness_public_key=signer.public_key().public_bytes_raw().hex())
        monkeypatch.setenv('NARUV_EXPECTED_WITNESS_POLICY_SHA256',bridge.digest(policy))
    elif bad=='wrong_signer':signer=Ed25519PrivateKey.generate()
    elif bad=='bad_archive':
        o=v.decode(obs['staged']);o['archive_results'][0]['restored']=False;obs['staged']=v.canonical(o)
    elif bad=='wrong_approval':
        policy=policy_change(approval_pin='f'*64)
        monkeypatch.setenv('NARUV_EXPECTED_WITNESS_POLICY_SHA256',bridge.digest(policy))
    elif bad=='disabled':monkeypatch.delenv('NARUV_WITNESS_BRIDGE_CI')
    with pytest.raises(ValueError,match=code):
        bridge.build_pair(raw,policy,obs,wit,signer)
    assert status(pin)['state']=='REGISTERED' and counts()==(1,2,0)
