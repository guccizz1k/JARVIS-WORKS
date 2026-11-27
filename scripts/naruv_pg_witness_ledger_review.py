"""New isolated evidence store. Only trusted verifier service can append a pair.
No private signing key required by admission/readback. No production migration.
The legacy V4 store remains separate and is NOT evidence of witness admission.
Database owner and compromised verifier service are outside this trust boundary.
"""
import os
import psycopg
from scripts import naruv_future_receipt_review as v
from scripts import naruv_pg_signed_receipt_review as old
from scripts import naruv_receipt_witness_bridge_review as bridge

SCHEMA='naruv_witness_ledger_ci'
REGISTRAR='naruv_witness_registrar_ci'
VERIFIER='naruv_witness_verifier_ci'
READER='naruv_witness_reader_ci'
DDL="""
CREATE ROLE naruv_witness_registrar_ci NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_witness_verifier_ci NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_witness_reader_ci NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE SCHEMA naruv_witness_ledger_ci;
REVOKE ALL ON SCHEMA naruv_witness_ledger_ci FROM PUBLIC;
CREATE TABLE naruv_witness_ledger_ci.approval(
 pin text PRIMARY KEY CHECK(pin ~ '^[0-9a-f]{64}$'),
 document bytea NOT NULL CHECK(octet_length(document) BETWEEN 1 AND 65536),
 policy bytea NOT NULL CHECK(octet_length(policy) BETWEEN 1 AND 65536),
 policy_pin text NOT NULL CHECK(policy_pin=encode(sha256(policy),'hex'))
);
CREATE TABLE naruv_witness_ledger_ci.run(
 run_id text PRIMARY KEY CHECK(run_id ~ '^[0-9a-f]{32}$'),
 challenge text UNIQUE NOT NULL CHECK(challenge ~ '^[0-9a-f]{64}$'),
 pin text NOT NULL REFERENCES naruv_witness_ledger_ci.approval(pin),
 scope text NOT NULL CHECK(scope IN ('legacy','staged')),
 UNIQUE(pin,scope)
);
CREATE TABLE naruv_witness_ledger_ci.evidence(
 pin text PRIMARY KEY REFERENCES naruv_witness_ledger_ci.approval(pin),
 legacy_observation bytea NOT NULL CHECK(octet_length(legacy_observation) BETWEEN 1 AND 65536),
 staged_observation bytea NOT NULL CHECK(octet_length(staged_observation) BETWEEN 1 AND 65536),
 legacy_witness bytea NOT NULL CHECK(octet_length(legacy_witness) BETWEEN 1 AND 65536),
 staged_witness bytea NOT NULL CHECK(octet_length(staged_witness) BETWEEN 1 AND 65536),
 legacy_receipt bytea NOT NULL CHECK(octet_length(legacy_receipt) BETWEEN 1 AND 65536),
 staged_receipt bytea NOT NULL CHECK(octet_length(staged_receipt) BETWEEN 1 AND 65536),
 CHECK(legacy_receipt<>staged_receipt)
);
REVOKE ALL ON ALL TABLES IN SCHEMA naruv_witness_ledger_ci FROM PUBLIC;
GRANT USAGE ON SCHEMA naruv_witness_ledger_ci TO naruv_witness_registrar_ci,naruv_witness_verifier_ci,naruv_witness_reader_ci;
GRANT SELECT ON ALL TABLES IN SCHEMA naruv_witness_ledger_ci TO naruv_witness_registrar_ci,naruv_witness_verifier_ci,naruv_witness_reader_ci;
GRANT INSERT ON naruv_witness_ledger_ci.approval,naruv_witness_ledger_ci.run TO naruv_witness_registrar_ci;
GRANT INSERT ON naruv_witness_ledger_ci.evidence TO naruv_witness_verifier_ci;
"""

def guard(c,role):
    v.need(os.environ.get('NARUV_WITNESS_LEDGER_CI')=='1','WITNESS_LEDGER_CI_ONLY')
    old.guard(c,role)

def _policy(raw,policy,policy_pin):
    pin,doc=old.parse_approval(raw)
    p=bridge.read_canonical(policy)
    v.exact(p,{'approval_pin','witness_public_key'},'WITNESS_POLICY_FIELDS')
    v.need(v.hexval(policy_pin) and bridge.digest(policy)==policy_pin,'WITNESS_POLICY_PIN')
    v.need(p['approval_pin']==pin,'WITNESS_APPROVAL_PIN')
    v.need(v.hexval(p['witness_public_key']) and p['witness_public_key']!=doc['public_key'],'WITNESS_KEY_SEPARATION')
    return pin,doc

def register(c,raw,policy):
    guard(c,REGISTRAR)
    policy_pin=os.environ.get('NARUV_EXPECTED_WITNESS_POLICY_SHA256')
    pin,doc=_policy(raw,policy,policy_pin)
    phase='statement'
    try:
        with c.transaction():
            c.execute('INSERT INTO naruv_witness_ledger_ci.approval VALUES(%s,%s,%s,%s)',(pin,raw,policy,policy_pin))
            for s in v.SCOPES:
                b=doc['expected'][s]
                c.execute('INSERT INTO naruv_witness_ledger_ci.run VALUES(%s,%s,%s,%s)',(b['run_id'],b['challenge'],pin,s))
            phase='commit'
    except psycopg.Error as exc:
        raise old._error(exc,phase) from None
    return pin

def _approval(c,pin):
    row=c.execute('SELECT document,policy,policy_pin FROM naruv_witness_ledger_ci.approval WHERE pin=%s',(pin,)).fetchone()
    if row is None:return None
    raw,policy,policy_pin=bytes(row[0]),bytes(row[1]),row[2]
    actual,doc=_policy(raw,policy,policy_pin)
    v.need(actual==pin,'APPROVAL_PIN_MISMATCH')
    runs=c.execute('SELECT scope,run_id,challenge FROM naruv_witness_ledger_ci.run WHERE pin=%s ORDER BY scope',(pin,)).fetchall()
    v.need(runs==[(s,doc['expected'][s]['run_id'],doc['expected'][s]['challenge']) for s in v.SCOPES],'LEDGER_BINDING_INCONSISTENT')
    return raw,policy,policy_pin

def _snapshot(items):
    v.exact(items,set(v.SCOPES),'EVIDENCE_SCOPES')
    out={s:items[s] for s in v.SCOPES}
    v.need(all(type(x) is bytes and 0<len(x)<=65536 for x in out.values()),'EVIDENCE_SIZE')
    return out

def _proof(a,obs,wit,reports):
    raw,policy,policy_pin=a
    return bridge.verify_existing_pair(raw,policy,obs,wit,reports,expected_policy_pin=policy_pin)

def consume(c,pin,observations,witnesses,reports):
    guard(c,VERIFIER)
    v.need(v.hexval(pin),'APPROVAL_PIN')
    obs,wit,reports=map(_snapshot,(observations,witnesses,reports))
    phase='statement'
    try:
        with c.transaction():
            a=_approval(c,pin)
            v.need(a is not None,'NOT_REGISTERED')
            result=_proof(a,obs,wit,reports)
            # One row holds all six immutable byte documents; no partial pair exists.
            row=c.execute('INSERT INTO naruv_witness_ledger_ci.evidence VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(pin) DO NOTHING RETURNING pin',
                          (pin,obs['legacy'],obs['staged'],wit['legacy'],wit['staged'],reports['legacy'],reports['staged'])).fetchone()
            v.need(row==(pin,),'ALREADY_CONSUMED')
            phase='commit'
    except psycopg.Error as exc:
        raise old._error(exc,phase) from None
    return dict(result,approval_pin=pin,receipt_consumption='PASS_WITNESS_LEDGER_REVIEW')

def inspect_status(c,pin):
    guard(c,READER)
    v.need(v.hexval(pin),'APPROVAL_PIN')
    try:
        with c.transaction():
            a=_approval(c,pin)
            if a is None:return {'state':'NOT_REGISTERED','gate5':'BLOCKED'}
            row=c.execute('SELECT legacy_observation,staged_observation,legacy_witness,staged_witness,legacy_receipt,staged_receipt FROM naruv_witness_ledger_ci.evidence WHERE pin=%s',(pin,)).fetchone()
            if row is None:return {'state':'REGISTERED','gate5':'BLOCKED'}
            obs,wit,reports=({s:bytes(row[i+j]) for j,s in enumerate(v.SCOPES)} for i in (0,2,4))
            proof=_proof(a,obs,wit,reports)
    except psycopg.Error as exc:
        raise old._error(exc,'readback') from None
    return dict(proof,state='CONSUMED',new_consumption=False,approval_pin=pin)
