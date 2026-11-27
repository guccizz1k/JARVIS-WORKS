"""Synthetic PostgreSQL review adapter, NOT a production migration or attestation.
Registration is trusted-operator-only. Consumption accepts immutable signed bytes
and an existing approval pin, never a caller-supplied signing key or policy.
Database administrator compromise/rollback and independent signer custody are out of scope.
"""
import hashlib
import os
import re
import psycopg
from psycopg.pq import TransactionStatus
from scripts import naruv_future_receipt_review as v
from scripts.naruv_pg_error_policy_review import classify

SCHEMA = "naruv_signed_receipt_ci"
REGISTRAR = "naruv_signed_registrar_ci"
CONSUMER = "naruv_signed_consumer_ci"
DDL = """
CREATE ROLE naruv_signed_registrar_ci NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE naruv_signed_consumer_ci NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE SCHEMA naruv_signed_receipt_ci;
REVOKE ALL ON SCHEMA naruv_signed_receipt_ci FROM PUBLIC;
CREATE TABLE naruv_signed_receipt_ci.approval (
 pin text PRIMARY KEY CHECK(pin ~ '^[0-9a-f]{64}$'),
 document bytea NOT NULL CHECK(octet_length(document) BETWEEN 1 AND 65536),
 consumed boolean NOT NULL DEFAULT false
);
CREATE TABLE naruv_signed_receipt_ci.run (
 run_id text PRIMARY KEY CHECK(run_id ~ '^[0-9a-f]{32}$'),
 challenge text NOT NULL UNIQUE CHECK(challenge ~ '^[0-9a-f]{64}$'),
 scope text NOT NULL CHECK(scope IN ('legacy','staged')),
 pin text NOT NULL REFERENCES naruv_signed_receipt_ci.approval(pin),
 UNIQUE(pin,scope)
);
CREATE TABLE naruv_signed_receipt_ci.receipt (
 digest text PRIMARY KEY CHECK(digest ~ '^[0-9a-f]{64}$'),
 pin text NOT NULL,
 scope text NOT NULL,
 FOREIGN KEY(pin,scope) REFERENCES naruv_signed_receipt_ci.run(pin,scope),
 UNIQUE(pin,scope)
);
REVOKE ALL ON ALL TABLES IN SCHEMA naruv_signed_receipt_ci FROM PUBLIC;
GRANT USAGE ON SCHEMA naruv_signed_receipt_ci TO naruv_signed_registrar_ci,naruv_signed_consumer_ci;
GRANT SELECT ON ALL TABLES IN SCHEMA naruv_signed_receipt_ci TO naruv_signed_registrar_ci,naruv_signed_consumer_ci;
GRANT INSERT(pin,document) ON naruv_signed_receipt_ci.approval TO naruv_signed_registrar_ci;
GRANT INSERT ON naruv_signed_receipt_ci.run TO naruv_signed_registrar_ci;
GRANT INSERT ON naruv_signed_receipt_ci.receipt TO naruv_signed_consumer_ci;
GRANT UPDATE(consumed) ON naruv_signed_receipt_ci.approval TO naruv_signed_consumer_ci;
"""

def guard(c, role):
    v.need(os.environ.get('GITHUB_ACTIONS')=='true' and
           os.environ.get('GITHUB_REPOSITORY')=='guccizz1k/JARVIS-WORKS' and
           os.environ.get('NARUV_SIGNED_PG17_CI')=='1','CI_ONLY')
    v.need(c.info.host=='127.0.0.1' and c.info.port==55439 and
           c.info.dbname=='postgres' and c.info.user=='postgres' and
           c.info.server_version//10000==17,'DISPOSABLE_PG17_REQUIRED')
    v.need(c.autocommit and c.info.transaction_status==TransactionStatus.IDLE,'TRANSACTION_BOUNDARY')
    v.need(c.execute('SELECT current_user').fetchone()==(role,),'ROLE_DENIED')

def parse_approval(raw):
    doc=v.decode(raw)
    v.exact(doc,{'expected','public_key','start','end'},'APPROVAL_FIELDS')
    v.need(v.canonical(doc)==raw,'APPROVAL_NOT_CANONICAL')
    v.exact(doc['expected'],set(v.SCOPES),'EXPECTED_SCOPES')
    a,b=(v.binding(doc['expected'][s]) for s in v.SCOPES)
    v.need(a['scope']=='legacy' and b['scope']=='staged','EXPECTED_SCOPE')
    v.need(all(a[k]!=b[k] for k in ('run_id','challenge','reference_sha256')),'EXPECTED_NOT_INDEPENDENT')
    v.need(a['manifest_sha256']==b['manifest_sha256'],'EXPECTED_MANIFEST_MISMATCH')
    v.need(not set(a['archives'])&set(b['archives']),'EXPECTED_ARCHIVE_OVERLAP')
    v.need(type(doc['public_key']) is str and re.fullmatch(r'[0-9a-f]{64}',doc['public_key']),'PUBLIC_KEY')
    v.need(v.stamp(doc['start'])<v.stamp(doc['end']),'APPROVED_WINDOW')
    return hashlib.sha256(b'NARUV_V4_LEDGER_APPROVAL\0'+raw).hexdigest(),doc

def _state(c,pin):
    row=c.execute('SELECT document,consumed FROM naruv_signed_receipt_ci.approval WHERE pin=%s FOR UPDATE',(pin,)).fetchone()
    if row is None:
        return None,None,None
    actual,doc=parse_approval(bytes(row[0]))
    v.need(actual==pin,'APPROVAL_PIN_MISMATCH')
    runs=c.execute('SELECT scope,run_id,challenge FROM naruv_signed_receipt_ci.run WHERE pin=%s ORDER BY scope',(pin,)).fetchall()
    v.need(runs==[(s,doc['expected'][s]['run_id'],doc['expected'][s]['challenge']) for s in v.SCOPES],'LEDGER_BINDING_INCONSISTENT')
    receipts=c.execute('SELECT scope,digest FROM naruv_signed_receipt_ci.receipt WHERE pin=%s ORDER BY scope',(pin,)).fetchall()
    if row[1] is False:
        v.need(not receipts,'LEDGER_PAIR_INCONSISTENT')
        return doc,'REGISTERED',None
    v.need(row[1] is True and len(receipts)==2 and
           [r[0] for r in receipts]==list(v.SCOPES) and
           all(v.hexval(r[1]) for r in receipts) and receipts[0][1]!=receipts[1][1],'LEDGER_PAIR_INCONSISTENT')
    return doc,'CONSUMED',dict(receipts)

def _error(exc,phase):
    return ValueError(classify(exc.sqlstate,phase=phase,rollback_confirmed=False).code)

def register(c,raw):
    guard(c,REGISTRAR)
    pin,doc=parse_approval(raw)
    phase='statement'
    try:
        with c.transaction():
            c.execute('INSERT INTO naruv_signed_receipt_ci.approval(pin,document) VALUES(%s,%s)',(pin,raw))
            for s in v.SCOPES:
                b=doc['expected'][s]
                c.execute('INSERT INTO naruv_signed_receipt_ci.run VALUES(%s,%s,%s,%s)',(b['run_id'],b['challenge'],s,pin))
            phase='commit'
    except psycopg.Error as exc:
        raise _error(exc,phase) from None
    return pin

def consume(c,pin,legacy,staged):
    guard(c,CONSUMER)
    v.need(v.hexval(pin),'APPROVAL_PIN')
    v.need(type(legacy) is bytes and type(staged) is bytes and 0<len(legacy)<=65536 and 0<len(staged)<=65536,'RECEIPT_SIZE')
    phase='statement'
    try:
        with c.transaction():
            doc,state,_=_state(c,pin)
            v.need(state=='REGISTERED','UNREGISTERED_OR_CONSUMED')
            result=v.verify_pair({'legacy':legacy,'staged':staged},doc['expected'],bytes.fromhex(doc['public_key']),window_start=doc['start'],window_end=doc['end'])
            for s in v.SCOPES:
                c.execute('INSERT INTO naruv_signed_receipt_ci.receipt VALUES(%s,%s,%s)',(result['receipt_sha256'][s],pin,s))
            v.need(c.execute('UPDATE naruv_signed_receipt_ci.approval SET consumed=true WHERE pin=%s AND NOT consumed',(pin,)).rowcount==1,'UNREGISTERED_OR_CONSUMED')
            phase='commit'
    except psycopg.Error as exc:
        raise _error(exc,phase) from None
    return dict(result,approval_pin=pin,receipt_consumption='PASS_ATOMIC_PG17_REVIEW')

def inspect_status(c,pin):
    guard(c,CONSUMER)
    v.need(v.hexval(pin),'APPROVAL_PIN')
    try:
        with c.transaction():
            _,state,digests=_state(c,pin)
    except psycopg.Error as exc:
        raise _error(exc,'readback') from None
    return {'state':state or 'NOT_REGISTERED','receipt_sha256':digests,'approval_pin':pin,
            'new_consumption':False,'production_authorized':False,'gate5':'BLOCKED'}
