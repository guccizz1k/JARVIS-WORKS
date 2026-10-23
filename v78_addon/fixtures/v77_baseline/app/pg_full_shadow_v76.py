"""V7.6: complete SQLite -> disposable PG17 shadow, *not* application migration.

Fail-closed, bounded, in-memory, read-only against the SQLite source. Preserves
all entity values and SQLite schema metadata without pretending PG semantics
or tenant RLS have been migrated. Never invoke against production customer data.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import re
import sqlite3

from .pg_migration_shadow_v36 import canonical_bytes, row_key, value_token

EXPECTED_TABLES = frozenset('''audit_logs automation_document_drafts_v62 automation_statements_v60 automation_task_times_v60 customers evidence_lines_v66 evidence_links_v65 evidence_previews_v64 evidence_records_v64 import_previews invoice_adjustment_decisions_v69 invoice_adjustments_v69 invoice_items invoices login_failures messenger_attachments messenger_companies messenger_connections messenger_edits messenger_messages messenger_read_positions messenger_receipts mfa_credentials mfa_recovery_codes order_items orders organizations payments quote_items quotes reconciliation_reviews_v67 security_events sessions staff_disabled users'''.split())
LAB_DB = re.compile(r'^jw_v20_test_[a-f0-9]{12}$')
SCHEMA = 'jw_full_shadow_v76'
MAX_ROWS = 25000
MAX_BYTES = 128 * 1024 * 1024

class ShadowBlocked(RuntimeError):
    pass

@dataclass(frozen=True)
class ShadowRecord:
    table: str
    key: str
    payload: bytes
    sha256: str

@dataclass(frozen=True)
class ShadowBundle:
    records: tuple[ShadowRecord, ...]
    tables: tuple[str, ...]
    schema_bytes: bytes
    seal: str


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _seal(records, schema_bytes):
    h=sha256(schema_bytes)
    for r in records:
        h.update(_canonical([r.table,r.key,r.sha256]))
    return h.hexdigest()


def _verify(bundle):
    if len(bundle.schema_bytes)>1024*1024:
        raise ShadowBlocked('Schema metadata exceeds size cap')
    if len(set(bundle.tables)) != len(bundle.tables) or set(bundle.tables) != EXPECTED_TABLES:
        raise ShadowBlocked('Source table set mismatch')
    if len(bundle.records)>MAX_ROWS or sum(len(x.payload) for x in bundle.records)>MAX_BYTES:
        raise ShadowBlocked('Safety cap exceeded')
    if tuple(sorted(bundle.records,key=lambda x:(x.table,x.key)))!=bundle.records:
        raise ShadowBlocked('Archive ordering invalid')
    if len({(r.table,r.key) for r in bundle.records})!=len(bundle.records):
        raise ShadowBlocked('Duplicate row key')
    if any(r.table not in EXPECTED_TABLES or sha256(r.payload).hexdigest()!=r.sha256 for r in bundle.records):
        raise ShadowBlocked('Corrupted payload')
    if bundle.seal!=_seal(bundle.records,bundle.schema_bytes):
        raise ShadowBlocked('Archive seal mismatch')
    try:
        metadata=json.loads(bundle.schema_bytes)
    except (UnicodeDecodeError,ValueError) as exc:
        raise ShadowBlocked('Invalid schema metadata') from exc
    if {x['name'] for x in metadata['tables']}!=EXPECTED_TABLES:
        raise ShadowBlocked('Schema does not describe every table')


def capture(source: sqlite3.Connection) -> ShadowBundle:
    """Consistent online backup; does not mutate caller/source connection."""
    if os.environ.get('JW_ENV','').lower() in ('prod','production'):
        raise ShadowBlocked('Synthetic shadow capture forbidden in production')
    if source.in_transaction:
        raise ShadowBlocked('Source has open transaction; abort rather than block or capture uncommitted data')
    snapshot=sqlite3.connect(':memory:')
    try:
        source.backup(snapshot)
        if snapshot.execute('PRAGMA integrity_check').fetchone()!=('ok',):
            raise ShadowBlocked('SQLite integrity_check failed')
        if snapshot.execute('PRAGMA foreign_key_check').fetchone() is not None:
            raise ShadowBlocked('SQLite foreign_key_check failed')
        objects=snapshot.execute('''SELECT type,name,tbl_name,sql FROM sqlite_master
                  WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name''').fetchall()
        tables={name for kind,name,_,__ in objects if kind=='table'}
        if tables!=EXPECTED_TABLES:
            raise ShadowBlocked('Source table set mismatch; inspect all schema changes before shadow')
        descriptions=[]
        archive=[]
        byte_total=0
        for table in sorted(tables):
            # Name is only ever taken from the exact constant allowlist.
            safe='"'+table+'"'
            info=snapshot.execute(f'PRAGMA table_info({safe})').fetchall()
            columns=[x[1] for x in info]
            pk=[x[1] for x in sorted(info,key=lambda x:x[5]) if x[5]]
            if not columns or not pk:
                raise ShadowBlocked('Table missing columns or explicit PK: '+table)
            fk=snapshot.execute(f'PRAGMA foreign_key_list({safe})').fetchall()
            ix=snapshot.execute(f'PRAGMA index_list({safe})').fetchall()
            descriptions.append({'name':table,'columns':info,'pk':pk,'foreign_keys':fk,'indexes':ix})
            indexes=[columns.index(x) for x in pk]
            for values in snapshot.execute(f'SELECT * FROM {safe}'):
                if any(values[i] is None for i in indexes):
                    raise ShadowBlocked('NULL primary key: '+table)
                payload=canonical_bytes(table,columns,values)
                byte_total+=len(payload)
                archive.append(ShadowRecord(table,row_key([values[i] for i in indexes]),payload,sha256(payload).hexdigest()))
                if byte_total>MAX_BYTES or len(archive)>MAX_ROWS:
                    raise ShadowBlocked('Synthetic-only safety cap exceeded')
        # SQLite AUTOINCREMENT sequence can exceed MAX(id) after deletions.
        # Preserve it explicitly; copying only visible rows is not sufficient.
        seq_exists=any(n=='sqlite_sequence' for (n,) in snapshot.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'"))
        seq=snapshot.execute('SELECT name,seq FROM sqlite_sequence ORDER BY name').fetchall() if seq_exists else []
        schema_bytes=_canonical({'objects':objects,'tables':descriptions,
            'sqlite_sequence':seq,
            'pragma_user_version':snapshot.execute('PRAGMA user_version').fetchone()[0],
            'pragma_application_id':snapshot.execute('PRAGMA application_id').fetchone()[0]})
        archive=tuple(sorted(archive,key=lambda r:(r.table,r.key)))
        bundle=ShadowBundle(archive,tuple(sorted(tables)),schema_bytes,_seal(archive,schema_bytes))
        _verify(bundle)
        return bundle
    finally:
        snapshot.close()


def summary(bundle:ShadowBundle):
    _verify(bundle)
    counts=Counter(x.table for x in bundle.records)
    return {'tables':len(bundle.tables),'rows':len(bundle.records),
            'per_table':{table:counts[table] for table in bundle.tables},
            'schema_sha256':sha256(bundle.schema_bytes).hexdigest(),
            'seal_sha256':bundle.seal,'postgres_verified':False,
            'operational_cutover_permitted':False,
            'blockers':['POSTGRES_DISPOSABLE_SHADOW_NOT_VERIFIED',
                        'APPLICATION_PG_STORAGE_ADAPTER_MISSING',
                        'FULL_APPLICATION_RLS_NOT_VERIFIED',
                        'PRODUCTION_CUTOVER_NOT_AUTHORIZED']}


def compare(expected:ShadowBundle, actual:ShadowBundle):
    _verify(expected);_verify(actual)
    if expected!=actual:
        raise ShadowBlocked('Shadow restore not byte identical to SQLite snapshot')
    return summary(actual)


def _guard(cur):
    cur.execute('SELECT current_database(), current_user, current_setting(%s)',('server_version_num',))
    database,user,version=cur.fetchone()
    if not LAB_DB.fullmatch(database) or user!='postgres' or int(version)//10000!=17:
        raise ShadowBlocked('Only temporary isolated PG17 administrator allowed')
    cur.execute('SELECT to_regnamespace(%s)',(SCHEMA,))
    if cur.fetchone()[0] is not None:
        raise ShadowBlocked('Existing shadow namespace cannot be overwritten')


def stage_disposable_pg(pg, bundle:ShadowBundle, inject_failure_after=None):
    """Optional integration: atomic PG17 shadow, not a live table cutover.

    No migrations/roles/grants to the application. Staging contains sensitive
    source data; use only synthetic inputs in a throwaway isolated cluster.
    """
    if os.environ.get('JW_ENV','').lower() in ('prod','production'):
        raise ShadowBlocked('Never write PG staging in production')
    if os.environ.get('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_DISPOSABLE_LAB':
        raise ShadowBlocked('Disposable lab opt-in required')
    _verify(bundle)
    if inject_failure_after is not None and (type(inject_failure_after) is not int or inject_failure_after < 1 or inject_failure_after > len(bundle.records)):
        raise ShadowBlocked('Invalid rollback injection')
    with pg.transaction():
        with pg.cursor() as cur:
            _guard(cur)
            cur.execute(f'CREATE SCHEMA {SCHEMA} AUTHORIZATION postgres')
            cur.execute(f'REVOKE ALL ON SCHEMA {SCHEMA} FROM PUBLIC')
            cur.execute(f'''CREATE TABLE {SCHEMA}.metadata (key text PRIMARY KEY, payload bytea NOT NULL)''')
            cur.execute(f'''CREATE TABLE {SCHEMA}.records (
                table_name text NOT NULL, row_key text NOT NULL,
                payload bytea NOT NULL, sha256 text NOT NULL,
                PRIMARY KEY(table_name,row_key))''')
            cur.execute(f'REVOKE ALL ON ALL TABLES IN SCHEMA {SCHEMA} FROM PUBLIC')
            cur.execute(f'ALTER TABLE {SCHEMA}.records ENABLE ROW LEVEL SECURITY')
            cur.execute(f'ALTER TABLE {SCHEMA}.records FORCE ROW LEVEL SECURITY')
            cur.execute(f'ALTER TABLE {SCHEMA}.metadata ENABLE ROW LEVEL SECURITY')
            cur.execute(f'ALTER TABLE {SCHEMA}.metadata FORCE ROW LEVEL SECURITY')
            cur.execute(f'INSERT INTO {SCHEMA}.metadata(key,payload) VALUES(%s,%s)',('schema',bundle.schema_bytes))
            for i,r in enumerate(bundle.records,1):
                cur.execute(f'INSERT INTO {SCHEMA}.records(table_name,row_key,payload,sha256) VALUES(%s,%s,%s,%s)',
                            (r.table,r.key,r.payload,r.sha256))
                if i==inject_failure_after:
                    raise ShadowBlocked('Injected PG transaction rollback')
            cur.execute(f'SELECT COUNT(*) FROM {SCHEMA}.records')
            if cur.fetchone()[0]!=len(bundle.records):
                raise ShadowBlocked('PostgreSQL shadow count mismatch')


def verify_disposable_pg(pg,bundle:ShadowBundle):
    if os.environ.get('JW_ENV','').lower() in ('prod','production'):
        raise ShadowBlocked('Never query staging from production')
    _verify(bundle)
    with pg.cursor() as cur:
        cur.execute('SELECT current_database(),current_user,current_setting(%s)',('server_version_num',))
        name,user,version=cur.fetchone()
        if not LAB_DB.fullmatch(name) or user!='postgres' or int(version)//10000!=17:
            raise ShadowBlocked('PostgreSQL shadow verification requires isolated PG17')
        cur.execute(f'SELECT payload FROM {SCHEMA}.metadata WHERE key=%s',('schema',))
        row=cur.fetchone()
        if row is None:
            raise ShadowBlocked('Metadata missing')
        raw=row[0]
        schema=bytes(raw)
        cur.execute(f'SELECT table_name,row_key,payload,sha256 FROM {SCHEMA}.records ORDER BY table_name,row_key')
        actual=tuple(ShadowRecord(t,k,bytes(p),d) for t,k,p,d in cur.fetchall())
    restored=ShadowBundle(actual,bundle.tables,schema,_seal(actual,schema))
    return compare(bundle,restored)


def drop_disposable_pg(pg):
    with pg.transaction():
        with pg.cursor() as cur:
            cur.execute('SELECT current_database(),current_user,current_setting(%s)',('server_version_num',))
            name,user,ver=cur.fetchone()
            if not LAB_DB.fullmatch(name) or user!='postgres' or int(ver)//10000!=17:
                raise ShadowBlocked('Unsafe shadow cleanup refused')
            cur.execute(f'DROP SCHEMA IF EXISTS {SCHEMA} CASCADE')
