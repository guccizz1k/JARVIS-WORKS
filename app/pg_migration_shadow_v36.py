"""V3.6 disposable *lossless shadow archive* for synthetic SQLite messenger evidence.

This deliberately does NOT map rows into the live PostgreSQL messenger tables:
legacy order snapshots, receipts, edit history and attachment-kind semantics are
not yet schema-compatible. All PG writes require a separate disposable postgres
administrator connection and occur in a single rollback-capable transaction.
Never mount this module in the public FastAPI application or use customer data.
"""
from __future__ import annotations

import base64
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
import re
import sqlite3

TABLES = (
    'messenger_companies', 'messenger_connections', 'messenger_messages',
    'messenger_edits', 'messenger_attachments', 'messenger_read_positions',
    'messenger_receipts',
)
DB_NAME = re.compile(r'^jw_v20_test_[0-9a-f]{12}$')
SHADOW_SCHEMA = 'jw_migration_v36'
MAX_ROWS = 5000
MAX_BYTES = 16 * 1024 * 1024


class MigrationBlocked(RuntimeError):
    """Fail closed: never silently discard unsupported or mismatching evidence."""


@dataclass(frozen=True)
class Record:
    entity: str
    row_key: str
    payload: bytes
    digest: str


def value_token(v):
    if v is None:
        return ['null', None]
    if isinstance(v, bytes):
        return ['bytes', base64.b64encode(v).decode('ascii')]
    if isinstance(v, str):
        return ['text', v]
    if isinstance(v, bool):
        raise MigrationBlocked('Unexpected Boolean SQLite value')
    if isinstance(v, int):
        return ['integer', str(v)]
    if isinstance(v, float):
        return ['float', v.hex()]
    raise MigrationBlocked('Unsupported SQLite value type')


def canonical_bytes(entity, cols, row):
    encoded = {'entity':entity, 'columns':list(cols), 'values':[value_token(v) for v in row]}
    return json.dumps(encoded, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def row_key(values):
    return json.dumps([value_token(v) for v in values], ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False)


def source_records(source: sqlite3.Connection):
    """Consistent SQLite online backup; no user-file path input or mutation."""
    snapshot = sqlite3.connect(':memory:')
    snapshot.row_factory = None
    try:
        source.backup(snapshot)
        if snapshot.execute('PRAGMA integrity_check').fetchone() != ('ok',):
            raise MigrationBlocked('SQLite integrity verification failed')
        if snapshot.execute('PRAGMA foreign_key_check').fetchone() is not None:
            raise MigrationBlocked('SQLite foreign key violation')
        records = []
        total = 0
        for entity in TABLES:
            found = snapshot.execute('SELECT type FROM sqlite_master WHERE name=?', (entity,)).fetchone()
            if found != ('table',):
                raise MigrationBlocked('Required legacy table missing: '+entity)
            info = snapshot.execute('PRAGMA table_info("'+entity+'")').fetchall()
            cols = [entry[1] for entry in info]
            pk = [entry[1] for entry in sorted(info, key=lambda e:e[5]) if entry[5]]
            if not cols or not pk:
                raise MigrationBlocked('Missing table column/primary key: '+entity)
            pk_idx = [cols.index(name) for name in pk]
            entries = snapshot.execute('SELECT * FROM "'+entity+'"').fetchall()
            for values in entries:
                if any(values[i] is None for i in pk_idx):
                    raise MigrationBlocked('NULL synthetic source primary key: '+entity)
                key = row_key([values[i] for i in pk_idx])
                payload = canonical_bytes(entity, cols, values)
                total += len(payload)
                records.append(Record(entity,key,payload,sha256(payload).hexdigest()))
                if len(records)>MAX_ROWS or total>MAX_BYTES:
                    raise MigrationBlocked('Synthetic shadow archive exceeds safety cap')
        keys=[(r.entity,r.row_key) for r in records]
        if len(keys)!=len(set(keys)):
            raise MigrationBlocked('Duplicate SQLite source primary key')
        return sorted(records, key=lambda r:(r.entity,r.row_key))
    finally:
        snapshot.close()


def seal(records):
    h = sha256()
    for record in records:
        h.update(record.entity.encode('utf-8')+b'\0'+record.row_key.encode('utf-8')+
                 b'\0'+record.digest.encode('ascii')+b'\n')
    return h.hexdigest()


def compare_records(original, actual):
    """Byte-for-byte equality, not just totals or digest equality."""
    if len(actual)!=len(original):
        raise MigrationBlocked('Archive row count differs')
    a = sorted(original, key=lambda r:(r.entity,r.row_key))
    b = sorted(actual, key=lambda r:(r.entity,r.row_key))
    if a!=b or seal(a)!=seal(b):
        raise MigrationBlocked('Archive bytes or SHA-256 differ')
    return {'rows':len(a), 'tables':dict(Counter(r.entity for r in a)), 'seal_sha256':seal(a)}


def operational_cutover_blockers(records):
    """Explicitly mark unsupported semantics: a shadow PASS is not cutover."""
    why = ['PG_OPERATIONAL_SCHEMA_NOT_LOSSLESS', 'REAL_EMPLOYEE_IDENTITY_NOT_VERIFIED',
           'LIVE_API_STORAGE_NOT_MIGRATED', 'PRODUCTION_CUTOVER_NOT_AUTHORIZED']
    kinds = set()
    for r in records:
        if r.entity=='messenger_messages':
            value = json.loads(r.payload.decode('utf-8'))
            item = dict(zip(value['columns'], value['values']))
            kinds.add(item.get('kind', ['',''])[1])
    if 'order' in kinds:
        why.append('ORDER_SNAPSHOT_FIELDS_MISSING_IN_PG_SCHEMA')
    if any(r.entity=='messenger_attachments' for r in records):
        why.append('LEGACY_ATTACHMENT_MESSAGE_KIND_INCOMPATIBLE')
    if any(r.entity=='messenger_receipts' for r in records):
        why.append('RECEIPT_EVIDENCE_FIELDS_DIFFER')
    return tuple(why)


def _gate_database(cur):
    cur.execute('SELECT current_database(), current_user, current_setting(%s)',('server_version_num',))
    database,user,version = cur.fetchone()
    if not DB_NAME.fullmatch(database) or user!='postgres' or int(version)//10000!=17:
        raise MigrationBlocked('Refuse non-ephemeral PostgreSQL 17 administrator')
    cur.execute('SELECT to_regnamespace(%s)', (SHADOW_SCHEMA,))
    if cur.fetchone()[0] is not None:
        raise MigrationBlocked('Shadow schema already exists; refuse overwrite')


def stage_shadow(pg, records, *, inject_failure_after=None):
    """Atomic create + copy in an isolated PG17 database; no production DSN."""
    if inject_failure_after is not None and (not isinstance(inject_failure_after,int)
                                             or inject_failure_after<1):
        raise MigrationBlocked('Invalid synthetic failure injection')
    with pg.transaction():
        with pg.cursor() as cur:
            _gate_database(cur)
            cur.execute('CREATE SCHEMA jw_migration_v36 AUTHORIZATION postgres')
            cur.execute('REVOKE ALL ON SCHEMA jw_migration_v36 FROM PUBLIC')
            cur.execute('''CREATE TABLE jw_migration_v36.records (
                 entity text NOT NULL,
                 row_key text NOT NULL,
                 payload bytea NOT NULL,
                 digest text NOT NULL,
                 PRIMARY KEY(entity,row_key),
                 CONSTRAINT jw_v36_content_sha CHECK (
                   digest ~ '^[0-9a-f]{64}$' AND
                   digest = encode(public.digest(payload,'sha256'),'hex'))
                 )''')
            cur.execute('REVOKE ALL ON jw_migration_v36.records FROM PUBLIC')
            for i,r in enumerate(records,1):
                if r.entity not in TABLES or sha256(r.payload).hexdigest()!=r.digest:
                    raise MigrationBlocked('Invalid or modified source record')
                cur.execute('INSERT INTO jw_migration_v36.records(entity,row_key,payload,digest) VALUES(%s,%s,%s,%s)',
                            (r.entity,r.row_key,r.payload,r.digest))
                if i==inject_failure_after:
                    raise MigrationBlocked('Injected rollback test')
            cur.execute('SELECT COUNT(*) FROM jw_migration_v36.records')
            if cur.fetchone()[0]!=len(records):
                raise MigrationBlocked('PostgreSQL staging count mismatch')


def verify_shadow(pg, records):
    with pg.cursor() as cur:
        cur.execute('SELECT entity,row_key,payload,digest FROM jw_migration_v36.records ORDER BY entity,row_key')
        found = [Record(entity,key,bytes(blob),digest) for entity,key,blob,digest in cur.fetchall()]
        for r in found:
            if sha256(r.payload).hexdigest()!=r.digest:
                raise MigrationBlocked('Stored PostgreSQL evidence hash mismatch')
    return compare_records(records,found)


def drop_shadow(pg):
    with pg.transaction():
        with pg.cursor() as cur:
            cur.execute('SELECT current_database(),current_user')
            database,user=cur.fetchone()
            if not DB_NAME.fullmatch(database) or user!='postgres':
                raise MigrationBlocked('Unsafe shadow cleanup target')
            cur.execute('DROP SCHEMA IF EXISTS jw_migration_v36 CASCADE')
