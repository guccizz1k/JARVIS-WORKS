"""V4.8 synthetic-only semantic evidence envelope, ALWAYS rolled back on PG17.

This is a preservation experiment, NOT an operational format or migration.
It reuses V3.6 canonical bytes, V3.7 exact legacy validation, and V4.6 RLS audit.
Never call it with real customer data, nor register it in public FastAPI.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
from typing import Iterable

MAX_ROWS = 5000
MAX_BYTES = 16 * 1024 * 1024
TEMP_TABLE = 'jw_v48_semantic_evidence'


class SemanticRefused(RuntimeError):
    """An unverifiable semantic mapping cannot be marked safe."""


@dataclass(frozen=True)
class Envelope:
    entity: str
    row_key: str
    payload: bytes
    digest: str
    original_kind: str | None
    candidate_kind: str | None


def _validate_times(by_table):
    """Require offsets; preserve original timestamp strings exactly, never reformat."""
    from app.pg_migration_compat_v37 import COLUMNS
    for name, rows in by_table.items():
        for row in rows:
            for column in COLUMNS[name]:
                if column not in ('verified_at', 'created_at', 'accepted_at',
                                  'edited_at', 'updated_at', 'received_at'):
                    continue
                value = row[column]
                if value is None:
                    continue
                if not isinstance(value, str) or not value or value.endswith('Z'):
                    # UTC 'Z' has an ambiguous lexical roundtrip under timestamp casts.
                    raise SemanticRefused('Unsupported timestamp representation')
                try:
                    parsed = datetime.fromisoformat(value)
                except ValueError as exc:
                    raise SemanticRefused('Invalid historical timestamp') from exc
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    raise SemanticRefused('Timestamp without a timezone offset')
                if parsed.isoformat() != value:
                    # Preserve source precisely; do not silently normalize fractions/offsets.
                    raise SemanticRefused('Noncanonical timestamp string')


def make_envelopes(records: Iterable):
    """Construct a lossless review *sidecar* for ALL seven source evidence tables."""
    from app.pg_migration_compat_v37 import COLUMNS, PK, build_contract
    from app.pg_migration_shadow_v36 import canonical_bytes, row_key
    records = list(records)
    if not records or len(records) > MAX_ROWS:
        raise SemanticRefused('Record boundary exceeded')
    if sum(len(r.payload) for r in records) > MAX_BYTES:
        raise SemanticRefused('Source byte boundary exceeded')
    # V3.7 already enforces edits, receipts, snapshots, hash and actor linkage.
    by_table = build_contract(records)
    _validate_times(by_table)
    # This explicitly exercises all evidence dimensions; an empty fixture must
    # never accidentally certify a missing semantic family as verified.
    if (not by_table['messenger_edits'] or not by_table['messenger_receipts']
            or len(by_table['messenger_read_positions']) < 2):
        raise SemanticRefused('Incomplete synthetic editing, receipt or bilateral read fixture')
    attachments = {r['message_id'] for r in by_table['messenger_attachments']}
    msgs = {m['id']: m for m in by_table['messenger_messages']}
    if attachments - msgs.keys():
        raise SemanticRefused('Orphan attachment')
    expected = {}
    for table, rows in by_table.items():
        for values in rows:
            key = row_key([values[c] for c in PK[table]])
            payload = canonical_bytes(table, COLUMNS[table], [values[c] for c in COLUMNS[table]])
            kind = None
            candidate = None
            if table == 'messenger_messages':
                kind = values['kind']
                candidate = 'attachment' if values['id'] in attachments else kind
                if candidate not in ('text', 'order', 'attachment'):
                    raise SemanticRefused('Unsupported target message kind')
            k = (table, key)
            if k in expected:
                raise SemanticRefused('Duplicate canonical key')
            expected[k] = Envelope(table, key, payload, sha256(payload).hexdigest(), kind, candidate)
    supplied = {(r.entity, r.row_key): r for r in records}
    if len(supplied) != len(records) or set(expected) != set(supplied):
        raise SemanticRefused('Missing or extra canonical rows')
    for key, row in expected.items():
        src = supplied[key]
        if src.payload != row.payload or src.digest != row.digest:
            raise SemanticRefused('Source bytes do not match semantic contract')
    envelopes = tuple(expected[k] for k in sorted(expected))
    if sum(len(e.payload) for e in envelopes) > MAX_BYTES:
        raise SemanticRefused('Encoded evidence too large')
    if not any(e.original_kind == 'text' and e.candidate_kind == 'attachment'
               for e in envelopes):
        raise SemanticRefused('Required synthetic attachment semantic not exercised')
    if not any(e.original_kind == 'order' for e in envelopes):
        raise SemanticRefused('Required synthetic order evidence not exercised')
    return envelopes


def verify_envelopes(expected, actual):
    """Compare originals and projection metadata byte-for-byte (no digest-only PASS)."""
    rows = list(actual)
    if len(rows) != len(expected):
        raise SemanticRefused('Semantic row count mismatch')
    recovered = {}
    for raw in rows:
        if len(raw) != 6:
            raise SemanticRefused('Malformed semantic row')
        entity, key, payload, digest, kind, candidate = raw
        item = Envelope(entity, key, bytes(payload), digest, kind, candidate)
        if item.digest != sha256(item.payload).hexdigest():
            raise SemanticRefused('Semantic checksum mismatch')
        if (entity, key) in recovered:
            raise SemanticRefused('Repeated evidence row')
        recovered[entity, key] = item
    if recovered != {(x.entity, x.row_key): x for x in expected}:
        raise SemanticRefused('Evidence bytes, fields or kind projection changed')
    return len(rows)


@dataclass(frozen=True)
class SemanticResult:
    rows: int
    attachments_as_candidate_kind: int
    rollback_verified: bool
    force_rls_preserved: bool
    cutover_approved: bool = False
    decision: str = 'BLOCKED'


def rehearse_semantic_envelopes(pg, records):
    """Disposable PG17 only: create TEMP table inside a transaction; ALWAYS rollback.

    Public messenger tables and historical compatibility schemas never receive DML.
    """
    from app.pg_cutover_readiness_v46 import postgres_inventory, TABLES
    envelopes = make_envelopes(records)
    if pg.autocommit is not True:
        raise SemanticRefused('Expected disposable autocommit PG connection')
    with pg.cursor() as cur:
        baseline = postgres_inventory(cur)  # validates disposable PG17 admin
        if any(baseline.force_rls.get(t) is not True for t in TABLES):
            raise SemanticRefused('Forced RLS missing')
        cur.execute("SELECT to_regclass('pg_temp.jw_v48_semantic_evidence')")
        if cur.fetchone()[0] is not None:
            raise SemanticRefused('Preexisting semantic temp table')
        failure = None
        begun = False
        try:
            cur.execute('BEGIN')
            begun = True
            cur.execute("SET LOCAL lock_timeout = '2000ms'")
            cur.execute("SET LOCAL statement_timeout = '5000ms'")
            cur.execute('''CREATE TEMP TABLE jw_v48_semantic_evidence (
              entity text NOT NULL, row_key text NOT NULL, payload bytea NOT NULL,
              digest text NOT NULL, original_kind text, candidate_kind text,
              PRIMARY KEY(entity,row_key)) ON COMMIT DROP''')
            for e in envelopes:
                cur.execute('''INSERT INTO pg_temp.jw_v48_semantic_evidence
                  (entity,row_key,payload,digest,original_kind,candidate_kind)
                  VALUES (%s,%s,%s,%s,%s,%s)''',
                  (e.entity,e.row_key,e.payload,e.digest,e.original_kind,e.candidate_kind))
            cur.execute('''SELECT entity,row_key,payload,digest,original_kind,candidate_kind
              FROM pg_temp.jw_v48_semantic_evidence ORDER BY entity,row_key''')
            if verify_envelopes(envelopes, cur.fetchall()) != len(envelopes):
                raise SemanticRefused('Incomplete semantic evidence')
            if postgres_inventory(cur) != baseline:
                raise SemanticRefused('Public catalog changed during rehearsal')
        except Exception as exc:
            failure = exc
        finally:
            if begun:
                try:
                    cur.execute('ROLLBACK')
                except Exception as exc:
                    raise SemanticRefused('Rollback failed') from exc
        cur.execute("SELECT to_regclass('pg_temp.jw_v48_semantic_evidence')")
        if cur.fetchone()[0] is not None or postgres_inventory(cur) != baseline:
            raise SemanticRefused('Temporary or public catalog survived rollback')
        if failure is not None:
            raise SemanticRefused('Semantic rehearsal failed') from failure
        return SemanticResult(
            len(envelopes),
            sum(e.candidate_kind == 'attachment' for e in envelopes),
            rollback_verified=True, force_rls_preserved=True,
        )
