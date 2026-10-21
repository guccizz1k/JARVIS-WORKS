"""V5.2: opt-in disposable-lab SQLite outbox -> PG17 reference relay.

NOT a customer-data migrator or a production writer. Only message.insert
references with independently verified synthetic actor/tenant are supported.
The PostgreSQL sink commits before the SQLite ACK. A crash between them causes
at-least-once delivery requests and an exactly-once *PG ledger effect*, enforced
by (source_stream, source_seq) and content equality in the PG transaction.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import sqlite3
from dataclasses import dataclass

from app.pg_transition_outbox_v51 import OUTBOX, _authorize, OutboxRefused

FLAG = 'JW_PG_RELAY_V52'
LAB = 'ONLY_DISPOSABLE_LAB'
STATE = 'jw_relay_checkpoint_v52'
SUPPORTED = frozenset({'message.insert'})
MAX_BATCH = 50


class RelayRefused(RuntimeError):
    """Unverified, unsupported or potentially lossy relay operation."""


@dataclass(frozen=True)
class Event:
    seq: int
    kind: str
    ref: str
    sender_org: str
    sender_user: str
    digest: str


def _gate(source: sqlite3.Connection) -> None:
    if (os.getenv('JW_ENV', '').casefold() == 'production'
            or os.getenv('JW_PG_LAB_V52') != LAB
            or os.getenv(FLAG) != LAB):
        raise RelayRefused('V5.2 disposable relay is not authorized')
    try:
        _authorize(source)
    except OutboxRefused as exc:
        raise RelayRefused('V5.1 disposable outbox authorization failed') from exc
    found = {r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    required = {
        'jw_v51_message_new', 'jw_v51_message_body', 'jw_v51_edit_new',
        'jw_v51_attachment_new', 'jw_v51_receipt_new',
        'jw_v51_read_new', 'jw_v51_read_advance',
        'jw_v51_outbox_immutable_update', 'jw_v51_outbox_immutable_delete',
    }
    if not required.issubset(found):
        raise RelayRefused('Missing mandatory immutable V5.1 triggers')
    columns = {r[1] for r in source.execute('PRAGMA table_info(messenger_messages)')}
    if not {'id', 'sender_org', 'sender_user', 'connection_id'}.issubset(columns):
        raise RelayRefused('Verified message provenance columns absent')
    if {r[1] for r in source.execute('PRAGMA table_info(' + OUTBOX + ')')} != {
            'seq', 'event_type', 'entity_ref', 'recorded_at'}:
        raise RelayRefused('Outbox schema incompatible')


def _prepare_state(source: sqlite3.Connection) -> None:
    # Called after _gate, outside transaction. No production SQLite writes.
    source.execute(f'''CREATE TABLE IF NOT EXISTS {STATE} (
         stream_id TEXT PRIMARY KEY CHECK(length(stream_id)=32),
         ack_seq INTEGER NOT NULL DEFAULT 0 CHECK(ack_seq >= 0)
    )''')
    columns = {r[1] for r in source.execute(f'PRAGMA table_info({STATE})')}
    if columns != {'stream_id', 'ack_seq'}:
        raise RelayRefused('Unexpected checkpoint schema')
    records = source.execute(f'SELECT stream_id,ack_seq FROM {STATE}').fetchall()
    if not records:
        source.execute(f'INSERT INTO {STATE}(stream_id,ack_seq) VALUES (?,0)',
                       (secrets.token_hex(16),))
    elif (len(records) != 1 or not re.fullmatch(r'[0-9a-f]{32}', records[0][0])
          or not isinstance(records[0][1], int) or records[0][1] < 0):
        raise RelayRefused('Invalid stream identity or multiple checkpoints')
    if source.in_transaction:
        source.commit()  # only our checkpoint initialization; prior writes were refused


def _load(source: sqlite3.Connection, stream_id: str, ack: int, *,
          tenant: str, actor: str, limit: int) -> list[Event]:
    data = source.execute(f'''SELECT seq,event_type,entity_ref FROM {OUTBOX}
        WHERE seq>? ORDER BY seq LIMIT ?''', (ack, limit)).fetchall()
    result: list[Event] = []
    for seq, kind, ref in data:
        if not isinstance(seq, int) or seq <= ack or (result and seq <= result[-1].seq):
            raise RelayRefused('Nonmonotonic source outbox sequence')
        if kind not in SUPPORTED or not isinstance(ref, str) or not ref or len(ref) > 128:
            raise RelayRefused('Unsupported event or invalid source identity; ACK withheld')
        rows = source.execute('''SELECT sender_org,sender_user FROM messenger_messages
                  WHERE id=?''', (ref,)).fetchall()
        if len(rows) != 1 or not all(isinstance(x, str) and x for x in rows[0]):
            raise RelayRefused('Source message provenance missing')
        org, user = rows[0]
        if org != tenant or user != actor:
            raise RelayRefused('Signed PG actor differs from SQLite source owner')
        raw = f'{stream_id}\0{seq}\0{kind}\0{ref}\0{org}\0{user}'
        digest = hashlib.sha256(raw.encode('utf-8')).hexdigest()
        result.append(Event(seq, kind, ref, org, user, digest))
    return result


def relay_batch(source: sqlite3.Connection, sink, *, limit: int = MAX_BATCH,
                after_pg_commit=None) -> dict:
    """Deliver references via a signed, restricted PG sink; ACK after commit.

    sink.verified_identity() returns the CURRENT database-verified (org,user),
    and sink.commit_events(stream_id, events) atomically performs SQL+commit.
    Never pass caller-supplied organizational IDs as authoritative.
    """
    _gate(source)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_BATCH:
        raise RelayRefused('Bounded batch is required')
    _prepare_state(source)
    if source.in_transaction:
        raise RelayRefused('Relay source already in transaction')
    source.execute('BEGIN IMMEDIATE')  # serialize ACK against other relay workers
    try:
        stream, ack = source.execute(f'SELECT stream_id,ack_seq FROM {STATE}').fetchone()
        if not isinstance(ack, int) or ack < 0:
            raise RelayRefused('Invalid checkpoint value')
        maxseq = source.execute(f'SELECT COALESCE(MAX(seq),0) FROM {OUTBOX}').fetchone()[0]
        if ack > maxseq or (ack and not source.execute(
                f'SELECT 1 FROM {OUTBOX} WHERE seq=?', (ack,)).fetchone()):
            raise RelayRefused('Checkpoint points beyond verified source history')
        tenant, actor = sink.verified_identity()
        if not all(isinstance(v, str) and v for v in (tenant, actor)):
            raise RelayRefused('No verified PostgreSQL actor')
        events = _load(source, stream, ack, tenant=tenant, actor=actor, limit=limit)
        if not events:
            source.execute('COMMIT')
            return {'delivered': 0, 'ack_seq': ack, 'cutover_approved': False}
        sink.commit_events(stream, events)  # PG durable commit before ACK
        if after_pg_commit is not None:
            # Local fault injection only. Never surfaced in HTTP or production.
            if not callable(after_pg_commit):
                raise RelayRefused('Invalid test fault injector')
            after_pg_commit()
        last = events[-1].seq
        updated = source.execute(f'UPDATE {STATE} SET ack_seq=? WHERE stream_id=? AND ack_seq=?',
                                 (last, stream, ack))
        if updated.rowcount != 1:
            raise RelayRefused('SQLite checkpoint compare-and-swap failed')
        source.execute('COMMIT')
        return {'delivered': len(events), 'ack_seq': last, 'cutover_approved': False}
    except BaseException:
        if source.in_transaction:
            source.rollback()
        raise


class Pg17LabSink:
    """A new PG17 jw_app session with signed jw_guard identity, never admin."""

    def __init__(self, dsn: str, token: str):
        _verify_pg_env()
        from app.pg_compat_read_api_v38 import check_dsn
        check_dsn(dsn)
        if not isinstance(token, str) or not (40 <= len(token) <= 512):
            raise RelayRefused('Synthetic signed PG session missing')
        self._dsn = dsn
        self._token = token

    def _connect(self):
        _verify_pg_env()
        from app.pg_compat_read_api_v38 import check_dsn
        check_dsn(self._dsn)
        import psycopg
        return psycopg.connect(self._dsn, connect_timeout=5)

    def _bind(self, cursor):
        cursor.execute("SET LOCAL statement_timeout = '5000ms'")
        cursor.execute("SET LOCAL lock_timeout = '2000ms'")
        cursor.execute("SELECT current_database(), current_user, current_setting('server_version_num'), "
                       "COALESCE((SELECT rolsuper OR rolbypassrls FROM pg_catalog.pg_roles "
                       "WHERE rolname=current_user), true)")
        db, role, version, elevated = cursor.fetchone()
        from app.pg_compat_read_api_v38 import check_dsn
        if (db != check_dsn(self._dsn)['dbname'] or role != 'jw_app'
                or int(version)//10000 != 17 or elevated):
            raise RelayRefused('Unexpected database, PG role or PostgreSQL version')
        cursor.execute('SELECT jw_guard.bind_session(%s)', (self._token,))
        cursor.execute('SELECT jw_guard.current_tenant(), jw_guard.current_actor()')
        tenant, actor = cursor.fetchone()
        if not tenant or not actor:
            raise RelayRefused('Unbound or revoked signed PG identity')
        return tenant, actor

    def verified_identity(self) -> tuple[str, str]:
        with self._connect() as pg:
            with pg.cursor() as cur:
                result = self._bind(cur)
            pg.rollback()  # identity check must not retain role/GUC
            return result

    def commit_events(self, stream_id: str, events: list[Event]) -> None:
        if not re.fullmatch(r'[0-9a-f]{32}', stream_id) or not events:
            raise RelayRefused('Missing stream or empty batch')
        with self._connect() as pg:
            with pg.cursor() as cur:
                identity = self._bind(cur)
                for e in events:
                    if (e.sender_org, e.sender_user) != identity:
                        raise RelayRefused('PG identity revoked or changed before commit')
                    cur.execute('''INSERT INTO jw_relay_v52.inbox
                        (stream_id,source_seq,tenant_id,actor_id,event_type,entity_ref,source_digest)
                        VALUES (%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT(stream_id,source_seq) DO NOTHING''',
                        (stream_id,e.seq,e.sender_org,e.sender_user,e.kind,e.ref,e.digest))
                    cur.execute('''SELECT tenant_id,actor_id,event_type,entity_ref,source_digest
                        FROM jw_relay_v52.inbox WHERE stream_id=%s AND source_seq=%s''',
                        (stream_id,e.seq))
                    row = cur.fetchone()
                    if row != (e.sender_org,e.sender_user,e.kind,e.ref,e.digest):
                        raise RelayRefused('PostgreSQL ledger conflict or RLS denial')
            pg.commit()  # exactly-once effect; caller owns SQLite ACK later


def _verify_pg_env() -> None:
    if (os.getenv('JW_ENV', '').casefold() == 'production'
            or os.getenv('JW_PG_LAB_V52') != LAB
            or os.getenv(FLAG) != LAB
            or os.getenv('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE'
            or os.getenv('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE'):
        raise RelayRefused('Disposable PG17 laboratory write gate closed')
