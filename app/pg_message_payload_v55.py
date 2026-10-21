"""V5.5 signed, disposable PostgreSQL 17 message-body replication rehearsal.

Reuses V5.1 outbox + V5.4 immutable mutation journal and V5.2 signed RLS
session driver. NOT a production writer/migration. Only unedited text-message
inserts are accepted. Future edits, attachments, orders, receipts or read cursor
must halt at the source checkpoint. Commit PG before SQLite ACK; replay must
match the full original PG payload byte-for-byte (via text comparison).
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import sqlite3
from dataclasses import dataclass

from app.pg_transition_outbox_v51 import OUTBOX
from app.pg_mutation_snapshot_v54 import _gate as snapshot_gate, _verify_existing, _installed, SnapshotRefused
from app.pg_outbox_relay_v52 import RelayRefused

LAB = 'ONLY_DISPOSABLE_LAB'
FLAG = 'JW_PG_LAB_V55'
STATE = 'jw_payload_checkpoint_v55'
MAX_BATCH = 24
MAX_BODY_BYTES = 32768


@dataclass(frozen=True)
class Payload:
    seq: int
    entity_ref: str
    tenant: str
    actor: str
    connection: str
    body: str
    created_at: str
    content_sha256: str


def _gate(source: sqlite3.Connection) -> None:
    if os.getenv(FLAG) != LAB or os.getenv('JW_ENV', '').casefold() == 'production':
        raise RelayRefused('V5.5 disposable message payload gate not authorized')
    try:
        snapshot_gate(source)
        if not _installed(source):
            raise SnapshotRefused('V5.4 mutation history required')
        _verify_existing(source, replaced=True)
    except (SnapshotRefused, sqlite3.Error) as exc:
        raise RelayRefused('V5.4 immutable write-time precondition missing') from exc
    if source.isolation_level is not None or source.in_transaction:
        raise RelayRefused('Only autocommit SQLite outside caller transaction')
    cols = {x[1] for x in source.execute('PRAGMA table_info(messenger_messages)')}
    required = {'id', 'sender_org', 'sender_user', 'connection_id', 'kind',
                'body', 'version', 'created_at', 'edited_at', 'order_id',
                'immutable_order_snapshot', 'actor_name'}
    if not required.issubset(cols):
        raise RelayRefused('Cannot certify source message schema')


def _init_checkpoint(source: sqlite3.Connection) -> None:
    source.execute(f'''CREATE TABLE IF NOT EXISTS {STATE} (
      stream_id TEXT PRIMARY KEY CHECK(length(stream_id)=32),
      ack_seq INTEGER NOT NULL DEFAULT 0 CHECK(ack_seq >= 0))''')
    if {r[1] for r in source.execute(f'PRAGMA table_info({STATE})')} != {'stream_id','ack_seq'}:
        raise RelayRefused('Checkpoint schema changed')
    rows = source.execute(f'SELECT stream_id,ack_seq FROM {STATE}').fetchall()
    if not rows:
        source.execute(f'INSERT INTO {STATE} VALUES (?,0)', (secrets.token_hex(16),))
    elif (len(rows) != 1 or not isinstance(rows[0][0], str) or
          not re.fullmatch(r'[0-9a-f]{32}',rows[0][0]) or
          type(rows[0][1]) is not int or rows[0][1] < 0):
        raise RelayRefused('Invalid checkpoint stream')


def _payload(source: sqlite3.Connection, seq: int, ref: str) -> Payload:
    rows = source.execute('''SELECT m.id,m.sender_org,m.sender_user,
       m.connection_id,m.kind,m.body,m.version,m.created_at,m.edited_at,
       m.order_id,m.immutable_order_snapshot,m.actor_name,
       c.org_a,c.org_b
       FROM messenger_messages m JOIN messenger_connections c
         ON c.id=m.connection_id WHERE m.id=?''', (ref,)).fetchall()
    if len(rows) != 1:
        raise RelayRefused('Missing or duplicated source message')
    (mid,tenant,actor,thread,kind,body,version,stamp,edited,
     order_id,snapshot,actor_name,left,right) = rows[0]
    if (mid != ref or not all(isinstance(v,str) and v for v in
                  (mid,tenant,actor,thread,stamp,left,right)) or
        tenant not in (left,right) or left == right or kind != 'text' or
        type(version) is not int or version != 1 or edited is not None or
        order_id is not None or snapshot is not None or actor_name != '' or
        not isinstance(body,str)):
        raise RelayRefused('Message is mutable, unsupported, or owner mapping invalid')
    utf8 = body.encode('utf-8')
    if not 0 < len(utf8) <= MAX_BODY_BYTES:
        raise RelayRefused('Message body violates bounded lossless transfer')
    if source.execute('SELECT 1 FROM messenger_edits WHERE message_id=? LIMIT 1', (ref,)).fetchone():
        raise RelayRefused('Edited message insert lacks immutable original body snapshot')
    if source.execute('SELECT 1 FROM messenger_attachments WHERE message_id=? LIMIT 1', (ref,)).fetchone():
        raise RelayRefused('Attached payload not certified by this phase')
    return Payload(seq, ref, tenant, actor, thread, body, stamp, hashlib.sha256(utf8).hexdigest())


def relay_payloads(source: sqlite3.Connection, sink, *, limit: int = MAX_BATCH,
                   after_pg_commit=None) -> dict:
    """PG transaction first; SQLite ACK second. Never skip unsupported head row."""
    _gate(source)
    if type(limit) is not int or not 1 <= limit <= MAX_BATCH:
        raise RelayRefused('Invalid bounded message batch')
    if after_pg_commit is not None and not callable(after_pg_commit):
        raise RelayRefused('Invalid fault injection callback')
    _init_checkpoint(source)
    source.execute('BEGIN IMMEDIATE')
    try:
        checkpoint = source.execute(f'SELECT stream_id,ack_seq FROM {STATE}').fetchall()
        if len(checkpoint) != 1:
            raise RelayRefused('Checkpoint multiplicity')
        stream,ack = checkpoint[0]
        last = source.execute(f'SELECT COALESCE(MAX(seq),0) FROM {OUTBOX}').fetchone()[0]
        if ack > last or (ack and source.execute(
            f'SELECT 1 FROM {OUTBOX} WHERE seq=?',(ack,)).fetchone() is None):
            raise RelayRefused('Checkpoint refers to nonexistent evidence')
        tenant,actor = sink.verified_identity()
        if not all(isinstance(v,str) and v for v in (tenant,actor)):
            raise RelayRefused('Missing trusted RLS identity')
        rows = source.execute(f'SELECT seq,event_type,entity_ref FROM {OUTBOX} WHERE seq>? ORDER BY seq LIMIT ?',
                              (ack,limit)).fetchall()
        messages=[]
        previous=ack
        for seq,kind,ref in rows:
            if (type(seq) is not int or seq <= previous or not isinstance(ref,str)
                or not 0 < len(ref) <= 128 or kind != 'message.insert'):
                raise RelayRefused('Unsupported event or outbox sequence; ACK held')
            record = _payload(source,seq,ref)
            if (record.tenant,record.actor) != (tenant,actor):
                raise RelayRefused('PG signed identity differs from source owner')
            messages.append(record)
            previous=seq
        if not messages:
            source.execute('COMMIT')
            return {'delivered':0,'ack_seq':ack,'cutover_approved':False}
        sink.commit_payloads(stream,messages)
        if after_pg_commit is not None:
            after_pg_commit()
        end=messages[-1].seq
        updated=source.execute(f'UPDATE {STATE} SET ack_seq=? WHERE stream_id=? AND ack_seq=?',
                               (end,stream,ack))
        if updated.rowcount != 1:
            raise RelayRefused('Checkpoint CAS conflict')
        source.execute('COMMIT')
        return {'delivered':len(messages),'ack_seq':end,'cutover_approved':False}
    except BaseException:
        if source.in_transaction:
            source.rollback()
        raise


class Pg17PayloadLabSink:
    """Trust existing signed role binding from V5.2, not application-supplied actor."""
    def __init__(self,dsn:str, token:str):
        if os.getenv(FLAG) != LAB or os.getenv('JW_ENV','').casefold() == 'production':
            raise RelayRefused('V5.5 PG lab not authorized')
        from app.pg_outbox_relay_v52 import Pg17LabSink
        self._delegate = Pg17LabSink(dsn,token)

    def verified_identity(self):
        return self._delegate.verified_identity()

    def commit_payloads(self,stream:str, messages:list[Payload]):
        if not re.fullmatch(r'[0-9a-f]{32}',str(stream)) or not messages:
            raise RelayRefused('Invalid payload batch metadata')
        with self._delegate._connect() as pg:
            with pg.cursor() as cur:
                tenant,actor = self._delegate._bind(cur)
                for msg in messages:
                    if ((msg.tenant,msg.actor)!=(tenant,actor)
                        or type(msg.seq) is not int or msg.seq <= 0
                        or not isinstance(msg.body,str)
                        or hashlib.sha256(msg.body.encode()).hexdigest()!=msg.content_sha256):
                        raise RelayRefused('Payload changed or signed tenant mismatched')
                    cur.execute('''INSERT INTO jw_payload_v55.messages
                      (stream_id,source_seq,tenant_id,actor_id,entity_ref,
                       connection_id,body,created_at,content_sha256)
                      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                      ON CONFLICT(stream_id,source_seq) DO NOTHING''',
                      (stream,msg.seq,msg.tenant,msg.actor,msg.entity_ref,msg.connection,
                       msg.body,msg.created_at,msg.content_sha256))
                    cur.execute('''SELECT tenant_id,actor_id,entity_ref,
                        connection_id,body,created_at,content_sha256
                        FROM jw_payload_v55.messages
                        WHERE stream_id=%s AND source_seq=%s''',(stream,msg.seq))
                    expected=(msg.tenant,msg.actor,msg.entity_ref,msg.connection,
                              msg.body,msg.created_at,msg.content_sha256)
                    if cur.fetchone()!=expected:
                        raise RelayRefused('Durable payload conflict, tamper or RLS denial')
            pg.commit()
