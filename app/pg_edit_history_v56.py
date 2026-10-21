"""V5.6 disposable PG17 immutable text-edit history relay (never operational).

Replay can recover a version-1 body from the first immutable edit's previous_body
instead of accidentally copying the current, edited message body. V5.1 event
sequence and V5.4 write-time edit snapshot must agree before any PG commit.
Unsupported receipts, attachments, orders, cursors, or absent actor evidence fail
closed. PG commits before SQLite CAS ACK; a replay compares every stored field.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
import re
import secrets
import sqlite3

from app.pg_message_payload_v55 import _gate as old_gate, RelayRefused, MAX_BODY_BYTES
from app.pg_transition_outbox_v51 import OUTBOX
from app.pg_mutation_snapshot_v54 import JOURNAL

LAB = 'ONLY_DISPOSABLE_LAB'
FLAG = 'JW_PG_LAB_V56'
STATE = 'jw_edit_checkpoint_v56'
MAX_BATCH = 24
KINDS = frozenset(('message.insert', 'edit.insert', 'message.body_changed'))


@dataclass(frozen=True)
class EditEvent:
    seq: int
    kind: str
    ref: str
    tenant: str
    actor: str
    connection: str
    message_id: str
    version: int
    body: str
    created_at: str
    body_sha256: str
    edit_id: str  # empty for a creation event


def _guard(c: sqlite3.Connection):
    if os.getenv(FLAG) != LAB or os.getenv('JW_ENV', '').casefold() == 'production':
        raise RelayRefused('V5.6 disposable edit relay not authorized')
    old_gate(c)  # Requires V5.1 trigger contract, V5.4 immutable journal, temporary DB.
    for table, cols in {
        'messenger_edits': {'id','message_id','version','previous_body','new_body','actor_user','edited_at'},
        JOURNAL: {'outbox_seq','event_type','entity_ref','edit_id','edit_version'},
    }.items():
        existing = {r[1] for r in c.execute(f'PRAGMA table_info({table})')}
        if not cols.issubset(existing):
            raise RelayRefused('Required immutable edit evidence schema missing')


def _checkpoint(c):
    c.execute(f'''CREATE TABLE IF NOT EXISTS {STATE} (
        stream_id TEXT PRIMARY KEY CHECK(length(stream_id)=32),
        ack_seq INTEGER NOT NULL CHECK(ack_seq >= 0))''')
    if {r[1] for r in c.execute(f'PRAGMA table_info({STATE})')} != {'stream_id','ack_seq'}:
        raise RelayRefused('Edit checkpoint schema differs')
    rows=c.execute(f'SELECT stream_id,ack_seq FROM {STATE}').fetchall()
    if not rows:
        c.execute(f'INSERT INTO {STATE} VALUES (?,0)',(secrets.token_hex(16),))
    elif (len(rows)!=1 or not isinstance(rows[0][0],str)
          or not re.fullmatch('[0-9a-f]{32}',rows[0][0])
          or type(rows[0][1]) is not int or rows[0][1] < 0):
        raise RelayRefused('Invalid edit checkpoint identity')


def _content(value):
    if not isinstance(value,str):
        raise RelayRefused('Edit body not text')
    content=value.encode('utf-8')
    if not 0 < len(content) <= MAX_BODY_BYTES:
        raise RelayRefused('Edit body exceeds safe bounds')
    return sha256(content).hexdigest()


def _history(c, mid):
    rows=c.execute('''SELECT m.id,m.sender_org,m.sender_user,m.connection_id,
        m.kind,m.body,m.version,m.created_at,m.edited_at,m.order_id,
        m.immutable_order_snapshot,m.actor_name,c.org_a,c.org_b
        FROM messenger_messages m JOIN messenger_connections c ON c.id=m.connection_id
        WHERE m.id=?''',(mid,)).fetchall()
    if len(rows)!=1:
        raise RelayRefused('Source message missing or not uniquely joined')
    (msg,tenant,actor,thread,kind,current,version,created,edited,
     order,snapshot,name,left,right)=rows[0]
    if (not all(isinstance(v,str) and v for v in (msg,tenant,actor,thread,created,left,right))
        or tenant not in (left,right) or left==right or msg != mid
        or kind != 'text' or type(version) is not int or version < 1
        or order is not None or snapshot is not None or name != '' or not isinstance(current,str)):
        raise RelayRefused('Message type, owner or source version is unverifiable')
    _content(current)
    if c.execute('SELECT 1 FROM messenger_attachments WHERE message_id=? LIMIT 1',(mid,)).fetchone():
        raise RelayRefused('Attachment-linked message unsupported by edit relay')
    edits=c.execute('''SELECT id,version,actor_user,previous_body,new_body,edited_at
                      FROM messenger_edits WHERE message_id=? ORDER BY version''',(mid,)).fetchall()
    if len(edits)!=version-1 or (version==1 and edited is not None) or (version>1 and not edited):
        raise RelayRefused('Edit version chain missing or extra rows')
    previous=current if not edits else edits[0][3]
    _content(previous)
    by_id={}
    for i,(eid,v,editor,old,new,at) in enumerate(edits,2):
        if (type(v) is not int or v!=i or not isinstance(eid,str) or not eid
            or eid in by_id or editor != actor or not isinstance(at,str) or not at
            or old != previous or not isinstance(new,str)):
            raise RelayRefused('Edit chain discontinuous or owner not verified')
        _content(new)
        by_id[eid]=(v,new)
        previous=new
    if previous != current or (edits and edited != edits[-1][5]):
        raise RelayRefused('Latest edit does not match original message state')
    # Every edit must have an outbox insert and V5.4 mutation proof.  This
    # catches source edits inserted without a matching message-body update.
    for eid,(v,new) in by_id.items():
        out=c.execute(f'''SELECT seq FROM {OUTBOX}
             WHERE event_type='edit.insert' AND entity_ref=?''',(eid,)).fetchall()
        proof=c.execute(f'''SELECT j.outbox_seq FROM {JOURNAL} j
             JOIN {OUTBOX} o ON o.seq=j.outbox_seq
             WHERE j.edit_id=? AND j.edit_version=? AND j.entity_ref=?
               AND j.event_type='message.body_changed'
               AND o.event_type='message.body_changed' AND o.entity_ref=?''',
               (eid,v,mid,mid)).fetchall()
        if len(out)!=1 or len(proof)!=1 or proof[0][0] <= out[0][0]:
            raise RelayRefused('Missing corresponding immutable edit and mutation evidence')
    return tenant,actor,thread,created,(current if not edits else edits[0][3]),by_id


def _event(c, seq, kind, ref):
    if kind == 'edit.insert':
        linked=c.execute('SELECT message_id FROM messenger_edits WHERE id=?',(ref,)).fetchall()
        if len(linked)!=1:
            raise RelayRefused('Immutable edit reference missing')
        mid=linked[0][0]
    else:
        mid=ref
    tenant,actor,thread,created,original,edits=_history(c,mid)
    if kind=='message.insert':
        version,body,eid=1,original,''
    elif kind=='edit.insert':
        if ref not in edits:
            raise RelayRefused('Source edit ID is not part of attested message chain')
        version,body=edits[ref];eid=ref
    elif kind=='message.body_changed':
        proofs=c.execute(f'''SELECT edit_id,edit_version FROM {JOURNAL}
            WHERE outbox_seq=? AND event_type=? AND entity_ref=?''',
            (seq,kind,ref)).fetchall()
        if len(proofs)!=1:
            raise RelayRefused('Write-time proof missing or duplicated')
        eid,version=proofs[0]
        if eid not in edits or edits[eid][0]!=version:
            raise RelayRefused('Write-time proof refers to wrong edit')
        body=edits[eid][1]
    else:
        raise RelayRefused('Unsupported edit event')
    return EditEvent(seq,kind,ref,tenant,actor,thread,mid,version,body,created,_content(body),eid)


def relay_edits(source: sqlite3.Connection, sink, *, limit=MAX_BATCH, after_pg_commit=None):
    _guard(source)
    if type(limit) is not int or not 1<=limit<=MAX_BATCH:
        raise RelayRefused('Invalid bounded edit batch')
    if after_pg_commit is not None and not callable(after_pg_commit):
        raise RelayRefused('Invalid crash hook')
    _checkpoint(source)
    source.execute('BEGIN IMMEDIATE')
    try:
        stream,ack=source.execute(f'SELECT stream_id,ack_seq FROM {STATE}').fetchone()
        max_seq=source.execute(f'SELECT COALESCE(MAX(seq),0) FROM {OUTBOX}').fetchone()[0]
        if (type(ack) is not int or ack<0 or ack>max_seq
            or (ack>0 and source.execute(f'SELECT 1 FROM {OUTBOX} WHERE seq=?',(ack,)).fetchone() is None)):
            raise RelayRefused('Edit checkpoint cannot be trusted')
        tenant,actor=sink.verified_identity()
        if not (isinstance(tenant,str) and tenant and isinstance(actor,str) and actor):
            raise RelayRefused('Signed tenant/actor unavailable')
        rows=source.execute(f'SELECT seq,event_type,entity_ref FROM {OUTBOX} WHERE seq>? ORDER BY seq LIMIT ?',
                            (ack,limit)).fetchall()
        events=[];prev=ack
        for seq,kind,ref in rows:
            if (type(seq) is not int or seq<=prev or kind not in KINDS
                or not isinstance(ref,str) or not 0<len(ref)<=128):
                raise RelayRefused('Unsupported or reordered event; checkpoint held')
            event=_event(source,seq,kind,ref)
            if (event.tenant,event.actor)!=(tenant,actor):
                raise RelayRefused('Source sender not equal to PG signed identity')
            events.append(event);prev=seq
        if not events:
            source.commit()
            return {'delivered':0,'ack_seq':ack,'cutover_approved':False}
        sink.commit_edits(stream,events)
        if after_pg_commit:
            after_pg_commit()
        end=events[-1].seq
        if source.execute(f'UPDATE {STATE} SET ack_seq=? WHERE stream_id=? AND ack_seq=?',
                          (end,stream,ack)).rowcount!=1:
            raise RelayRefused('Checkpoint compare-and-swap conflict')
        source.commit()
        return {'delivered':len(events),'ack_seq':end,'cutover_approved':False}
    except BaseException:
        if source.in_transaction:
            source.rollback()
        raise


class Pg17EditLabSink:
    """Shares V5.2 signed RLS binder; app role has SELECT/INSERT only."""
    def __init__(self, dsn, token):
        if os.getenv(FLAG)!=LAB or os.getenv('JW_ENV','').casefold()=='production':
            raise RelayRefused('PG17 edit lab not authorized')
        from app.pg_outbox_relay_v52 import Pg17LabSink
        self._delegate=Pg17LabSink(dsn,token)

    def verified_identity(self):
        return self._delegate.verified_identity()

    def commit_edits(self,stream,events):
        if not re.fullmatch(r'[0-9a-f]{32}',str(stream)) or not events:
            raise RelayRefused('Edit stream invalid')
        with self._delegate._connect() as pg:
            with pg.cursor() as cur:
                tenant,actor=self._delegate._bind(cur)
                for event in events:
                    if ((event.tenant,event.actor)!=(tenant,actor)
                        or event.kind not in KINDS or type(event.seq) is not int or event.seq<=0
                        or _content(event.body)!=event.body_sha256):
                        raise RelayRefused('Invalid PG edit source or signed identity')
                    fields=(event.tenant,event.actor,event.kind,event.ref,event.connection,
                            event.message_id,event.version,event.body,event.created_at,
                            event.body_sha256,event.edit_id)
                    cur.execute('''INSERT INTO jw_edits_v56.events
                      (stream_id,source_seq,tenant_id,actor_id,event_type,entity_ref,
                       connection_id,message_id,message_version,body,created_at,
                       body_sha256,edit_id)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT(stream_id,source_seq) DO NOTHING''',(stream,event.seq,*fields))
                    cur.execute('''SELECT tenant_id,actor_id,event_type,entity_ref,connection_id,
                       message_id,message_version,body,created_at,body_sha256,edit_id
                       FROM jw_edits_v56.events WHERE stream_id=%s AND source_seq=%s''',
                       (stream,event.seq))
                    if cur.fetchone()!=fields:
                        raise RelayRefused('PG edit event durability, RLS, or replay conflict')
            pg.commit()
