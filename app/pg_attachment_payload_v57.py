"""V5.7 isolated PostgreSQL 17 attachment-byte rehearsal; never a public writer.

Only adjacent message.insert + attachment.insert pairs in the V5.1 outbox are
accepted. Both events are ACKed together after a single PostgreSQL commit.
The bytea readback, all metadata and hashes must match on every replay.
Receipt/read cursor/order events are deliberately refused.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
import re
import secrets
import sqlite3

from app.pg_message_payload_v55 import _gate as prior_gate, RelayRefused
from app.pg_transition_outbox_v51 import OUTBOX

LAB='ONLY_DISPOSABLE_LAB'
FLAG='JW_PG_LAB_V57'
STATE='jw_attachment_checkpoint_v57'
MAX_BATCH=12
MAX_BYTES=5*1024*1024

@dataclass(frozen=True)
class Attachment:
    seq: int
    created_seq: int
    message_id: str
    tenant: str
    actor: str
    thread: str
    filename: str
    mime: str
    data: bytes
    created_at: str
    sha256: str


def _guard(c):
    if os.getenv(FLAG)!=LAB or os.getenv('JW_ENV','').casefold()=='production':
        raise RelayRefused('V5.7 disposable attachment gate denied')
    prior_gate(c)
    required={'messenger_attachments': {'message_id','filename','mime','data','size_bytes','content_hash'}}
    for name,columns in required.items():
        if not columns.issubset({r[1] for r in c.execute('PRAGMA table_info('+name+')')}):
            raise RelayRefused('Attachment evidence columns missing')
    triggers={r[0]:(r[1] or '').lower().replace(' ','') for r in c.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'")}
    for name in ('messenger_attachment_no_update','messenger_attachment_no_delete'):
        if 'raise(abort' not in triggers.get(name,''):
            raise RelayRefused('Attachment immutable triggers missing')


def _checkpoint(c):
    c.execute(f'''CREATE TABLE IF NOT EXISTS {STATE} (
       stream_id TEXT PRIMARY KEY CHECK(length(stream_id)=32),
       ack_seq INTEGER NOT NULL CHECK(ack_seq>=0))''')
    if {r[1] for r in c.execute(f'PRAGMA table_info({STATE})')} != {'stream_id','ack_seq'}:
        raise RelayRefused('Attachment checkpoint schema changed')
    rows=c.execute(f'SELECT stream_id,ack_seq FROM {STATE}').fetchall()
    if not rows:
        c.execute(f'INSERT INTO {STATE} VALUES (?,0)',(secrets.token_hex(16),))
    elif (len(rows)!=1 or not isinstance(rows[0][0],str)
          or not re.fullmatch('[0-9a-f]{32}',rows[0][0])
          or type(rows[0][1]) is not int or rows[0][1]<0):
        raise RelayRefused('Attachment checkpoint corrupt')


def _attachment(c, seq, first, mid):
    rows=c.execute('''SELECT m.id,m.sender_org,m.sender_user,m.connection_id,
       m.kind,m.body,m.version,m.created_at,m.edited_at,m.order_id,
       m.immutable_order_snapshot,m.actor_name,c.org_a,c.org_b,
       a.filename,a.mime,a.data,a.size_bytes,a.content_hash
       FROM messenger_messages m JOIN messenger_connections c
         ON c.id=m.connection_id JOIN messenger_attachments a ON a.message_id=m.id
       WHERE m.id=?''',(mid,)).fetchall()
    if len(rows)!=1:raise RelayRefused('Attachment message or bytes missing')
    (ident,tenant,actor,thread,kind,body,version,stamp,edited,order,snapshot,name,
     left,right,filename,mime,data,size,digest)=rows[0]
    if (ident!=mid or not all(isinstance(x,str) and x for x in
            (ident,tenant,actor,thread,stamp,left,right,filename,mime))
        or tenant not in (left,right) or left==right
        or kind!='text' or body!='첨부파일: '+filename or name!=''
        or type(version) is not int or version!=1 or edited is not None
        or order is not None or snapshot is not None or not isinstance(data,bytes)
        or type(size) is not int or not 0<size<=MAX_BYTES or len(data)!=size
        or not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest)
        or sha256(data).hexdigest()!=digest or '/' in filename or '\\' in filename
        or any(ord(c)<32 for c in filename) or len(filename)>120 or len(mime)>160):
        raise RelayRefused('Attachment owner, immutable metadata or bytes differ')
    if c.execute('SELECT 1 FROM messenger_edits WHERE message_id=? LIMIT 1',(mid,)).fetchone():
        raise RelayRefused('Edited attachment display text not supported')
    # Every message in this pass must be followed *immediately* by the same
    # attachment. Reject any additional creation or evidence marker for it.
    if c.execute(f'''SELECT COUNT(*) FROM {OUTBOX}
        WHERE entity_ref=? AND event_type IN ('message.insert','attachment.insert')''',(mid,)).fetchone()[0]!=2:
        raise RelayRefused('Duplicate or missing attachment source marker')
    return Attachment(seq,first,mid,tenant,actor,thread,filename,mime,data,stamp,digest)


def relay_attachments(source:sqlite3.Connection,sink,*,limit:int=MAX_BATCH,after_pg_commit=None):
    _guard(source)
    if type(limit) is not int or not 1<=limit<=MAX_BATCH:
        raise RelayRefused('Invalid bounded attachment batch size')
    if after_pg_commit is not None and not callable(after_pg_commit):
        raise RelayRefused('Invalid crash hook')
    _checkpoint(source)
    source.execute('BEGIN IMMEDIATE')
    try:
        stream,ack=source.execute(f'SELECT stream_id,ack_seq FROM {STATE}').fetchone()
        maxseq=source.execute(f'SELECT COALESCE(MAX(seq),0) FROM {OUTBOX}').fetchone()[0]
        if (type(ack) is not int or not 0<=ack<=maxseq
            or (ack and source.execute(f'SELECT 1 FROM {OUTBOX} WHERE seq=?',(ack,)).fetchone() is None)):
            raise RelayRefused('Source checkpoint invalid')
        tenant,actor=sink.verified_identity()
        if not all(isinstance(x,str) and x for x in (tenant,actor)):
            raise RelayRefused('No signed PostgreSQL identity')
        rows=source.execute(f'''SELECT seq,event_type,entity_ref FROM {OUTBOX}
             WHERE seq>? ORDER BY seq LIMIT ?''',(ack,2*limit+1)).fetchall()
        if not rows:
            source.commit()
            return {'delivered':0,'ack_seq':ack,'cutover_approved':False}
        if len(rows)%2 and len(rows)<=2*limit:
            raise RelayRefused('Unpaired attachment event; do not ACK')
        rows=rows[:2*limit]
        events=[]
        for i in range(0,len(rows),2):
            if i+1>=len(rows):raise RelayRefused('Unpaired source marker')
            (first,k1,r1),(last,k2,r2)=rows[i:i+2]
            expected=ack+1 if i==0 else rows[i-1][0]+1
            if (type(first) is not int or type(last) is not int or first!=expected
                or last!=first+1 or k1!='message.insert'
                or k2!='attachment.insert' or r1!=r2
                or not isinstance(r1,str) or not 0<len(r1)<=128):
                raise RelayRefused('Unsupported, missing or reordered attachment markers')
            ev=_attachment(source,last,first,r1)
            if (ev.tenant,ev.actor)!=(tenant,actor):
                raise RelayRefused('Source tenant differs from PG signed identity')
            events.append(ev)
        sink.commit_attachments(stream,events)
        if after_pg_commit is not None:after_pg_commit()
        end=events[-1].seq
        if source.execute(f'UPDATE {STATE} SET ack_seq=? WHERE stream_id=? AND ack_seq=?',
                          (end,stream,ack)).rowcount!=1:
            raise RelayRefused('Source checkpoint CAS collision')
        source.commit()
        return {'delivered':len(events),'ack_seq':end,'cutover_approved':False}
    except BaseException:
        if source.in_transaction:source.rollback()
        raise


class Pg17AttachmentLabSink:
    def __init__(self,dsn,token):
        if os.getenv(FLAG)!=LAB or os.getenv('JW_ENV','').casefold()=='production':
            raise RelayRefused('V5.7 PG17 disposable sink disabled')
        from app.pg_outbox_relay_v52 import Pg17LabSink
        self._delegate=Pg17LabSink(dsn,token)

    def verified_identity(self):
        return self._delegate.verified_identity()

    def commit_attachments(self,stream,attachments):
        if not re.fullmatch('[0-9a-f]{32}',str(stream)) or not attachments:
            raise RelayRefused('Invalid attachment PG batch')
        with self._delegate._connect() as pg:
            with pg.cursor() as cur:
                tenant,actor=self._delegate._bind(cur)
                for a in attachments:
                    if ((a.tenant,a.actor)!=(tenant,actor)
                        or type(a.seq) is not int or a.seq<=0
                        or type(a.created_seq) is not int or a.created_seq!=a.seq-1
                        or len(a.data)!=len(bytes(a.data))
                        or sha256(a.data).hexdigest()!=a.sha256):
                        raise RelayRefused('Attachment altered or signed user mismatched')
                    fields=(a.tenant,a.actor,a.message_id,a.thread,a.filename,a.mime,
                            a.data,len(a.data),a.created_at,a.sha256,a.created_seq)
                    cur.execute('''INSERT INTO jw_attach_v57.blobs
                      (stream_id,source_seq,tenant_id,actor_id,message_id,
                       connection_id,filename,mime,data,size_bytes,created_at,
                       content_sha256,create_seq)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT(stream_id,source_seq) DO NOTHING''',(stream,a.seq,*fields))
                    cur.execute('''SELECT tenant_id,actor_id,message_id,connection_id,
                         filename,mime,data,size_bytes,created_at,content_sha256,create_seq
                         FROM jw_attach_v57.blobs WHERE stream_id=%s AND source_seq=%s''',
                         (stream,a.seq))
                    row=cur.fetchone()
                    if row is None or tuple(row)!=fields:
                        raise RelayRefused('PG attachment byte readback/RLS/replay mismatch')
            pg.commit()
