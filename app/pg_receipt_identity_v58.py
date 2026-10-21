"""Disposable B2B receipt proof with signer bound to the receiving company.

This rehearsal accepts one *adjacent* order-create / receipt pair only. It is
not an operational stream-wide consumer: if an order was delivered earlier or
interleaved with other events the stream fails CLOSED rather than skipping rows.
The recipient actor is bound by the signed PostgreSQL session, never the
original sender's session. No rollout or real-customer database permission.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import os
import re
import secrets
import sqlite3

from app.pg_message_payload_v55 import _gate as prior_gate
from app.pg_outbox_relay_v52 import RelayRefused
from app.pg_transition_outbox_v51 import OUTBOX

FLAG='JW_PG_LAB_V58'
LAB='ONLY_DISPOSABLE_LAB'
STATE='jw_receipt_checkpoint_v58'
MAX_BATCH=12

@dataclass(frozen=True)
class Receipt:
    seq:int
    order_seq:int
    message_id:str
    tenant:str
    actor:str
    sender_org:str
    sender_user:str
    connection_id:str
    actor_name:str
    received_at:str
    order_snapshot_sha256:str


def _guard(source):
    if os.getenv(FLAG)!=LAB or os.getenv('JW_ENV','').casefold()=='production':
        raise RelayRefused('Disposable receipt integration disabled')
    prior_gate(source)
    required={
        'users':{'id','org_id'},
        'messenger_receipts':{'message_id','receiver_org','receiver_user','actor_name','received_at'},
        'messenger_messages':{'id','sender_org','sender_user','connection_id','kind','order_id','immutable_order_snapshot','version'},
        'messenger_connections':{'id','org_a','org_b'},
    }
    for tbl,cols in required.items():
        found={r[1] for r in source.execute(f'PRAGMA table_info({tbl})')}
        if not cols.issubset(found):
            raise RelayRefused('Required signed receipt evidence missing')
    triggers={r[0]:(r[1] or '').lower().replace(' ','') for r in source.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'")}
    for name in ('messenger_receipt_no_update','messenger_receipt_no_delete','messenger_no_delete'):
        if 'raise(abort' not in triggers.get(name,''):
            raise RelayRefused('Immutable source evidence trigger missing')


def _checkpoint(source):
    source.execute(f'''CREATE TABLE IF NOT EXISTS {STATE} (
        stream_id TEXT PRIMARY KEY CHECK(length(stream_id)=32),
        ack_seq INTEGER NOT NULL CHECK(ack_seq>=0))''')
    if {r[1] for r in source.execute(f'PRAGMA table_info({STATE})')} != {'stream_id','ack_seq'}:
        raise RelayRefused('Checkpoint schema corrupt')
    rows=source.execute(f'SELECT stream_id,ack_seq FROM {STATE}').fetchall()
    if not rows:source.execute(f'INSERT INTO {STATE} VALUES(?,0)',(secrets.token_hex(16),))
    elif (len(rows)!=1 or not isinstance(rows[0][0],str)
          or not re.fullmatch('[0-9a-f]{32}',rows[0][0])
          or type(rows[0][1]) is not int or rows[0][1]<0):
        raise RelayRefused('Checkpoint identity invalid')


def _receipt(source,receipt_seq,order_seq,mid):
    rows=source.execute('''SELECT m.id,m.sender_org,m.sender_user,m.connection_id,
        m.kind,m.order_id,m.immutable_order_snapshot,m.version,m.edited_at,
        c.org_a,c.org_b,r.receiver_org,r.receiver_user,r.actor_name,r.received_at,
        u.org_id FROM messenger_messages m
        JOIN messenger_connections c ON c.id=m.connection_id
        JOIN messenger_receipts r ON r.message_id=m.id
        JOIN users u ON u.id=r.receiver_user WHERE m.id=?''',(mid,)).fetchall()
    if len(rows)!=1:raise RelayRefused('Source receipt, order or user mapping missing')
    (rid,sender_org,sender_user,thread,kind,order_id,snapshot,version,edited,
     left,right,receiver_org,receiver_user,actor_name,received_at,employee_org)=rows[0]
    fields=(rid,sender_org,sender_user,thread,left,right,receiver_org,receiver_user,actor_name,received_at)
    if (any(not isinstance(x,str) or not x for x in fields)
        or rid!=mid or left==right or sender_org not in (left,right)
        or receiver_org not in (left,right) or sender_org==receiver_org
        or employee_org!=receiver_org or kind!='order' or not isinstance(order_id,str)
        or not order_id or type(version) is not int or version!=1 or edited is not None
        or not isinstance(snapshot,str) or not snapshot or len(snapshot.encode('utf-8'))>32768
        or not 2<=len(actor_name)<=120 or len(received_at)>80):
        raise RelayRefused('Receipt sender/receiver/employee order contract mismatch')
    if source.execute('SELECT 1 FROM messenger_attachments WHERE message_id=? LIMIT 1',(mid,)).fetchone():
        raise RelayRefused('Attachment order not supported')
    if source.execute('SELECT 1 FROM messenger_edits WHERE message_id=? LIMIT 1',(mid,)).fetchone():
        raise RelayRefused('Edited order not supported')
    if source.execute(f'''SELECT COUNT(*) FROM {OUTBOX}
        WHERE entity_ref=? AND event_type IN ('message.insert','receipt.insert')''',(mid,)).fetchone()[0]!=2:
        raise RelayRefused('Receipt/outbox evidence duplicated')
    return Receipt(receipt_seq,order_seq,mid,receiver_org,receiver_user,sender_org,
                   sender_user,thread,actor_name,received_at,
                   hashlib.sha256(snapshot.encode('utf-8')).hexdigest())


def relay_receipts(source:sqlite3.Connection,sink,*,limit=MAX_BATCH,after_pg_commit=None):
    _guard(source)
    if type(limit) is not int or not 1<=limit<=MAX_BATCH:
        raise RelayRefused('Invalid bounded receipt batch')
    if after_pg_commit is not None and not callable(after_pg_commit):
        raise RelayRefused('Invalid crash callback')
    _checkpoint(source)
    source.execute('BEGIN IMMEDIATE')
    try:
        checkpoint=source.execute(f'SELECT stream_id,ack_seq FROM {STATE}').fetchall()
        if len(checkpoint)!=1:raise RelayRefused('Checkpoint multiplicity')
        stream,ack=checkpoint[0]
        maxseq=source.execute(f'SELECT COALESCE(MAX(seq),0) FROM {OUTBOX}').fetchone()[0]
        if (type(ack) is not int or not 0<=ack<=maxseq
            or (ack and source.execute(f'SELECT 1 FROM {OUTBOX} WHERE seq=?',(ack,)).fetchone() is None)):
            raise RelayRefused('Checkpoint cannot be trusted')
        tenant,actor=sink.verified_identity()
        if not all(isinstance(x,str) and x for x in (tenant,actor)):
            raise RelayRefused('Signed recipient actor required')
        rows=source.execute(f'SELECT seq,event_type,entity_ref FROM {OUTBOX} WHERE seq>? ORDER BY seq LIMIT ?',
                            (ack,2*limit+1)).fetchall()
        if not rows:
            source.commit();return {'delivered':0,'ack_seq':ack,'cutover_approved':False}
        if len(rows)%2 and len(rows)<=2*limit:raise RelayRefused('Unpaired receipt marker')
        rows=rows[:2*limit];events=[]
        for i in range(0,len(rows),2):
            (first,k1,m1),(second,k2,m2)=rows[i:i+2]
            target=ack+1 if i==0 else rows[i-1][0]+1
            if (type(first) is not int or type(second) is not int or first!=target or second!=first+1
                or k1!='message.insert' or k2!='receipt.insert' or m1!=m2
                or not isinstance(m1,str) or not 0<len(m1)<=128):
                raise RelayRefused('Out-of-order or unsupported receipt event')
            ev=_receipt(source,second,first,m1)
            if (ev.tenant,ev.actor)!=(tenant,actor):
                raise RelayRefused('Receiver employee differs from signed PG actor')
            events.append(ev)
        sink.commit_receipts(stream,events)
        if after_pg_commit:after_pg_commit()
        end=events[-1].seq
        if source.execute(f'UPDATE {STATE} SET ack_seq=? WHERE stream_id=? AND ack_seq=?',
                          (end,stream,ack)).rowcount!=1:
            raise RelayRefused('Receipt checkpoint CAS collision')
        source.commit()
        return {'delivered':len(events),'ack_seq':end,'cutover_approved':False}
    except BaseException:
        if source.in_transaction:source.rollback()
        raise


class Pg17ReceiptLabSink:
    def __init__(self,dsn,token):
        if os.getenv(FLAG)!=LAB or os.getenv('JW_ENV','').casefold()=='production':
            raise RelayRefused('PG17 receipt lab unauthorized')
        from app.pg_outbox_relay_v52 import Pg17LabSink
        self._delegate=Pg17LabSink(dsn,token)
    def verified_identity(self):return self._delegate.verified_identity()
    def commit_receipts(self,stream,events):
        if not re.fullmatch('[0-9a-f]{32}',str(stream)) or not events:
            raise RelayRefused('Invalid receipt batch')
        with self._delegate._connect() as pg:
            with pg.cursor() as cur:
                tenant,actor=self._delegate._bind(cur)
                for ev in events:
                    if ((ev.tenant,ev.actor)!=(tenant,actor) or type(ev.seq) is not int or ev.seq<2
                       or ev.order_seq!=ev.seq-1 or not re.fullmatch('[0-9a-f]{64}',ev.order_snapshot_sha256)):
                        raise RelayRefused('Wrong receiver signature or receipt metadata')
                    values=(ev.tenant,ev.actor,ev.message_id,ev.sender_org,ev.sender_user,
                            ev.connection_id,ev.actor_name,ev.received_at,ev.order_snapshot_sha256,ev.order_seq)
                    cur.execute('''INSERT INTO jw_receipt_v58.receipts
                      (stream_id,source_seq,tenant_id,actor_id,message_id,sender_org,
                       sender_user,connection_id,actor_name,received_at,order_snapshot_sha256,order_seq)
                       VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT(stream_id,source_seq) DO NOTHING''',(stream,ev.seq,*values))
                    cur.execute('''SELECT tenant_id,actor_id,message_id,sender_org,sender_user,
                             connection_id,actor_name,received_at,order_snapshot_sha256,order_seq
                             FROM jw_receipt_v58.receipts WHERE stream_id=%s AND source_seq=%s''',(stream,ev.seq))
                    if cur.fetchone()!=values:
                        raise RelayRefused('Receipt ledger replay, readback or RLS mismatch')
            pg.commit()
