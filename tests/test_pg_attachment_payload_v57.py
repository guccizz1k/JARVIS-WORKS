"""SQLite real transaction fault-injection tests; actual PG17 is separate."""
import os
import sqlite3
from hashlib import sha256
from pathlib import Path
import pytest

from app.pg_transition_outbox_v51 import install_disposable_outbox,OUTBOX
from app.pg_mutation_snapshot_v54 import install_lab_snapshots
from app.pg_attachment_payload_v57 import relay_attachments,STATE,RelayRefused,_attachment,Pg17AttachmentLabSink,MAX_BYTES
from tests.test_pg_message_payload_v55 import SCHEMA as OLD_SCHEMA

SCHEMA=OLD_SCHEMA.replace('messenger_attachments(message_id TEXT PRIMARY KEY,data BLOB)',
    'messenger_attachments(message_id TEXT PRIMARY KEY,filename TEXT,mime TEXT,data BLOB,size_bytes INTEGER,content_hash TEXT)') + '''
CREATE TRIGGER messenger_attachment_no_update BEFORE UPDATE ON messenger_attachments
 BEGIN SELECT RAISE(ABORT,'immutable attachment'); END;
CREATE TRIGGER messenger_attachment_no_delete BEFORE DELETE ON messenger_attachments
 BEGIN SELECT RAISE(ABORT,'immutable attachment'); END;
'''
class Sink:
    def __init__(self,identity=('tenant_a','ua')):
        self.identity=identity;self.rows={};self.fail=False;self.revoke=False
    def verified_identity(self):
        if self.revoke:raise RelayRefused('session revoked')
        return self.identity
    def commit_attachments(self,stream,events):
        if self.fail:raise RelayRefused('PG down')
        staged={}
        for e in events:
            if (e.tenant,e.actor)!=self.identity:raise RelayRefused('signed actor mismatch')
            key=(stream,e.seq)
            body=(e.created_seq,e.tenant,e.actor,e.message_id,e.thread,e.filename,e.mime,e.data,e.created_at,e.sha256)
            if key in self.rows and self.rows[key]!=body:raise RelayRefused('conflicting replay')
            staged[key]=body
        self.rows.update(staged)

@pytest.fixture
def src(tmp_path,monkeypatch):
    for k,v in {'JW_PG_CI_ALLOW':'ONLY_EPHEMERAL_LOCAL_DATABASE','JW_PG_OUTBOX_V51':'ONLY_DISPOSABLE_LAB',
                 'JW_PG_LAB_V54':'ONLY_DISPOSABLE_LAB','JW_PG_LAB_V55':'ONLY_DISPOSABLE_LAB',
                 'JW_PG_LAB_V57':'ONLY_DISPOSABLE_LAB'}.items():monkeypatch.setenv(k,v)
    monkeypatch.delenv('JW_ENV',raising=False)
    c=sqlite3.connect(tmp_path/'src.db',isolation_level=None)
    c.execute('PRAGMA foreign_keys=ON');c.executescript(SCHEMA)
    install_disposable_outbox(c);install_lab_snapshots(c)
    c.execute("INSERT INTO messenger_connections VALUES('thread','tenant_a','tenant_b')")
    yield c;c.close()

def attach(c,mid='m1',data=b'%PDF-1.4\nHello\n',filename='doc.pdf',**kw):
    v={'tenant':'tenant_a','actor':'ua','thread':'thread','body':'첨부파일: '+filename,
       'kind':'text','version':1,'edited':None,'order':None,'snapshot':None,'name':''}
    v.update(kw)
    c.execute('INSERT INTO messenger_messages VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
        (mid,v['tenant'],v['actor'],v['thread'],v['kind'],v['body'],v['version'],
         '2026-10-21T18:01:00.123456Z',v['edited'],v['order'],v['snapshot'],v['name']))
    c.execute('INSERT INTO messenger_attachments VALUES(?,?,?,?,?,?)',
        (mid,filename,'application/pdf',data,len(data),sha256(data).hexdigest()))

def ack(c):
    if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(STATE,)).fetchone() is None:
        return None
    return c.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]

def test_full_bytes_and_idempotent_replay(src):
    data=b'\x00\xff\x89'+b'abc'*300
    attach(src,data=data)
    s=Sink();assert relay_attachments(src,s)=={'delivered':1,'ack_seq':2,'cutover_approved':False}
    assert next(iter(s.rows.values()))[7]==data
    assert relay_attachments(src,s)=={'delivered':0,'ack_seq':2,'cutover_approved':False}

def test_pg_commit_then_sqlite_crash_exact_replay(src):
    attach(src);s=Sink()
    with pytest.raises(RuntimeError):relay_attachments(src,s,after_pg_commit=lambda:(_ for _ in ()).throw(RuntimeError('crash')))
    assert ack(src)==0 and len(s.rows)==1
    assert relay_attachments(src,s)['ack_seq']==2 and len(s.rows)==1

def test_conflicting_pg_replay_halts_ack(src):
    attach(src);s=Sink()
    with pytest.raises(RuntimeError):relay_attachments(src,s,after_pg_commit=lambda:(_ for _ in ()).throw(RuntimeError()))
    s.rows[next(iter(s.rows))]=('tampered',)
    with pytest.raises(RelayRefused):relay_attachments(src,s)
    assert ack(src)==0

def test_cross_tenant_and_revoked_denied(src):
    attach(src)
    for who in [('tenant_b','ub'),('tenant_a','fake')]:
        with pytest.raises(RelayRefused):relay_attachments(src,Sink(who))
        assert ack(src)==0
    s=Sink();s.revoke=True
    with pytest.raises(RelayRefused):relay_attachments(src,s)

def test_unsupported_plain_text_head_stops(src):
    src.execute("INSERT INTO messenger_messages VALUES('plain','tenant_a','ua','thread','text','hello',1,'2026Z',NULL,NULL,NULL,'')")
    attach(src,mid='m2')
    with pytest.raises(RelayRefused):relay_attachments(src,Sink())
    assert ack(src)==0

def test_missing_attachment_marker_denied(src):
    src.execute("INSERT INTO messenger_messages VALUES('plain','tenant_a','ua','thread','text','첨부파일: doc.pdf',1,'2026Z',NULL,NULL,NULL,'')")
    with pytest.raises(RelayRefused):relay_attachments(src,Sink())
    assert ack(src)==0

def test_unsupported_read_cursor_blocks(src):
    attach(src);s=Sink();relay_attachments(src,s)
    src.execute("INSERT INTO messenger_read_positions VALUES('thread','tenant_a',3)")
    with pytest.raises(RelayRefused):relay_attachments(src,s)
    assert ack(src)==2

def test_integrity_rejects_sqlite_blob_corruption(src):
    attach(src);src.execute('DROP TRIGGER messenger_attachment_no_update')
    src.execute("UPDATE messenger_attachments SET data=X'00' WHERE message_id='m1'")
    with pytest.raises(RelayRefused):relay_attachments(src,Sink())
    assert ack(src) is None

def test_incorrect_hash_metadata_denied(src):
    attach(src);src.execute('DROP TRIGGER messenger_attachment_no_update')
    src.execute("UPDATE messenger_attachments SET content_hash=? WHERE message_id='m1'",('0'*64,))
    with pytest.raises(RelayRefused):relay_attachments(src,Sink())

def test_missing_source_company_denied(src):
    attach(src,tenant='tenant_unknown')
    with pytest.raises(RelayRefused):relay_attachments(src,Sink())

def test_missing_adjacent_pair_denied(src):
    attach(src);src.execute(f"INSERT INTO {OUTBOX}(event_type,entity_ref) VALUES('receipt.insert','m1')")
    with pytest.raises(RelayRefused):relay_attachments(src,Sink())
    assert ack(src)==0

def test_uncommitted_insert_is_not_delivered(src):
    src.execute('BEGIN IMMEDIATE');attach(src);src.execute('ROLLBACK')
    assert relay_attachments(src,Sink())['delivered']==0

def test_batch_splits_at_pair_boundary(src):
    for i in range(4):attach(src,mid=f'm{i}')
    s=Sink()
    for i in range(4):assert relay_attachments(src,s,limit=1)['ack_seq']==(i+1)*2
    assert len(s.rows)==4

def test_disabled_by_default(src,monkeypatch):
    attach(src);monkeypatch.delenv('JW_PG_LAB_V57')
    with pytest.raises(RelayRefused):relay_attachments(src,Sink())

def test_production_refused(src,monkeypatch):
    attach(src);monkeypatch.setenv('JW_ENV','PrOdUcTiOn')
    with pytest.raises(RelayRefused):relay_attachments(src,Sink())

def test_commit_failure_leaves_ack(src):
    attach(src);s=Sink();s.fail=True
    with pytest.raises(RelayRefused):relay_attachments(src,s)
    assert ack(src)==0

def test_disallow_unbounded_batch(src):
    attach(src)
    for v in (0,-1,13,True,1.0):
        with pytest.raises(RelayRefused):relay_attachments(src,Sink(),limit=v)

def test_disallow_edit_or_order(src):
    for kwargs in ({'version':2},{'order':'order-1','kind':'order'}, {'name':'manager'}):
        attach(src,mid='m'+str(len(src.execute('SELECT * FROM messenger_messages').fetchall())),**kwargs)
        with pytest.raises(RelayRefused):relay_attachments(src,Sink())
        # The first unsupported marker stays at stream head (never skip).
        assert ack(src)==0

def test_mutated_creation_body_denied(src):
    attach(src)
    with pytest.raises(sqlite3.IntegrityError):
        src.execute("UPDATE messenger_messages SET body='different' WHERE id='m1'")
    assert relay_attachments(src,Sink())['ack_seq']==2

def test_pg_lab_constructor_denied(src,monkeypatch):
    monkeypatch.setenv('JW_ENV','Production')
    with pytest.raises(RelayRefused):Pg17AttachmentLabSink('postgresql://localhost/fake','fake')
