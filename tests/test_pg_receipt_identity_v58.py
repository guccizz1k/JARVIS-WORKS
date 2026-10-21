"""V5.8 local SQLite transaction and signed recipient tests (PG live separate)."""
from hashlib import sha256
import os
import sqlite3
import pytest
from app.pg_transition_outbox_v51 import install_disposable_outbox,OUTBOX
from app.pg_mutation_snapshot_v54 import install_lab_snapshots
from app.pg_receipt_identity_v58 import relay_receipts,RelayRefused,STATE
from tests.test_pg_message_payload_v55 import SCHEMA as SIMPLE
SCHEMA=SIMPLE+'''\nCREATE TABLE users(id TEXT PRIMARY KEY,org_id TEXT NOT NULL);\nCREATE TRIGGER messenger_no_delete BEFORE DELETE ON messenger_messages\n BEGIN SELECT RAISE(ABORT,'protected'); END;\n'''
# V5.4 demands immutable receipt triggers; installs them itself.
# Existing SIMPLE fixture contains a receiver-only receipt table: replace it.
SCHEMA=SCHEMA.replace('messenger_receipts(message_id TEXT PRIMARY KEY,receiver_org TEXT)',
 'messenger_receipts(message_id TEXT PRIMARY KEY,receiver_org TEXT,receiver_user TEXT,actor_name TEXT,received_at TEXT)')

class Sink:
    def __init__(self,identity=('tenant_b','ub')):self.identity=identity;self.rows={};self.revoked=False;self.fail=False
    def verified_identity(self):
        if self.revoked:raise RelayRefused('revoked')
        return self.identity
    def commit_receipts(self,stream,events):
        if self.fail:raise RelayRefused('PG unavailable')
        stage={}
        for ev in events:
            if (ev.tenant,ev.actor)!=self.identity:raise RelayRefused('wrong PG actor')
            key=(stream,ev.seq)
            val=(ev.order_seq,ev.tenant,ev.actor,ev.message_id,ev.sender_org,ev.sender_user,
                 ev.connection_id,ev.actor_name,ev.received_at,ev.order_snapshot_sha256)
            if key in self.rows and self.rows[key]!=val:raise RelayRefused('modified replay')
            stage[key]=val
        self.rows.update(stage)
@pytest.fixture
def source(tmp_path,monkeypatch):
    for k,v in {'JW_PG_CI_ALLOW':'ONLY_EPHEMERAL_LOCAL_DATABASE','JW_PG_OUTBOX_V51':'ONLY_DISPOSABLE_LAB',
          'JW_PG_LAB_V54':'ONLY_DISPOSABLE_LAB','JW_PG_LAB_V55':'ONLY_DISPOSABLE_LAB',
          'JW_PG_LAB_V58':'ONLY_DISPOSABLE_LAB'}.items():monkeypatch.setenv(k,v)
    monkeypatch.delenv('JW_ENV',raising=False)
    c=sqlite3.connect(tmp_path/'source.db',isolation_level=None)
    c.execute('PRAGMA foreign_keys=ON');c.executescript(SCHEMA)
    install_disposable_outbox(c);install_lab_snapshots(c)
    c.execute("INSERT INTO messenger_connections VALUES('thread','tenant_a','tenant_b')")
    c.execute("INSERT INTO users VALUES('ua','tenant_a'),('ub','tenant_b')")
    yield c;c.close()
def make(source,mid='order1',receiver='tenant_b',actor='ub',org='tenant_a',snapshot='{"doc":"001"}'):
    source.execute('''INSERT INTO messenger_messages VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
       (mid,org,'ua','thread','order','발주서 001',1,'2026-10-21T12:01:02Z',None,'order-x',snapshot,'홍길동'))
    source.execute('INSERT INTO messenger_receipts VALUES(?,?,?,?,?)',
       (mid,receiver,actor,'김담당','2026-10-21T12:02:02Z'))
def ack(c):
    if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(STATE,)).fetchone():return None
    return c.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]
def test_signed_receiver_end_to_end(source):
    make(source);s=Sink();assert relay_receipts(source,s)=={'delivered':1,'ack_seq':2,'cutover_approved':False}
    assert relay_receipts(source,s)['delivered']==0
    assert list(s.rows.values())[0][-1]==sha256(b'{"doc":"001"}').hexdigest()
def test_pg_commit_before_source_ack_replays(source):
    make(source);s=Sink()
    with pytest.raises(RuntimeError):relay_receipts(source,s,after_pg_commit=lambda:(_ for _ in ()).throw(RuntimeError('crash')))
    assert ack(source)==0 and len(s.rows)==1
    assert relay_receipts(source,s)['ack_seq']==2 and len(s.rows)==1
def test_wrong_actor_or_tenant(source):
    make(source)
    for identity in [('tenant_a','ua'),('tenant_b','ua'),('tenant_b','other')]:
        with pytest.raises(RelayRefused):relay_receipts(source,Sink(identity))
        assert ack(source)==0
def test_source_employee_wrong_org(source):
    make(source);source.execute("UPDATE users SET org_id='tenant_a' WHERE id='ub'")
    with pytest.raises(RelayRefused):relay_receipts(source,Sink())
def test_revoke_and_sink_failure(source):
    make(source);sink=Sink();sink.revoked=True
    with pytest.raises(RelayRefused):relay_receipts(source,sink)
    sink.revoked=False;sink.fail=True
    with pytest.raises(RelayRefused):relay_receipts(source,sink)
    assert ack(source)==0
def test_conflicting_pg_row_fails(source):
    make(source);s=Sink()
    with pytest.raises(RuntimeError):relay_receipts(source,s,after_pg_commit=lambda:(_ for _ in ()).throw(RuntimeError()))
    s.rows[next(iter(s.rows))]=('corrupt',)
    with pytest.raises(RelayRefused):relay_receipts(source,s)
    assert ack(source)==0
@pytest.mark.parametrize('kwargs',[{'receiver':'tenant_a'},{'actor':'ua'},{'org':'tenant_b'},
                                   {'snapshot':''},{'snapshot':'x'*32769}])
def test_invalid_receipt_source_denied(source,kwargs):
    make(source,**kwargs)
    with pytest.raises(RelayRefused):relay_receipts(source,Sink())
def test_missing_receipt_denied(source):
    source.execute("INSERT INTO messenger_messages VALUES('x','tenant_a','ua','thread','order','p',1,'now',NULL,'ord','{}','actor')")
    with pytest.raises(RelayRefused):relay_receipts(source,Sink())
def test_nonadjacent_order_and_receipt_denied(source):
    source.execute("INSERT INTO messenger_messages VALUES('x','tenant_a','ua','thread','order','p',1,'now',NULL,'ord','{}','actor')")
    source.execute("INSERT INTO messenger_messages VALUES('y','tenant_a','ua','thread','order','p',1,'now',NULL,'ord','{}','actor')")
    source.execute("INSERT INTO messenger_receipts VALUES('x','tenant_b','ub','담당자','now')")
    with pytest.raises(RelayRefused):relay_receipts(source,Sink())
def test_receipt_source_immutable(source):
    make(source)
    with pytest.raises(sqlite3.IntegrityError):source.execute("UPDATE messenger_receipts SET received_at='hacked' WHERE message_id='order1'")
def test_uncommitted_receipt_never_sent(source):
    source.execute('BEGIN IMMEDIATE');make(source);source.rollback()
    assert relay_receipts(source,Sink())['delivered']==0
def test_disabled_default_or_production(source,monkeypatch):
    make(source);monkeypatch.delenv('JW_PG_LAB_V58')
    with pytest.raises(RelayRefused):relay_receipts(source,Sink())
    monkeypatch.setenv('JW_PG_LAB_V58','ONLY_DISPOSABLE_LAB');monkeypatch.setenv('JW_ENV','Production')
    with pytest.raises(RelayRefused):relay_receipts(source,Sink())
@pytest.mark.parametrize('limit',[0,13,-1,True,1.0])
def test_invalid_batch_size(source,limit):
    make(source)
    with pytest.raises(RelayRefused):relay_receipts(source,Sink(),limit=limit)
def test_cursor_or_attachment_not_skipped(source):
    make(source);s=Sink();relay_receipts(source,s)
    source.execute("INSERT INTO messenger_read_positions VALUES('thread','tenant_b',2)")
    with pytest.raises(RelayRefused):relay_receipts(source,s)
    assert ack(source)==2
def test_corrupt_checkpoint_halts(source):
    make(source);relay_receipts(source,Sink())
    source.execute(f'UPDATE {STATE} SET ack_seq=500')
    with pytest.raises(RelayRefused):relay_receipts(source,Sink())
def test_duplicate_receipt_source_rejected(source):
    make(source);source.execute(f"INSERT INTO {OUTBOX}(event_type,entity_ref) VALUES('receipt.insert','order1')")
    with pytest.raises(RelayRefused):relay_receipts(source,Sink())
