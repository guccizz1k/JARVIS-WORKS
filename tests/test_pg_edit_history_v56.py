"""No PG server: real SQLite triggers, immmutable edit proof and relay failure tests."""
from __future__ import annotations
import os
import sqlite3
from hashlib import sha256
import pytest

from app.pg_transition_outbox_v51 import install_disposable_outbox
from app.pg_mutation_snapshot_v54 import install_lab_snapshots, JOURNAL
from app.pg_edit_history_v56 import relay_edits, RelayRefused, STATE, _event, Pg17EditLabSink
from tests.test_pg_message_payload_v55 import SCHEMA


class Sink:
    def __init__(self, identity=('tenant_a','ua')):
        self.identity=identity
        self.rows={}
        self.revoke=False
        self.fail=False
    def verified_identity(self):
        if self.revoke:
            raise RelayRefused('Session revoked')
        return self.identity
    def commit_edits(self,stream,events):
        if self.fail:
            raise RelayRefused('PG failed')
        staged={}
        for e in events:
            if (e.tenant,e.actor)!=self.identity:
                raise RelayRefused('Signed tenant mismatch')
            key=(stream,e.seq)
            value=(e.kind,e.ref,e.connection,e.message_id,e.version,e.body,e.created_at,e.body_sha256,e.edit_id)
            if key in self.rows and self.rows[key]!=value:
                raise RelayRefused('Conflicting replay')
            staged[key]=value
        self.rows.update(staged)


@pytest.fixture
def source(tmp_path,monkeypatch):
    for k,v in {
        'JW_PG_CI_ALLOW':'ONLY_EPHEMERAL_LOCAL_DATABASE',
        'JW_PG_OUTBOX_V51':'ONLY_DISPOSABLE_LAB',
        'JW_PG_LAB_V54':'ONLY_DISPOSABLE_LAB',
        'JW_PG_LAB_V55':'ONLY_DISPOSABLE_LAB',
        'JW_PG_LAB_V56':'ONLY_DISPOSABLE_LAB',
    }.items():
        monkeypatch.setenv(k,v)
    monkeypatch.delenv('JW_ENV',raising=False)
    c=sqlite3.connect(tmp_path/'source.db',isolation_level=None)
    c.execute('PRAGMA foreign_keys=ON')
    c.executescript(SCHEMA)
    install_disposable_outbox(c)
    install_lab_snapshots(c)
    c.execute("INSERT INTO messenger_connections VALUES('thread','tenant_a','tenant_b')")
    yield c
    c.close()


def original(c,body='최초 내용 📝',mid='m1'):
    c.execute("INSERT INTO messenger_messages VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
              (mid,'tenant_a','ua','thread','text',body,1,'2026-10-21T10:00:00Z',None,None,None,''))


def edit(c,mid='m1',eid='e1',before='최초 내용 📝',after='두번째 📌',version=2):
    c.execute('INSERT INTO messenger_edits VALUES (?,?,?,?,?,?,?)',
              (eid,mid,before,after,'ua',f'2026-10-21T10:00:0{version}Z',version))
    c.execute('UPDATE messenger_messages SET body=?,version=?,edited_at=? WHERE id=?',
              (after,version,f'2026-10-21T10:00:0{version}Z',mid))


def checkpoint(c):
    exists=c.execute("SELECT 1 FROM sqlite_master WHERE name=? AND type='table'",(STATE,)).fetchone()
    if not exists:return None
    return c.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]


def test_reconstruct_original_and_multiple_edits(source):
    original(source)
    edit(source)
    edit(source,eid='e2',before='두번째 📌',after='세번째',version=3)
    s=Sink()
    r=relay_edits(source,s)
    assert r=={'delivered':5,'ack_seq':5,'cutover_approved':False}
    rows=[v for _,v in sorted(s.rows.items())]
    assert [v[0] for v in rows]==['message.insert','edit.insert','message.body_changed','edit.insert','message.body_changed']
    assert [v[5] for v in rows]==['최초 내용 📝','두번째 📌','두번째 📌','세번째','세번째']
    assert [v[4] for v in rows]==[1,2,2,3,3]
    assert all(v[7]==sha256(v[5].encode()).hexdigest() for v in rows)
    assert relay_edits(source,s)['delivered']==0


def test_created_after_edits_before_first_relay_is_lossless(source):
    original(source)
    edit(source)
    s=Sink()
    assert relay_edits(source,s,limit=1)['ack_seq']==1
    assert list(s.rows.values())[0][5]=='최초 내용 📝'
    assert relay_edits(source,s,limit=1)['ack_seq']==2
    assert relay_edits(source,s,limit=1)['ack_seq']==3


def test_insert_before_update_rolls_back(source):
    original(source)
    with pytest.raises(sqlite3.IntegrityError):
        source.execute("UPDATE messenger_messages SET body='tampered',version=2 WHERE id='m1'")
    assert source.execute("SELECT body FROM messenger_messages").fetchone()[0]=='최초 내용 📝'
    assert relay_edits(source,Sink())['ack_seq']==1


def test_rollback_keeps_event_and_message_atomic(source):
    original(source)
    source.execute('BEGIN IMMEDIATE')
    edit(source)
    source.execute('ROLLBACK')
    s=Sink()
    assert relay_edits(source,s)['ack_seq']==1
    assert len(s.rows)==1


def test_pg_commit_then_crash_and_exact_retry(source):
    original(source)
    edit(source)
    sink=Sink()
    def crash():raise RuntimeError('simulated PG committed before ACK')
    with pytest.raises(RuntimeError):relay_edits(source,sink,after_pg_commit=crash)
    assert checkpoint(source)==0
    assert len(sink.rows)==3
    assert relay_edits(source,sink)['ack_seq']==3
    assert len(sink.rows)==3


def test_replay_conflict_blocks_checkpoint(source):
    original(source)
    sink=Sink()
    with pytest.raises(RuntimeError):relay_edits(source,sink,after_pg_commit=lambda: (_ for _ in ()).throw(RuntimeError()))
    sink.rows[next(iter(sink.rows))]=('forged',)
    with pytest.raises(RelayRefused):relay_edits(source,sink)
    assert checkpoint(source)==0


def test_missing_v54_proof_denies(source):
    original(source)
    edit(source)
    source.execute(f'DROP TRIGGER jw_v54_snapshot_no_delete')
    source.execute(f'DELETE FROM {JOURNAL}')
    with pytest.raises(RelayRefused):relay_edits(source,Sink())
    assert checkpoint(source) is None


def test_source_current_state_tampered_denies(source):
    original(source)
    edit(source)
    source.execute("DROP TRIGGER jw_v51_message_body")
    source.execute("UPDATE messenger_messages SET body='newer' WHERE id='m1'")
    with pytest.raises(RelayRefused):relay_edits(source,Sink())


def test_wrong_actor_and_tenant_denied(source):
    original(source)
    edit(source)
    for ident in [('tenant_b','ub'),('tenant_a','intruder')]:
        with pytest.raises(RelayRefused):relay_edits(source,Sink(ident))
        assert checkpoint(source)==0


def test_session_revoked_or_db_failure(source):
    original(source)
    s=Sink();s.revoke=True
    with pytest.raises(RelayRefused):relay_edits(source,s)
    s.revoke=False;s.fail=True
    with pytest.raises(RelayRefused):relay_edits(source,s)
    assert checkpoint(source)==0


@pytest.mark.parametrize('kind',["receipt","attachment","read","order"])
def test_unsupported_events_fail_closed(source,kind):
    original(source)
    if kind=='receipt':
        source.execute("INSERT INTO messenger_receipts VALUES('m1','tenant_b')")
    elif kind=='attachment':
        source.execute("INSERT INTO messenger_attachments VALUES('m1',?)",(b'file',))
    elif kind=='read':
        source.execute("INSERT INTO messenger_read_positions VALUES('thread','tenant_a',1)")
    else:
        source.execute("INSERT INTO messenger_messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       ('order1','tenant_a','ua','thread','order','file',1,'date',None,'order','{}','manager'))
    with pytest.raises(RelayRefused):relay_edits(source,Sink())
    assert checkpoint(source)==0


def test_incomplete_edit_event_cannot_be_relayed(source):
    original(source)
    source.execute('INSERT INTO messenger_edits VALUES (?,?,?,?,?,?,?)',
                   ('e1','m1','최초 내용 📝','second','ua','timestamp',2))
    with pytest.raises(RelayRefused):relay_edits(source,Sink())


def test_malformed_edit_chain_denied(source):
    original(source)
    source.execute('INSERT INTO messenger_edits VALUES (?,?,?,?,?,?,?)',
                   ('e1','m1','wrong prior','second','ua','timestamp',2))
    with pytest.raises(sqlite3.IntegrityError):
        source.execute("UPDATE messenger_messages SET body='second',version=2 WHERE id='m1'")
    with pytest.raises(RelayRefused):relay_edits(source,Sink())


@pytest.mark.parametrize('limit',[0,25,True,'3'])
def test_invalid_batch_limit(source,limit):
    original(source)
    with pytest.raises(RelayRefused):relay_edits(source,Sink(),limit=limit)


def test_empty_queue_and_ordered_checkpoint(source):
    s=Sink()
    assert relay_edits(source,s)=={'delivered':0,'ack_seq':0,'cutover_approved':False}
    original(source)
    assert relay_edits(source,s)['ack_seq']==1


def test_production_refused(source,monkeypatch):
    original(source)
    monkeypatch.setenv('JW_ENV','Production')
    with pytest.raises(RelayRefused):relay_edits(source,Sink())


def test_unsigned_lab_refused(source,monkeypatch):
    original(source)
    monkeypatch.delenv('JW_PG_LAB_V56')
    with pytest.raises(RelayRefused):relay_edits(source,Sink())


def test_caller_transaction_refused(source):
    original(source)
    source.execute('BEGIN')
    with pytest.raises(RelayRefused):relay_edits(source,Sink())
    source.rollback()


def test_pg_sink_requires_disposable_token(monkeypatch):
    monkeypatch.setenv('JW_ENV','PRODUCTION')
    with pytest.raises(RelayRefused):Pg17EditLabSink('invalid','invalid')
