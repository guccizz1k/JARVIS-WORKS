"""Deterministic transaction, replay, authorization, conflict and source tests."""
import os
import sqlite3
from pathlib import Path

import pytest

from app.pg_transition_outbox_v51 import install_disposable_outbox, OUTBOX
from app.pg_outbox_relay_v52 import (
    RelayRefused, relay_batch, STATE, LAB, Pg17LabSink,
)


SCHEMA = '''
CREATE TABLE messenger_messages(id TEXT PRIMARY KEY, sender_org TEXT NOT NULL,
 sender_user TEXT NOT NULL, connection_id TEXT NOT NULL, body TEXT NOT NULL);
CREATE TABLE messenger_edits(id TEXT PRIMARY KEY,message_id TEXT);
CREATE TABLE messenger_attachments(message_id TEXT PRIMARY KEY,data BLOB);
CREATE TABLE messenger_receipts(message_id TEXT PRIMARY KEY,receiver_org TEXT);
CREATE TABLE messenger_read_positions(connection_id TEXT,org_id TEXT,
 last_read_seq INTEGER,PRIMARY KEY(connection_id,org_id));
'''


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv('JW_PG_OUTBOX_V51', LAB)
    monkeypatch.setenv('JW_PG_CI_ALLOW', 'ONLY_EPHEMERAL_LOCAL_DATABASE')
    monkeypatch.setenv('JW_PG_LAB_V52', LAB)
    monkeypatch.setenv('JW_PG_RELAY_V52', LAB)
    monkeypatch.delenv('JW_ENV', raising=False)
    db = sqlite3.connect(tmp_path/'source.db', isolation_level=None)
    db.execute('PRAGMA foreign_keys=ON')
    db.executescript(SCHEMA)
    install_disposable_outbox(db)
    yield db
    db.close()


class MemorySink:
    def __init__(self, org='tenant_a', actor='ua'):
        self.org, self.actor = org, actor
        self.records = {}
        self.reject = False
        self.commits = 0

    def verified_identity(self):
        return self.org, self.actor

    def commit_events(self, stream_id, events):
        if self.reject:
            raise OSError('PG connection dropped')
        changes = {}
        for e in events:
            key = (stream_id, e.seq)
            record = (e.sender_org, e.sender_user, e.kind, e.ref, e.digest)
            old = changes.get(key, self.records.get(key))
            if old is not None and old != record:
                raise RelayRefused('ledger collision')
            changes[key] = record
        self.records.update(changes)
        self.commits += 1


def source_message(db, mid='m1', org='tenant_a', actor='ua'):
    db.execute('INSERT INTO messenger_messages VALUES (?,?,?,?,?)',
               (mid, org, actor, 'chat_ab', 'SECRET MESSAGE'))


def checkpoint(db):
    return db.execute('SELECT stream_id,ack_seq FROM ' + STATE).fetchone()


def test_deliver_reference_and_stable_dedup(state):
    sink = MemorySink()
    source_message(state)
    assert relay_batch(state,sink)=={'delivered':1,'ack_seq':1,'cutover_approved':False}
    assert relay_batch(state,sink)['delivered']==0
    assert len(sink.records)==1
    assert 'SECRET MESSAGE' not in str(sink.records)
    assert 'SECRET MESSAGE' not in str(state.execute('SELECT * FROM '+OUTBOX).fetchall())


def test_commit_before_sqlite_ack_crash_and_retry(state):
    sink = MemorySink()
    source_message(state)
    def crash(): raise RuntimeError('crash after PG commit before SQLite ACK')
    with pytest.raises(RuntimeError):relay_batch(state,sink,after_pg_commit=crash)
    assert checkpoint(state)[1]==0
    assert len(sink.records)==1
    assert relay_batch(state,sink)['ack_seq']==1
    assert len(sink.records)==1 and sink.commits==2


def test_sender_mismatch_blocks_no_ack(state):
    source_message(state, org='tenant_b')
    with pytest.raises(RelayRefused):relay_batch(state,MemorySink())
    assert checkpoint(state)[1]==0


def test_actor_mismatch_blocks_no_ack(state):
    source_message(state,actor='imposter')
    with pytest.raises(RelayRefused):relay_batch(state,MemorySink())
    assert checkpoint(state)[1]==0


def test_unknown_event_fail_closed(state):
    sink=MemorySink()
    source_message(state)
    state.execute('INSERT INTO messenger_attachments VALUES (?,?)',('m1',b'file'))
    with pytest.raises(RelayRefused):relay_batch(state,sink)
    assert checkpoint(state)[1]==0
    assert len(sink.records)==0


def test_partially_supported_after_ack_blocked(state):
    sink=MemorySink()
    source_message(state)
    relay_batch(state,sink)
    state.execute('INSERT INTO messenger_edits VALUES (?,?)',('e1','m1'))
    with pytest.raises(RelayRefused):relay_batch(state,sink)
    assert checkpoint(state)[1]==1


def test_pg_network_failure_no_ack(state):
    sink=MemorySink();sink.reject=True
    source_message(state)
    with pytest.raises(OSError):relay_batch(state,sink)
    assert checkpoint(state)[1]==0
    assert len(sink.records)==0


def test_postgres_ledger_tamper_detected_before_ack(state):
    sink=MemorySink();source_message(state)
    with pytest.raises(RuntimeError):
        relay_batch(state,sink,after_pg_commit=lambda: (_ for _ in ()).throw(RuntimeError('stop')))
    k=next(iter(sink.records));sink.records[k]=('wrong',)*5
    with pytest.raises(RelayRefused):relay_batch(state,sink)
    assert checkpoint(state)[1]==0


def test_sqlite_source_rollback_does_not_emit(state):
    sink=MemorySink()
    state.execute('BEGIN IMMEDIATE');source_message(state);state.rollback()
    assert relay_batch(state,sink)['delivered']==0 and sink.records=={}


def test_batch_bounded_and_recovery(state):
    sink=MemorySink()
    for i in range(4):source_message(state,str(i))
    assert relay_batch(state,sink,limit=2)['delivered']==2
    assert relay_batch(state,sink,limit=2)['delivered']==2
    assert relay_batch(state,sink)['delivered']==0
    assert len(sink.records)==4

@pytest.mark.parametrize('batch',[0,51,True,1.5,-1,'5'])
def test_bad_batch_rejected(state,batch):
    with pytest.raises(RelayRefused):relay_batch(state,MemorySink(),limit=batch)

@pytest.mark.parametrize('name,value',[
    ('JW_PG_LAB_V52','incorrect'),('JW_PG_RELAY_V52','incorrect'),
    ('JW_PG_OUTBOX_V51','incorrect'),('JW_PG_CI_ALLOW','incorrect'),
    ('JW_ENV','production'),('JW_ENV','PRODUCTION')])
def test_flags_fail_closed(state,monkeypatch,name,value):
    monkeypatch.setenv(name,value)
    with pytest.raises(RelayRefused):relay_batch(state,MemorySink())
    assert state.execute('SELECT name FROM sqlite_master WHERE name=?',(STATE,)).fetchone() is None


def test_multi_worker_guard_for_active_tx(state):
    state.execute('BEGIN')
    try:
        with pytest.raises(RelayRefused):relay_batch(state,MemorySink())
    finally:state.rollback()


def test_revoked_identity_denies(state):
    sink=MemorySink();sink.actor=None
    source_message(state)
    with pytest.raises(RelayRefused):relay_batch(state,sink)
    assert checkpoint(state)[1]==0


def test_dropped_outbox_triggers_fail_closed(state):
    state.execute('DROP TRIGGER jw_v51_message_new')
    with pytest.raises(RelayRefused):relay_batch(state,MemorySink())


def test_empty_checkpoint_tamper_detected(state):
    assert relay_batch(state,MemorySink())['delivered']==0
    state.execute('UPDATE '+STATE+' SET stream_id=?',('z'*32,))
    with pytest.raises(RelayRefused):relay_batch(state,MemorySink())


def test_absent_source_rows_deny(state):
    state.execute(f"INSERT INTO {OUTBOX}(event_type,entity_ref) VALUES ('message.insert','ghost')")
    with pytest.raises(RelayRefused):relay_batch(state,MemorySink())


def test_pg_lab_sink_denies_without_explicit_writer_grant(state,monkeypatch):
    monkeypatch.setenv('JW_PG_ALLOW_TEST_WRITES','')
    with pytest.raises(RelayRefused):Pg17LabSink('postgresql://x:y@server/prod','x'*50)


def test_no_production_relay_endpoint_or_sensitive_payload_fields():
    txt=(Path(__file__).parents[1]/'app/pg_outbox_relay_v52.py').read_text()
    assert 'FastAPI' not in txt and '@app.' not in txt
    assert 'body' not in txt.split("VALUES (%s,%s,%s,%s,%s,%s,%s)")[0].split('INSERT INTO jw_relay_v52.inbox')[-1]
    assert 'on_conflict' not in txt.lower() or 'DO NOTHING' in txt


def test_checkpoint_ahead_blocks_silent_data_loss(state):
    sink=MemorySink()
    source_message(state)
    relay_batch(state,sink)
    state.execute('UPDATE '+STATE+' SET ack_seq=999')
    with pytest.raises(RelayRefused):relay_batch(state,sink)


def test_checkpoint_nonexistent_gap_blocks(state):
    source_message(state)
    relay_batch(state,MemorySink())
    state.execute('UPDATE '+STATE+' SET ack_seq=2')
    with pytest.raises(RelayRefused):relay_batch(state,MemorySink())
