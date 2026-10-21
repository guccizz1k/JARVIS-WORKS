"""V5.5 local synthetic SQLite contract and fault injection tests (no PG server)."""
import os
import sqlite3
from hashlib import sha256

import pytest

from app.pg_transition_outbox_v51 import install_disposable_outbox, OUTBOX
from app.pg_mutation_snapshot_v54 import install_lab_snapshots
from app.pg_message_payload_v55 import (
    relay_payloads, RelayRefused, STATE, _payload, Pg17PayloadLabSink,
)

SCHEMA = '''
CREATE TABLE messenger_connections(id TEXT PRIMARY KEY,org_a TEXT,org_b TEXT);
CREATE TABLE messenger_messages(id TEXT PRIMARY KEY,sender_org TEXT,sender_user TEXT,
 connection_id TEXT, kind TEXT NOT NULL,body TEXT NOT NULL,version INTEGER NOT NULL,
 created_at TEXT NOT NULL, edited_at TEXT,order_id TEXT,immutable_order_snapshot TEXT,
 actor_name TEXT NOT NULL DEFAULT '');
CREATE TABLE messenger_edits(id TEXT PRIMARY KEY,message_id TEXT,previous_body TEXT,
 new_body TEXT,actor_user TEXT,edited_at TEXT,version INTEGER);
CREATE TABLE messenger_attachments(message_id TEXT PRIMARY KEY,data BLOB);
CREATE TABLE messenger_receipts(message_id TEXT PRIMARY KEY,receiver_org TEXT);
CREATE TABLE messenger_read_positions(connection_id TEXT,org_id TEXT,last_read_seq INTEGER,
 PRIMARY KEY(connection_id,org_id));
CREATE TRIGGER messenger_edit_no_update BEFORE UPDATE ON messenger_edits
 BEGIN SELECT RAISE(ABORT,'protected');END;
CREATE TRIGGER messenger_edit_no_delete BEFORE DELETE ON messenger_edits
 BEGIN SELECT RAISE(ABORT,'protected');END;
'''


class Sink:
    def __init__(self,owner=('tenant_a','ua')):
        self.owner=owner
        self.rows={}
        self.fail=False
        self.revoke=False

    def verified_identity(self):
        if self.revoke:
            raise RelayRefused('Revoked session')
        return self.owner

    def commit_payloads(self,stream,records):
        if self.fail:
            raise RelayRefused('DB failure')
        for msg in records:
            assert (msg.tenant,msg.actor)==self.owner
            key=(stream,msg.seq)
            actual=(msg.tenant,msg.actor,msg.entity_ref,msg.connection,
                    msg.body,msg.created_at,msg.content_sha256)
            if key in self.rows and self.rows[key]!=actual:
                raise RelayRefused('Conflict/altered replay')
            self.rows[key]=actual


@pytest.fixture
def db(tmp_path,monkeypatch):
    for k,v in {'JW_PG_CI_ALLOW':'ONLY_EPHEMERAL_LOCAL_DATABASE',
                'JW_PG_OUTBOX_V51':'ONLY_DISPOSABLE_LAB',
                'JW_PG_LAB_V54':'ONLY_DISPOSABLE_LAB',
                'JW_PG_LAB_V55':'ONLY_DISPOSABLE_LAB'}.items():
        monkeypatch.setenv(k,v)
    monkeypatch.delenv('JW_ENV',raising=False)
    src=sqlite3.connect(tmp_path/'relay.db',isolation_level=None)
    src.execute('PRAGMA foreign_keys=ON')
    src.executescript(SCHEMA)
    install_disposable_outbox(src)
    install_lab_snapshots(src)
    src.execute("INSERT INTO messenger_connections VALUES('thread','tenant_a','tenant_b')")
    yield src
    src.close()


def message(db,mid='m1',body='Hello 안녕하세요',**overrides):
    base={'id':mid,'org':'tenant_a','actor':'ua','thread':'thread','kind':'text',
          'body':body,'version':1,'created':'2026-10-21T15:00:01Z',
          'edited':None,'order':None,'snapshot':None,'name':''}
    base.update(overrides)
    db.execute('INSERT INTO messenger_messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',tuple(base.values()))


def ack(db):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(STATE,)).fetchone():
        return None
    rows=db.execute(f'SELECT ack_seq FROM {STATE}').fetchall()
    return rows[0][0] if rows else None


def test_synthetic_utf8_full_body_delivered_and_ack(db):
    message(db,body='원문 그대로 🌐 𓀀')
    sink=Sink()
    result=relay_payloads(db,sink)
    assert result=={'delivered':1,'ack_seq':1,'cutover_approved':False}
    record=next(iter(sink.rows.values()))
    assert record[4]=='원문 그대로 🌐 𓀀'
    assert record[-1]==sha256(record[4].encode('utf-8')).hexdigest()
    assert relay_payloads(db,sink)['delivered']==0


def test_two_plain_messages_order(db):
    message(db,'m1','one');message(db,'m2','two')
    sink=Sink()
    assert relay_payloads(db,sink,limit=1)['ack_seq']==1
    assert relay_payloads(db,sink,limit=1)['ack_seq']==2
    assert [v[4] for _,v in sorted(sink.rows.items())]==['one','two']


def test_commit_crash_then_idempotent_replay(db):
    message(db)
    sink=Sink()
    def crash():raise RuntimeError('after commit')
    with pytest.raises(RuntimeError):relay_payloads(db,sink,after_pg_commit=crash)
    assert ack(db)==0 and len(sink.rows)==1
    assert relay_payloads(db,sink)['ack_seq']==1
    assert len(sink.rows)==1


def test_tamper_between_commit_and_ack_refused(db):
    message(db)
    sink=Sink()
    with pytest.raises(RuntimeError):relay_payloads(db,sink,after_pg_commit=lambda: (_ for _ in ()).throw(RuntimeError()))
    # Legitimate versioned change produces a new immutable edit; original insert
    # can no longer be attested as an unchanged message and ACK stays zero.
    db.execute("INSERT INTO messenger_edits VALUES ('e1','m1','Hello 안녕하세요','changed','ua','now',2)")
    db.execute("UPDATE messenger_messages SET body='changed',version=2,edited_at='now' WHERE id='m1'")
    with pytest.raises(RelayRefused):relay_payloads(db,sink)
    assert ack(db)==0


def test_message_edits_block_unverified_original(db):
    message(db)
    db.execute("INSERT INTO messenger_edits VALUES('e1','m1','Hello 안녕하세요','new','ua','now',2)")
    db.execute("UPDATE messenger_messages SET body='new',version=2,edited_at='now' WHERE id='m1'")
    with pytest.raises(RelayRefused):relay_payloads(db,Sink())
    assert ack(db)==0


@pytest.mark.parametrize('change',[
    {'kind':'order','order':'order-1','snapshot':'{}','name':'Alice'},
    {'kind':'attachment'}, {'version':2}, {'edited':'yesterday'},
    {'org':'tenant_x'}, {'actor':'intruder'}, {'thread':'missing'},
    {'body':''}, {'body':'x'*33000}, {'name':'forged'},
])
def test_unsupported_or_invalid_message_rejected(db,change):
    message(db,**change)
    with pytest.raises(RelayRefused):relay_payloads(db,Sink())
    assert ack(db) in (0,None)


def test_attachment_source_blocks_full_body_relay(db):
    message(db)
    db.execute("INSERT INTO messenger_attachments VALUES('m1',?)",(b'binary',))
    with pytest.raises(RelayRefused):relay_payloads(db,Sink())
    assert ack(db)==0


def test_following_unsupported_event_blocks_entire_batch(db):
    message(db)
    db.execute("INSERT INTO messenger_read_positions VALUES('thread','tenant_a',1)")
    sink=Sink()
    with pytest.raises(RelayRefused):relay_payloads(db,sink)
    assert ack(db)==0 and not sink.rows


def test_wrong_signed_tenant_or_actor_fails(db):
    message(db)
    for who in [('tenant_b','ub'),('tenant_a','wrong')]:
        with pytest.raises(RelayRefused):relay_payloads(db,Sink(who))
        assert ack(db)==0


def test_pg_failure_ack_stays_zero(db):
    message(db);sink=Sink();sink.fail=True
    with pytest.raises(RelayRefused):relay_payloads(db,sink)
    assert ack(db)==0


def test_revoke_denies_retry(db):
    message(db);sink=Sink();sink.revoke=True
    with pytest.raises(RelayRefused):relay_payloads(db,sink)
    assert ack(db)==0


def test_production_denied_before_checkpoint(db,monkeypatch):
    message(db);monkeypatch.setenv('JW_ENV','PrOdUcTiOn')
    with pytest.raises(RelayRefused):relay_payloads(db,Sink())
    assert not db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(STATE,)).fetchone()


def test_missing_flag_denied(db,monkeypatch):
    message(db);monkeypatch.delenv('JW_PG_LAB_V55')
    with pytest.raises(RelayRefused):relay_payloads(db,Sink())
    assert ack(db) is None


@pytest.mark.parametrize('value',[0,-1,25,True,3.4,'2'])
def test_invalid_limit_refused(db,value):
    message(db)
    with pytest.raises(RelayRefused):relay_payloads(db,Sink(),limit=value)


def test_missing_immutable_snapshot_contract_rejected(db):
    db.execute('DROP TRIGGER jw_v54_snapshot_no_update')
    with pytest.raises(RelayRefused):relay_payloads(db,Sink())
    assert ack(db) is None


def test_checkpoint_schema_tamper_rejected(db):
    message(db)
    db.execute(f'CREATE TABLE {STATE}(ack_seq INTEGER)')
    with pytest.raises(RelayRefused):relay_payloads(db,Sink())


def test_pg_sink_instantiation_production_denied(db,monkeypatch):
    monkeypatch.setenv('JW_ENV','production')
    with pytest.raises(RelayRefused):Pg17PayloadLabSink('bad','token')


def test_legacy_outbox_stays_reference_only(db):
    message(db,body='인증 데이터 저장하지 말 것')
    rows=db.execute(f'SELECT event_type,entity_ref FROM {OUTBOX}').fetchall()
    assert rows==[('message.insert','m1')]
    assert '인증 데이터' not in repr(rows)


def test_tampered_durable_payload_before_replay_is_detected(db):
    message(db,body='original')
    sink=Sink()
    with pytest.raises(RuntimeError):
        relay_payloads(db,sink,after_pg_commit=lambda: (_ for _ in ()).throw(RuntimeError('synthetic crash')))
    key=next(iter(sink.rows))
    original=sink.rows[key]
    sink.rows[key]=original[:4]+('changed',)+original[5:]
    with pytest.raises(RelayRefused):relay_payloads(db,sink)
    assert ack(db)==0


def test_batch_pg_error_keeps_whole_checkpoint(db):
    message(db,'m1','one')
    message(db,'m2','two')
    sink=Sink();sink.fail=True
    with pytest.raises(RelayRefused):relay_payloads(db,sink)
    assert ack(db)==0
    assert not sink.rows
