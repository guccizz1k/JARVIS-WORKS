"""V5.4 isolated real-SQLite mutation-time provenance tests; no PG or customer data."""
import os
import sqlite3
import pytest

from app.pg_transition_outbox_v51 import install_disposable_outbox, OUTBOX
from app.pg_mutation_snapshot_v54 import (install_lab_snapshots, audit_lab_snapshots,
                                              SnapshotRefused, JOURNAL)

SCHEMA = '''
CREATE TABLE messenger_connections(id TEXT PRIMARY KEY,org_a TEXT,org_b TEXT);
CREATE TABLE messenger_messages(id TEXT PRIMARY KEY, sender_org TEXT,sender_user TEXT,
 connection_id TEXT,body TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1);
CREATE TABLE messenger_edits(id TEXT PRIMARY KEY,message_id TEXT,previous_body TEXT,
 new_body TEXT,actor_user TEXT,edited_at TEXT,version INTEGER,
 UNIQUE(message_id,version));
CREATE TABLE messenger_attachments(message_id TEXT PRIMARY KEY,data BLOB);
CREATE TABLE messenger_receipts(message_id TEXT PRIMARY KEY,receiver_org TEXT,receiver_user TEXT,received_at TEXT);
CREATE TABLE messenger_read_positions(connection_id TEXT,org_id TEXT,last_read_seq INTEGER,
 PRIMARY KEY(connection_id,org_id));
CREATE TRIGGER messenger_edit_no_update BEFORE UPDATE ON messenger_edits
 BEGIN SELECT RAISE(ABORT,'protected'); END;
CREATE TRIGGER messenger_edit_no_delete BEFORE DELETE ON messenger_edits
 BEGIN SELECT RAISE(ABORT,'protected'); END;
'''

@pytest.fixture
def c(tmp_path,monkeypatch):
    for key,value in {'JW_PG_OUTBOX_V51':'ONLY_DISPOSABLE_LAB',
        'JW_PG_CI_ALLOW':'ONLY_EPHEMERAL_LOCAL_DATABASE',
        'JW_PG_LAB_V54':'ONLY_DISPOSABLE_LAB'}.items():
        monkeypatch.setenv(key,value)
    monkeypatch.delenv('JW_ENV',raising=False)
    db=sqlite3.connect(tmp_path/'v54.db',isolation_level=None)
    db.execute('PRAGMA foreign_keys=ON')
    db.executescript(SCHEMA)
    install_disposable_outbox(db)
    yield db
    db.close()

def init(c):
    install_lab_snapshots(c)
    c.execute("INSERT INTO messenger_connections VALUES('chat','tenant_a','tenant_b')")
    c.execute("INSERT INTO messenger_messages VALUES('m','tenant_a','alice','chat','hello',1)")

def edit(c,editid,ver,old,new):
    c.execute("INSERT INTO messenger_edits VALUES(?,?,?,?,?,?,?)",
              (editid,'m',old,new,'alice','2026-10-21Z',ver))
    c.execute('UPDATE messenger_messages SET body=?,version=? WHERE id=?',(new,ver,'m'))

def events(c):
    return c.execute(f'SELECT seq,event_type,entity_ref FROM {OUTBOX} ORDER BY seq').fetchall()

def journal(c):
    return c.execute(f'SELECT outbox_seq,event_type,entity_ref,edit_id,edit_version,read_seq FROM {JOURNAL} ORDER BY outbox_seq').fetchall()


def test_new_lab_install_and_idempotence(c):
    install_lab_snapshots(c);install_lab_snapshots(c)
    assert audit_lab_snapshots(c)['snapshot_count']==0


def test_edit_at_write_time_survives_next_edit(c):
    init(c);edit(c,'e1',2,'hello','secret1');edit(c,'e2',3,'secret1','secret2')
    assert [x[3:5] for x in journal(c)]==[('e1',2),('e2',3)]
    a=audit_lab_snapshots(c)
    assert a['snapshot_count']==2 and a['cutover_approved'] is False
    assert 'secret1' not in str(a) and 'secret2' not in str(a)


def test_edit_without_immutable_record_aborts_original_update(c):
    init(c)
    prior=events(c)
    with pytest.raises(sqlite3.IntegrityError,match='unmatched immutable edit'):
        c.execute("UPDATE messenger_messages SET body='bad',version=2 WHERE id='m'")
    assert events(c)==prior and journal(c)==[]
    assert c.execute('SELECT body,version FROM messenger_messages WHERE id="m"').fetchone()==('hello',1)


def test_mismatched_edit_body_aborts(c):
    init(c)
    c.execute("INSERT INTO messenger_edits VALUES('e1','m','bad-old','new','alice','now',2)")
    with pytest.raises(sqlite3.IntegrityError,match='unmatched immutable edit'):
        c.execute("UPDATE messenger_messages SET body='new',version=2 WHERE id='m'")
    assert journal(c)==[]


def test_read_positions_capture_historical_increment(c):
    init(c)
    c.execute("INSERT INTO messenger_read_positions VALUES('chat','tenant_b',1)")
    c.execute("UPDATE messenger_read_positions SET last_read_seq=4 WHERE org_id='tenant_b'")
    c.execute("UPDATE messenger_read_positions SET last_read_seq=7 WHERE org_id='tenant_b'")
    assert [r[-1] for r in journal(c)]==[1,4,7]
    a=audit_lab_snapshots(c)
    assert a['snapshot_count']==3 and a['read_actor_verified'] is False
    assert a['pg_delivery_implemented'] is False


def test_read_noop_has_no_new_event(c):
    init(c)
    c.execute("INSERT INTO messenger_read_positions VALUES('chat','tenant_a',5)")
    before=journal(c)
    c.execute("UPDATE messenger_read_positions SET last_read_seq=5 WHERE org_id='tenant_a'")
    assert journal(c)==before


def test_both_event_types_keep_v51_seq(c):
    init(c)
    edit(c,'e1',2,'hello','world')
    c.execute("INSERT INTO messenger_read_positions VALUES('chat','tenant_a',3)")
    tagged={(r[0],r[1],r[2]) for r in journal(c)}
    assert tagged=={(r[0],r[1],r[2]) for r in events(c) if r[1] in
                  {'message.body_changed','read_position.insert','read_position.advance'}}


def test_sqlite_rollback_removes_both_source_event_and_snapshot(c):
    init(c)
    c.execute('BEGIN IMMEDIATE')
    edit(c,'e1',2,'hello','temporary')
    assert len(journal(c))==1
    c.execute('ROLLBACK')
    assert journal(c)==[]
    assert events(c)==[(1,'message.insert','m')]
    assert c.execute('SELECT body FROM messenger_messages').fetchone()==('hello',)


def test_forbid_existing_events_install(c):
    c.execute("INSERT INTO messenger_messages VALUES('m','tenant_a','alice','chat','hello',1)")
    with pytest.raises(SnapshotRefused,match='historical'):
        install_lab_snapshots(c)
    assert c.execute("SELECT name FROM sqlite_master WHERE name=?",(JOURNAL,)).fetchone() is None

@pytest.mark.parametrize('key,value',[('JW_ENV','production'),('JW_ENV','PrOdUcTiOn'),
 ('JW_PG_LAB_V54','wrong'),('JW_PG_CI_ALLOW','no')])
def test_lab_denial_before_ddl(c,monkeypatch,key,value):
    monkeypatch.setenv(key,value)
    with pytest.raises(SnapshotRefused):install_lab_snapshots(c)
    assert c.execute('SELECT 1 FROM sqlite_master WHERE name=?',(JOURNAL,)).fetchone() is None


def test_foreign_temp_symlink_denied(tmp_path,monkeypatch):
    monkeypatch.setenv('JW_PG_LAB_V54','ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_OUTBOX_V51','ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    c=sqlite3.connect(':memory:',isolation_level=None)
    with pytest.raises(SnapshotRefused):install_lab_snapshots(c)
    c.close()


def test_receipt_cannot_update_or_delete(c):
    init(c)
    c.execute("INSERT INTO messenger_receipts VALUES('m','tenant_b','bob','now')")
    for sql in ["UPDATE messenger_receipts SET received_at='later' WHERE message_id='m'",
                "DELETE FROM messenger_receipts WHERE message_id='m'"]:
        with pytest.raises(sqlite3.IntegrityError):c.execute(sql)


def test_no_update_or_delete_journal(c):
    init(c)
    c.execute("INSERT INTO messenger_read_positions VALUES('chat','tenant_a',1)")
    for sql in [f'UPDATE {JOURNAL} SET read_seq=100',f'DELETE FROM {JOURNAL}']:
        with pytest.raises(sqlite3.IntegrityError):c.execute(sql)


def test_replaced_trigger_tampering_detected(c):
    init(c)
    c.execute('DROP TRIGGER jw_v51_read_advance')
    with pytest.raises(SnapshotRefused):audit_lab_snapshots(c)
    with pytest.raises(SnapshotRefused):install_lab_snapshots(c)


def test_unexpected_cursor_org_rejected_at_audit(c):
    init(c)
    c.execute("INSERT INTO messenger_read_positions VALUES('chat','intruder',1)")
    with pytest.raises(SnapshotRefused,match='tenant relationship'):
        audit_lab_snapshots(c)


def test_checkpoint_blocks_reinstall(c):
    c.execute('CREATE TABLE jw_relay_checkpoint_v52 (stream_id TEXT,ack_seq INTEGER)')
    with pytest.raises(SnapshotRefused,match='checkpoint'):
        install_lab_snapshots(c)


def test_bad_version_schema_blocks_install(c):
    c.execute('DROP TABLE messenger_messages')
    c.execute('CREATE TABLE messenger_messages (id TEXT,body TEXT,sender_org TEXT)')
    with pytest.raises(SnapshotRefused,match='trigger contract|schema'):
        install_lab_snapshots(c)


def test_audit_cursor_decreased_fails(c):
    init(c)
    c.execute("INSERT INTO messenger_read_positions VALUES('chat','tenant_a',5)")
    c.execute("UPDATE messenger_read_positions SET last_read_seq=3 WHERE org_id='tenant_a'")
    with pytest.raises(SnapshotRefused,match='contradicts'):
        audit_lab_snapshots(c)


def test_fake_receipt_trigger_cannot_silently_disable_protection(c):
    c.execute('CREATE TRIGGER messenger_receipt_no_update BEFORE UPDATE ON messenger_receipts BEGIN SELECT 1; END;')
    with pytest.raises(SnapshotRefused,match='receipt trigger'):
        install_lab_snapshots(c)
    assert c.execute("SELECT 1 FROM sqlite_master WHERE name=?",(JOURNAL,)).fetchone() is None


def test_edit_immutability_trigger_removed_detected(c):
    init(c)
    c.execute('DROP TRIGGER messenger_edit_no_update')
    with pytest.raises(SnapshotRefused,match='protection'):
        audit_lab_snapshots(c)


def test_read_snapshot_missing_detected(c):
    init(c)
    c.execute("INSERT INTO messenger_read_positions VALUES('chat','tenant_b',5)")
    c.execute('DROP TRIGGER jw_v54_snapshot_no_delete')
    c.execute(f'DELETE FROM {JOURNAL}')
    c.execute('CREATE TRIGGER jw_v54_snapshot_no_delete BEFORE DELETE ON jw_mutation_snapshots_v54 BEGIN SELECT RAISE(ABORT,\'protected\');END;')
    with pytest.raises(SnapshotRefused,match='Missing or extra'):
        audit_lab_snapshots(c)
