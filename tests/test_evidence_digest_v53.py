"""Pure ephemeral SQLite fault-injection; real PG17 integration is NOT RUN."""
import hashlib
import os
import sqlite3
import pytest

from app.pg_transition_outbox_v51 import install_disposable_outbox, OUTBOX
from app.pg_outbox_relay_v52 import RelayRefused
from app.pg_evidence_digest_v53 import relay_evidence, STATE

SCHEMA = """
CREATE TABLE messenger_messages(id TEXT PRIMARY KEY,sender_org TEXT NOT NULL,sender_user TEXT NOT NULL,
connection_id TEXT NOT NULL,body TEXT NOT NULL);
CREATE TABLE messenger_connections(id TEXT PRIMARY KEY,org_a TEXT NOT NULL,org_b TEXT NOT NULL);
CREATE TABLE messenger_edits(id TEXT PRIMARY KEY,message_id TEXT,previous_body TEXT,new_body TEXT,
actor_user TEXT,edited_at TEXT,version INTEGER);
CREATE TABLE messenger_attachments(message_id TEXT PRIMARY KEY, filename TEXT,mime TEXT,
data BLOB,size_bytes INTEGER,content_hash TEXT);
CREATE TABLE messenger_receipts(message_id TEXT PRIMARY KEY,receiver_org TEXT,
receiver_user TEXT,received_at TEXT);
CREATE TABLE messenger_read_positions(connection_id TEXT,org_id TEXT,last_read_seq INTEGER,
PRIMARY KEY(connection_id,org_id));
CREATE TRIGGER messenger_attachment_no_update BEFORE UPDATE ON messenger_attachments
BEGIN SELECT RAISE(ABORT,'protected');END;
CREATE TRIGGER messenger_attachment_no_delete BEFORE DELETE ON messenger_attachments
BEGIN SELECT RAISE(ABORT,'protected');END;
CREATE TRIGGER messenger_edit_no_update BEFORE UPDATE ON messenger_edits
BEGIN SELECT RAISE(ABORT,'protected');END;
CREATE TRIGGER messenger_edit_no_delete BEFORE DELETE ON messenger_edits
BEGIN SELECT RAISE(ABORT,'protected');END;
"""

class Sink:
    def __init__(self, org='a', actor='alice'):
        self.org,self.actor=org,actor
        self.data={}
        self.down=False
    def verified_identity(self):
        return self.org,self.actor
    def commit_events(self, stream, events):
        if self.down:raise OSError('PG unavailable')
        updated={}
        for e in events:
            key=(stream,e.seq)
            value=(e.org,e.actor,e.event_type,e.ref,e.digest,e.evidence_digest)
            existing=updated.get(key,self.data.get(key))
            if existing is not None and existing!=value:
                raise RelayRefused('Conflicting PG evidence event')
            updated[key]=value
        self.data.update(updated)

@pytest.fixture
def state(tmp_path, monkeypatch):
    for k,v in {
        'JW_PG_OUTBOX_V51':'ONLY_DISPOSABLE_LAB',
        'JW_PG_CI_ALLOW':'ONLY_EPHEMERAL_LOCAL_DATABASE',
        'JW_PG_LAB_V52':'ONLY_DISPOSABLE_LAB',
        'JW_PG_RELAY_V52':'ONLY_DISPOSABLE_LAB',
        'JW_PG_LAB_V53':'ONLY_DISPOSABLE_LAB',
    }.items():monkeypatch.setenv(k,v)
    monkeypatch.delenv('JW_ENV',raising=False)
    db=sqlite3.connect(tmp_path/'fixture.db',isolation_level=None)
    db.execute('PRAGMA foreign_keys=ON')
    db.executescript(SCHEMA)
    install_disposable_outbox(db)
    db.execute("INSERT INTO messenger_connections VALUES ('t1','a','b')")
    yield db
    db.close()


def msg(c, mid='m1', org='a', actor='alice'):
    c.execute("INSERT INTO messenger_messages VALUES (?,?,?,?,?)",(mid,org,actor,'t1','TOP SECRET'))

def attachment(c,mid='m1', content=b'%PDF-1.4 evidence'):
    c.execute("INSERT INTO messenger_attachments VALUES (?,?,?,?,?,?)",
              (mid,'proof.pdf','application/pdf',content,len(content),hashlib.sha256(content).hexdigest()))

def ack(c):
    present=c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (STATE,)).fetchone()
    if not present:return None
    result=c.execute(f'SELECT ack_seq FROM {STATE}').fetchone()
    return result[0] if result else None


def test_default_off_before_checkpoint(state,monkeypatch):
    msg(state);monkeypatch.delenv('JW_PG_LAB_V53')
    with pytest.raises(RelayRefused): relay_evidence(state,Sink())
    assert ack(state) is None

@pytest.mark.parametrize('name,value',[
    ('JW_ENV','production'),('JW_ENV','PRODUCTION'),
    ('JW_PG_LAB_V53','yes'),('JW_PG_RELAY_V52','yes'),
    ('JW_PG_OUTBOX_V51',''),('JW_PG_CI_ALLOW','wrong'),
])
def test_unsafe_env_denied(state,monkeypatch,name,value):
    monkeypatch.setenv(name,value)
    with pytest.raises(RelayRefused): relay_evidence(state,Sink())


def test_message_reference_is_not_secret(state):
    msg(state);sink=Sink()
    assert relay_evidence(state,sink)['delivered']==1
    assert len(sink.data)==1
    assert 'TOP SECRET' not in str(sink.data)
    assert relay_evidence(state,sink)['delivered']==0


def test_attachment_digest_no_bytes_exposed(state):
    msg(state);attachment(state);sink=Sink()
    assert relay_evidence(state,sink)['delivered']==2
    assert len(sink.data)==2
    assert '%PDF' not in str(sink.data)
    assert b'%PDF' not in repr(sink.data).encode()


def test_attachment_corruption_no_ack(state):
    msg(state);attachment(state);sink=Sink()
    state.execute('DROP TRIGGER messenger_attachment_no_update')
    state.execute("UPDATE messenger_attachments SET content_hash='0' WHERE message_id='m1'")
    state.execute('CREATE TRIGGER messenger_attachment_no_update BEFORE UPDATE ON messenger_attachments BEGIN SELECT RAISE(ABORT,\'protected\');END;')
    with pytest.raises(RelayRefused): relay_evidence(state,sink)
    assert ack(state)==0 and sink.data=={}


def test_attachment_wrong_size_no_ack(state):
    msg(state);attachment(state);sink=Sink()
    state.execute('DROP TRIGGER messenger_attachment_no_update')
    state.execute("UPDATE messenger_attachments SET size_bytes=100 WHERE message_id='m1'")
    state.execute('CREATE TRIGGER messenger_attachment_no_update BEFORE UPDATE ON messenger_attachments BEGIN SELECT RAISE(ABORT,\'protected\');END;')
    with pytest.raises(RelayRefused): relay_evidence(state,sink)
    assert ack(state)==0


def test_edit_evidence_only_hashes(state):
    msg(state)
    state.execute("INSERT INTO messenger_edits VALUES ('e1','m1','TOP SECRET','NEW SECRET','alice','2026-01-01Z',2)")
    sink=Sink();assert relay_evidence(state,sink)['delivered']==2
    assert not any(secret in str(sink.data) for secret in ('TOP SECRET','NEW SECRET'))


def test_edit_wrong_actor_refused(state):
    msg(state)
    state.execute("INSERT INTO messenger_edits VALUES ('e1','m1','before','after','mallory','time',2)")
    with pytest.raises(RelayRefused):relay_evidence(state,Sink())
    assert ack(state)==0


def test_receipt_requires_immutability(state):
    msg(state,org='a',actor='alice')
    state.execute("INSERT INTO messenger_receipts VALUES ('m1','b','bob','time')")
    with pytest.raises(RelayRefused,match='mutable'):relay_evidence(state,Sink('a','alice'))
    assert ack(state)==0


def test_receipt_immutable_other_org_signer(state):
    msg(state)
    state.executescript('''
CREATE TRIGGER messenger_receipt_no_update BEFORE UPDATE ON messenger_receipts BEGIN SELECT RAISE(ABORT,'protected');END;
CREATE TRIGGER messenger_receipt_no_delete BEFORE DELETE ON messenger_receipts BEGIN SELECT RAISE(ABORT,'protected');END;''')
    state.execute("INSERT INTO messenger_receipts VALUES ('m1','b','bob','time')")
    sinkA=Sink();assert relay_evidence(state,sinkA,limit=1)['ack_seq']==1
    sinkB=Sink('b','bob');assert relay_evidence(state,sinkB,limit=1)['ack_seq']==2
    assert len(sinkA.data)==1 and len(sinkB.data)==1


def test_cross_org_blocks_atomic_batch(state):
    msg(state)
    state.execute("INSERT INTO messenger_messages VALUES ('m2','b','bob','t1','secret')")
    sink=Sink()
    with pytest.raises(RelayRefused):relay_evidence(state,sink)
    assert ack(state)==0 and sink.data=={}


def test_read_cursor_blocks_pending_event(state):
    msg(state)
    state.execute("INSERT INTO messenger_read_positions VALUES ('t1','a',1)")
    sink=Sink()
    with pytest.raises(RelayRefused):relay_evidence(state,sink)
    assert ack(state)==0 and sink.data=={}


def test_body_change_blocks_until_historical_mapping(state):
    msg(state)
    state.execute("UPDATE messenger_messages SET body='NEW' WHERE id='m1'")
    with pytest.raises(RelayRefused):relay_evidence(state,Sink())
    assert ack(state)==0


def test_postcommit_crash_and_retry_no_duplicates(state):
    msg(state);sink=Sink()
    def crash():raise RuntimeError('simulated after PG commit')
    with pytest.raises(RuntimeError):relay_evidence(state,sink,after_pg_commit=crash)
    assert ack(state)==0 and len(sink.data)==1
    assert relay_evidence(state,sink)['ack_seq']==1
    assert len(sink.data)==1


def test_pg_offline_no_checkpoint(state):
    msg(state);sink=Sink();sink.down=True
    with pytest.raises(OSError):relay_evidence(state,sink)
    assert ack(state)==0


def test_existing_checkpoint_tamper_denied(state):
    msg(state);sink=Sink();relay_evidence(state,sink)
    state.execute(f'UPDATE {STATE} SET ack_seq=999')
    with pytest.raises(RelayRefused):relay_evidence(state,sink)


def test_source_rollback_no_event(state):
    sink=Sink();state.execute('BEGIN IMMEDIATE');msg(state);state.execute('ROLLBACK')
    assert relay_evidence(state,sink)['delivered']==0

@pytest.mark.parametrize('limit',[0,33,-1,True,'1',1.2])
def test_bad_limit(state,limit):
    with pytest.raises(RelayRefused):relay_evidence(state,Sink(),limit=limit)


def test_evidence_table_trigger_removed_fails_closed(state):
    state.execute('DROP TRIGGER messenger_edit_no_delete')
    with pytest.raises(RelayRefused):relay_evidence(state,Sink())


def test_duplicate_ref_pg_tamper_conflict(state):
    msg(state);sink=Sink()
    with pytest.raises(RuntimeError):relay_evidence(state,sink,after_pg_commit=lambda:(_ for _ in ()).throw(RuntimeError('crash')))
    k=next(iter(sink.data));sink.data[k]=('tampered',)*6
    with pytest.raises(RelayRefused):relay_evidence(state,sink)
    assert ack(state)==0


def test_only_explicit_evidence_types_are_accepted(state):
    msg(state)
    state.execute(f"INSERT INTO {OUTBOX}(event_type,entity_ref) VALUES ('read_position.advance','t1:a')")
    with pytest.raises(RelayRefused):relay_evidence(state,Sink())
