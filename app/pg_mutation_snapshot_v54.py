"""V5.4 isolated, immutable mutation-time evidence journal for the B2B SQLite demo.

NOT a production migration or a message/attachment writer. Installs only on a
fresh, temp-file SQLite that has V5.1 lab triggers; refuses existing outbox
rows and non-lab DBs. Replaces three V5.1 *lab* triggers transactionally to
atomically correlate mutable source events with immutable write-time metadata.
No plaintext body, secrets, or attachment bytes are copied to the journal.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3

from app.pg_transition_outbox_v51 import _authorize, OUTBOX, OutboxRefused

FLAG = 'JW_PG_LAB_V54'
LAB = 'ONLY_DISPOSABLE_LAB'
JOURNAL = 'jw_mutation_snapshots_v54'
SUPPORTED = {'message.body_changed', 'read_position.insert', 'read_position.advance'}
REPLACED = {
    'jw_v51_message_body': ('messenger_messages', 'message.body_changed'),
    'jw_v51_read_new': ('messenger_read_positions', 'read_position.insert'),
    'jw_v51_read_advance': ('messenger_read_positions', 'read_position.advance'),
}


class SnapshotRefused(RuntimeError):
    pass


def _gate(c: sqlite3.Connection) -> None:
    if os.getenv(FLAG) != LAB or os.getenv('JW_ENV', '').casefold() == 'production':
        raise SnapshotRefused('V5.4 disposable lab authorization required')
    try:
        _authorize(c)
    except OutboxRefused as exc:
        raise SnapshotRefused('V5.1 temporary source authorization failed') from exc
    if c.isolation_level is not None:
        raise SnapshotRefused('SQLite explicit autocommit required')
    if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (OUTBOX,)).fetchone() is None:
        raise SnapshotRefused('V5.1 outbox must already be installed')


def _installed(c: sqlite3.Connection) -> bool:
    row = c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (JOURNAL,)).fetchone()
    return bool(row)


def _verify_existing(c: sqlite3.Connection, *, replaced: bool) -> None:
    rows = {r[0]: r[1] for r in c.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'")}
    for name,(table,kind) in REPLACED.items():
        sql = (rows.get(name) or '').lower()
        if table not in sql or kind not in sql or ('jw_mutation_snapshots_v54' in sql) != replaced:
            raise SnapshotRefused('Unexpected or modified source trigger contract')
    if replaced:
        for trigger in ('jw_v54_snapshot_no_update', 'jw_v54_snapshot_no_delete',
                        'messenger_receipt_no_update', 'messenger_receipt_no_delete',
                        'messenger_edit_no_update', 'messenger_edit_no_delete'):
            sql = (rows.get(trigger) or '').lower().replace(' ', '')
            if 'raise(abort' not in sql:
                raise SnapshotRefused('Immutable evidence protection missing or modified')
        cols = {r[1] for r in c.execute(f'PRAGMA table_info({JOURNAL})')}
        if cols != {'outbox_seq','event_type','entity_ref','edit_id','edit_version',
                    'connection_id','org_id','read_seq'}:
            raise SnapshotRefused('Immutable journal schema altered')


def install_lab_snapshots(c: sqlite3.Connection) -> None:
    """Install correlated append-only source evidence before first outbox event.

    V5.1 outbox stream remains the same; its original trigger *source files*
    remain untouched. DDL is in one SQLite transaction: on failure V5.1
    triggers and journal are restored to their exact prior DB state.
    """
    _gate(c)
    if _installed(c):
        _verify_existing(c, replaced=True)
        return
    _verify_existing(c, replaced=False)
    # Never accept an existing same-name receipt trigger that suppresses the
    # protective CREATE IF NOT EXISTS without enforcing immutability.
    receipt_sql = {r[0]: r[1] for r in c.execute(
        "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name LIKE 'messenger_receipt_no_%'")}
    for trigger in ('messenger_receipt_no_update','messenger_receipt_no_delete'):
        if trigger in receipt_sql and 'raise(abort' not in (receipt_sql[trigger] or '').lower().replace(' ',''):
            raise SnapshotRefused('Existing receipt trigger does not enforce immutability')
    if c.execute(f'SELECT COUNT(*) FROM {OUTBOX}').fetchone()[0] != 0:
        raise SnapshotRefused('Cannot install after historical events without baseline')
    for name in ('jw_relay_checkpoint_v52','jw_evidence_checkpoint_v53'):
        if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone():
            raise SnapshotRefused('Existing checkpoint requires supervised restart')
    columns = {r[1] for r in c.execute('PRAGMA table_info(messenger_messages)')}
    if not {'id','sender_user','version','body'}.issubset(columns):
        raise SnapshotRefused('Versioned message schema required')
    for table,fields in {
        'messenger_edits': {'id','message_id','actor_user','version','previous_body','new_body'},
        'messenger_read_positions': {'connection_id','org_id','last_read_seq'},
        'messenger_receipts': {'message_id'},
    }.items():
        found={r[1] for r in c.execute('PRAGMA table_info('+table+')')}
        if not fields.issubset(found):
            raise SnapshotRefused('Full legacy schema missing required fields')
    try:
        c.executescript('''
        BEGIN IMMEDIATE;
        CREATE TABLE jw_mutation_snapshots_v54 (
          outbox_seq INTEGER PRIMARY KEY REFERENCES jw_transition_outbox_v51(seq),
          event_type TEXT NOT NULL CHECK(event_type IN
           ('message.body_changed','read_position.insert','read_position.advance')),
          entity_ref TEXT NOT NULL,
          edit_id TEXT, edit_version INTEGER,
          connection_id TEXT, org_id TEXT, read_seq INTEGER,
          CHECK ((event_type='message.body_changed' AND edit_id IS NOT NULL
            AND edit_version IS NOT NULL AND connection_id IS NULL
            AND org_id IS NULL AND read_seq IS NULL)
          OR (event_type!='message.body_changed' AND edit_id IS NULL
            AND edit_version IS NULL AND connection_id IS NOT NULL
            AND org_id IS NOT NULL AND read_seq>=0))
        );
        CREATE TRIGGER jw_v54_snapshot_no_update BEFORE UPDATE ON jw_mutation_snapshots_v54
          BEGIN SELECT RAISE(ABORT,'immutable snapshot'); END;
        CREATE TRIGGER jw_v54_snapshot_no_delete BEFORE DELETE ON jw_mutation_snapshots_v54
          BEGIN SELECT RAISE(ABORT,'immutable snapshot'); END;
        CREATE TRIGGER IF NOT EXISTS messenger_receipt_no_update BEFORE UPDATE ON messenger_receipts
          BEGIN SELECT RAISE(ABORT,'receipt immutable'); END;
        CREATE TRIGGER IF NOT EXISTS messenger_receipt_no_delete BEFORE DELETE ON messenger_receipts
          BEGIN SELECT RAISE(ABORT,'receipt immutable'); END;
        DROP TRIGGER jw_v51_message_body;
        DROP TRIGGER jw_v51_read_new;
        DROP TRIGGER jw_v51_read_advance;
        CREATE TRIGGER jw_v51_message_body AFTER UPDATE OF body ON messenger_messages
        WHEN NEW.body IS NOT OLD.body
        BEGIN
          SELECT RAISE(ABORT,'unmatched immutable edit') WHERE NOT EXISTS (
            SELECT 1 FROM messenger_edits e WHERE e.message_id=NEW.id
              AND e.version=NEW.version AND e.actor_user=NEW.sender_user
              AND e.previous_body=OLD.body AND e.new_body=NEW.body
          );
          INSERT INTO jw_transition_outbox_v51(event_type,entity_ref)
            VALUES('message.body_changed', NEW.id);
          INSERT INTO jw_mutation_snapshots_v54(
            outbox_seq,event_type,entity_ref,edit_id,edit_version)
            SELECT last_insert_rowid(),'message.body_changed',NEW.id,e.id,NEW.version
            FROM messenger_edits e WHERE e.message_id=NEW.id AND e.version=NEW.version
              AND e.actor_user=NEW.sender_user AND e.previous_body=OLD.body
              AND e.new_body=NEW.body;
        END;
        CREATE TRIGGER jw_v51_read_new AFTER INSERT ON messenger_read_positions
        BEGIN
          INSERT INTO jw_transition_outbox_v51(event_type,entity_ref)
            VALUES('read_position.insert',NEW.connection_id || ':' || NEW.org_id);
          INSERT INTO jw_mutation_snapshots_v54(
             outbox_seq,event_type,entity_ref,connection_id,org_id,read_seq)
            VALUES(last_insert_rowid(),'read_position.insert',NEW.connection_id || ':' || NEW.org_id,
              NEW.connection_id,NEW.org_id,NEW.last_read_seq);
        END;
        CREATE TRIGGER jw_v51_read_advance AFTER UPDATE OF last_read_seq ON messenger_read_positions
        WHEN NEW.last_read_seq > OLD.last_read_seq
        BEGIN
          INSERT INTO jw_transition_outbox_v51(event_type,entity_ref)
            VALUES('read_position.advance',NEW.connection_id || ':' || NEW.org_id);
          INSERT INTO jw_mutation_snapshots_v54(
             outbox_seq,event_type,entity_ref,connection_id,org_id,read_seq)
            VALUES(last_insert_rowid(),'read_position.advance',NEW.connection_id || ':' || NEW.org_id,
              NEW.connection_id,NEW.org_id,NEW.last_read_seq);
        END;
        COMMIT;
        ''')
    except BaseException:
        if c.in_transaction:
            c.rollback()
        raise
    _verify_existing(c,replaced=True)


def audit_lab_snapshots(c: sqlite3.Connection) -> dict:
    """Audit immutable per-event write-time provenance without exposing contents.

    This does not authorize PG delivery: read positions lack a signed actor.
    Replay, business payload replication, and production cutover remain blocked.
    """
    _gate(c)
    if not _installed(c):
        raise SnapshotRefused('V5.4 snapshot journal missing')
    _verify_existing(c,replaced=True)
    kinds=tuple(sorted(SUPPORTED))
    expected=c.execute(
        f'SELECT seq,event_type,entity_ref FROM {OUTBOX} WHERE event_type IN (?,?,?) ORDER BY seq', kinds).fetchall()
    saved=c.execute(f'''SELECT outbox_seq,event_type,entity_ref,edit_id,edit_version,
       connection_id,org_id,read_seq FROM {JOURNAL} ORDER BY outbox_seq''').fetchall()
    if len(expected)!=len(saved):
        raise SnapshotRefused('Missing or extra mutation snapshots')
    digests=[]; prevseq={}
    for evt,row in zip(expected,saved):
        seq,kind,ref,eid,version,thread,org,readseq=row
        if (seq,kind,ref)!=tuple(evt):
            raise SnapshotRefused('Mutation event linkage mismatch')
        if kind=='message.body_changed':
            rows=c.execute('''SELECT e.id,e.message_id,e.version,e.actor_user,
                    e.previous_body,e.new_body,m.sender_user
                FROM messenger_edits e JOIN messenger_messages m ON m.id=e.message_id
                WHERE e.id=?''',(eid,)).fetchall()
            if len(rows)!=1 or rows[0][0]!=eid or rows[0][1]!=ref or rows[0][2]!=version or rows[0][3]!=rows[0][6]:
                raise SnapshotRefused('Historical edit provenance changed')
            evidence={'sequence':seq,'kind':kind,'ref':ref,'edit_id':eid,'version':version,
                'before_sha256':hashlib.sha256(rows[0][4].encode()).hexdigest(),
                'after_sha256':hashlib.sha256(rows[0][5].encode()).hexdigest()}
        else:
            if not isinstance(thread,str) or not thread or not isinstance(org,str) or not org or type(readseq) is not int or readseq<0:
                raise SnapshotRefused('Invalid historical read position')
            relationship=c.execute('SELECT org_a,org_b FROM messenger_connections WHERE id=?',(thread,)).fetchall()
            if len(relationship)!=1 or org not in relationship[0] or ref!=thread+':'+org:
                raise SnapshotRefused('Read cursor tenant relationship invalid')
            key=(thread,org)
            old=prevseq.get(key)
            if old is not None and (kind!='read_position.advance' or readseq<=old):
                raise SnapshotRefused('Read cursor history nonmonotonic')
            if old is None and kind!='read_position.insert':
                raise SnapshotRefused('Missing first read position')
            prevseq[key]=readseq
            evidence={'sequence':seq,'kind':kind,'ref':ref,'connection':thread,
                      'tenant':org,'read_seq':readseq,'actor_verified':False}
        digests.append(hashlib.sha256(json.dumps(evidence,sort_keys=True,separators=(',',':')).encode()).hexdigest())
    for (thread,org),value in prevseq.items():
        current=c.execute('''SELECT last_read_seq FROM messenger_read_positions
          WHERE connection_id=? AND org_id=?''',(thread,org)).fetchone()
        if current is None or current[0]<value:
            raise SnapshotRefused('Current cursor contradicts immutable history')
    return {'snapshot_count':len(saved),'sha256':hashlib.sha256(''.join(digests).encode()).hexdigest(),
            'source_history_attested':True,'cutover_approved':False,
            'read_actor_verified':False,'pg_delivery_implemented':False}
