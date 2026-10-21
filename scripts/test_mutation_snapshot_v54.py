"""Standalone V5.4 real SQLite synthetic write-path / rollback rehearsal.
No network, PostgreSQL writes, live employees or operational cutover.
"""
import os
import sqlite3
import tempfile
from pathlib import Path
from app.pg_transition_outbox_v51 import install_disposable_outbox
from app.pg_mutation_snapshot_v54 import install_lab_snapshots,audit_lab_snapshots,SnapshotRefused

SCHEMA='''
CREATE TABLE messenger_connections(id TEXT PRIMARY KEY,org_a TEXT,org_b TEXT);
CREATE TABLE messenger_messages(id TEXT PRIMARY KEY,sender_org TEXT,sender_user TEXT,
 connection_id TEXT,body TEXT,version INTEGER NOT NULL);
CREATE TABLE messenger_edits(id TEXT PRIMARY KEY,message_id TEXT,previous_body TEXT,
 new_body TEXT,actor_user TEXT,edited_at TEXT,version INTEGER,UNIQUE(message_id,version));
CREATE TABLE messenger_attachments(message_id TEXT PRIMARY KEY,data BLOB);
CREATE TABLE messenger_receipts(message_id TEXT PRIMARY KEY,receiver_org TEXT,
 receiver_user TEXT,received_at TEXT);
CREATE TABLE messenger_read_positions(connection_id TEXT,org_id TEXT,last_read_seq INTEGER,
 PRIMARY KEY(connection_id,org_id));
CREATE TRIGGER messenger_edit_no_update BEFORE UPDATE ON messenger_edits
 BEGIN SELECT RAISE(ABORT,'protected');END;
CREATE TRIGGER messenger_edit_no_delete BEFORE DELETE ON messenger_edits
 BEGIN SELECT RAISE(ABORT,'protected');END;
'''

def run():
    stage='preflight'
    if os.getenv('JW_PG_LAB_V54')!='ONLY_DISPOSABLE_LAB' or os.getenv('JW_ENV','').casefold()=='production':
        print('NOT RUN: V5.4 disposable lab not authorized');return 2
    try:
        stage='disposable-db'
        with tempfile.TemporaryDirectory(prefix='jw-v54-') as folder:
            with sqlite3.connect(Path(folder)/'test.db',isolation_level=None) as source:
                source.execute('PRAGMA foreign_keys=ON')
                source.executescript(SCHEMA)
                install_disposable_outbox(source)
                install_lab_snapshots(source)
                stage='multi-version-source-evidence'
                source.execute("INSERT INTO messenger_connections VALUES('thread','org1','org2')")
                source.execute("INSERT INTO messenger_messages VALUES('m1','org1','actor1','thread','first',1)")
                source.execute("INSERT INTO messenger_edits VALUES('edit1','m1','first','second','actor1','stamp',2)")
                source.execute("UPDATE messenger_messages SET body='second',version=2 WHERE id='m1'")
                source.execute("INSERT INTO messenger_edits VALUES('edit2','m1','second','third','actor1','stamp',3)")
                source.execute("UPDATE messenger_messages SET body='third',version=3 WHERE id='m1'")
                source.execute("INSERT INTO messenger_read_positions VALUES('thread','org2',1)")
                source.execute("UPDATE messenger_read_positions SET last_read_seq=2 WHERE org_id='org2'")
                stage='audit-exact-snapshots'
                check=audit_lab_snapshots(source)
                assert check['snapshot_count']==4 and check['cutover_approved'] is False
                stage='atomic-failure'
                source.execute('BEGIN IMMEDIATE')
                source.execute("INSERT INTO messenger_edits VALUES('edit3','m1','third','fourth','actor1','stamp',4)")
                source.execute("UPDATE messenger_messages SET body='fourth',version=4 WHERE id='m1'")
                source.execute('ROLLBACK')
                assert audit_lab_snapshots(source)==check
                assert source.execute('SELECT body,version FROM messenger_messages WHERE id=?',('m1',)).fetchone()==('third',3)
                stage='tenant-safety'
                source.execute("INSERT INTO messenger_read_positions VALUES('thread','orgX',1)")
                try:
                    audit_lab_snapshots(source)
                except SnapshotRefused: pass
                else: raise AssertionError('Tenant violation accepted')
        print('PASS: V5.4 SQLite mutation-time edit/cursor snapshots, fail-closed tenant audit and rollback')
        print('BLOCKED: read actor identity, live PG payload replication, historical backfill and operational cutover')
        return 0
    except Exception as exc:
        print(f'FAIL: V5.4 stage={stage} type={type(exc).__name__} (sensitive data withheld)')
        return 1

if __name__=='__main__':
    raise SystemExit(run())
