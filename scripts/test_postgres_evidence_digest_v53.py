"""Actual ephemeral PG17 gate; invoked ONLY after V5.2 integration passes."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from hashlib import sha256
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile

from app.pg_evidence_digest_v53 import Pg17EvidenceLabSink, relay_evidence, STATE
from app.pg_outbox_relay_v52 import RelayRefused
from app.pg_transition_outbox_v51 import install_disposable_outbox


CREATE_SOURCE = '''
CREATE TABLE messenger_messages(id TEXT PRIMARY KEY, sender_org TEXT, sender_user TEXT,
 connection_id TEXT, body TEXT);
CREATE TABLE messenger_connections(id TEXT PRIMARY KEY,org_a TEXT,org_b TEXT);
CREATE TABLE messenger_edits(id TEXT PRIMARY KEY,message_id TEXT,previous_body TEXT,new_body TEXT,
 actor_user TEXT,edited_at TEXT,version INTEGER);
CREATE TABLE messenger_attachments(message_id TEXT PRIMARY KEY,filename TEXT,mime TEXT,
 data BLOB,size_bytes INTEGER,content_hash TEXT);
CREATE TABLE messenger_receipts(message_id TEXT PRIMARY KEY,receiver_org TEXT,receiver_user TEXT,received_at TEXT);
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
'''


def run() -> int:
    stage='env-preflight'
    if (os.getenv('JW_ENV','').casefold()=='production'
            or os.getenv('JW_PG_CI_ALLOW')!='ONLY_EPHEMERAL_LOCAL_DATABASE'
            or os.getenv('JW_PG_ALLOW_TEST_WRITES')!='ONLY_EPHEMERAL_DATABASE'
            or os.getenv('JW_PG_LAB_V53')!='ONLY_DISPOSABLE_LAB'):
        print('NOT RUN: V5.3 disposable PG17 lab only')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from scripts.test_postgres_writer_v40 import _verified_lab_uri
        admin=os.environ['JW_PG_TEST_ADMIN_DSN']
        app=os.environ['JW_PG_TEST_APP_DSN']
        app_uri=_verified_lab_uri(conninfo_to_dict(admin),conninfo_to_dict(app))
        if not app_uri.startswith('postgresql://'):
            raise ValueError('Incorrect PG connection URI')
    except (KeyError,ImportError,ValueError,RuntimeError):
        print('NOT RUN: V5.3 verified PG17 lab credentials unavailable')
        return 2
    try:
        stage='create-forced-rls-ledger'
        token=secrets.token_urlsafe(48)
        with psycopg.connect(admin,connect_timeout=5) as pg:
            with pg.cursor() as cur:
                cur.execute('CREATE SCHEMA jw_relay_v53 AUTHORIZATION postgres')
                cur.execute('''CREATE TABLE jw_relay_v53.inbox (
                   stream_id text NOT NULL CHECK(stream_id ~ '^[0-9a-f]{32}$'),
                   source_seq bigint NOT NULL CHECK(source_seq>0),
                   tenant_id text NOT NULL,actor_id text NOT NULL,
                   event_type text NOT NULL CHECK(event_type IN
                     ('message.insert','attachment.insert','edit.insert','receipt.insert')),
                   entity_ref text NOT NULL,
                   source_digest text NOT NULL CHECK(source_digest ~ '^[0-9a-f]{64}$'),
                   evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[0-9a-f]{64}$'),
                   inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                   PRIMARY KEY(stream_id,source_seq))''')
                cur.execute('ALTER TABLE jw_relay_v53.inbox ENABLE ROW LEVEL SECURITY')
                cur.execute('ALTER TABLE jw_relay_v53.inbox FORCE ROW LEVEL SECURITY')
                cur.execute('''CREATE POLICY v53_select ON jw_relay_v53.inbox FOR SELECT
                   TO jw_app USING (tenant_id=jw_guard.current_tenant()
                       AND actor_id=jw_guard.current_actor())''')
                cur.execute('''CREATE POLICY v53_insert ON jw_relay_v53.inbox FOR INSERT
                   TO jw_app WITH CHECK (tenant_id=jw_guard.current_tenant()
                       AND actor_id=jw_guard.current_actor())''')
                cur.execute('REVOKE ALL ON SCHEMA jw_relay_v53 FROM PUBLIC')
                cur.execute('REVOKE ALL ON jw_relay_v53.inbox FROM PUBLIC')
                cur.execute('GRANT USAGE ON SCHEMA jw_relay_v53 TO jw_app')
                cur.execute('GRANT SELECT,INSERT ON jw_relay_v53.inbox TO jw_app')
                cur.execute('''INSERT INTO jw_guard.authenticated_sessions
                   (token_digest,org_id,user_id,mfa_verified,expires_at)
                   VALUES (%s,%s,%s,true,%s)''',
                   (sha256(token.encode()).digest(),'tenant_a','ua',
                    datetime.now(timezone.utc)+timedelta(minutes=8)))
        stage='source-evidence-and-durable-commit'
        with tempfile.TemporaryDirectory(prefix='jw-v53-') as tmp:
            with sqlite3.connect(Path(tmp)/'source.db',isolation_level=None) as source:
                source.execute('PRAGMA foreign_keys=ON')
                source.executescript(CREATE_SOURCE)
                install_disposable_outbox(source)
                source.execute("INSERT INTO messenger_connections VALUES('chat_ab','tenant_a','tenant_b')")
                source.execute("INSERT INTO messenger_messages VALUES('m1','tenant_a','ua','chat_ab','PRIVATE_SECRET')")
                data=b'LAB-only PDF bytes'
                source.execute('''INSERT INTO messenger_attachments VALUES (?,?,?,?,?,?)''',
                    ('m1','file.pdf','application/pdf',data,len(data),sha256(data).hexdigest()))
                source.execute('''INSERT INTO messenger_edits VALUES (?,?,?,?,?,?,?)''',
                    ('e1','m1','SECRET_BEFORE','SECRET_AFTER','ua','2026-10-21T00:00:00Z',2))
                sink=Pg17EvidenceLabSink(app_uri,token)
                def crash():raise RuntimeError('synthetic crash after PostgreSQL commit')
                stage='PG-commit-then-checkpoint-crash'
                try:relay_evidence(source,sink,after_pg_commit=crash)
                except RuntimeError:pass
                else:raise AssertionError('Required crash injection was skipped')
                assert source.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]==0
                stage='exact-replay-and-no-secret-leak'
                r=relay_evidence(source,sink)
                assert r['ack_seq']==3 and r['delivered']==3 and r['cutover_approved'] is False
                with psycopg.connect(admin,connect_timeout=5) as pg:
                    with pg.cursor() as cur:
                        cur.execute('''SELECT COUNT(*),COUNT(DISTINCT source_seq),
                         MIN(tenant_id),MAX(actor_id),bool_and(event_type IN
                         ('message.insert','attachment.insert','edit.insert'))
                         FROM jw_relay_v53.inbox''')
                        assert cur.fetchone()==(3,3,'tenant_a','ua',True)
                        cur.execute('''SELECT bool_and(entity_ref NOT LIKE '%SECRET%')
                           FROM jw_relay_v53.inbox''')
                        assert cur.fetchone()==(True,)
                        cur.execute('''SELECT relrowsecurity,relforcerowsecurity
                           FROM pg_class WHERE oid='jw_relay_v53.inbox'::regclass''')
                        assert cur.fetchone()==(True,True)
                stage='unsupported-mutable-read-cursor-fails-closed'
                source.execute("INSERT INTO messenger_read_positions VALUES ('chat_ab','tenant_a',7)")
                try:relay_evidence(source,sink)
                except RelayRefused:pass
                else:raise AssertionError('Mutable read event accepted')
                assert source.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]==3
                stage='revoke-and-refuse'
                with psycopg.connect(admin,connect_timeout=5) as pg:
                    with pg.cursor() as cur:
                        cur.execute('''UPDATE jw_guard.authenticated_sessions
                         SET revoked_at=clock_timestamp() WHERE token_digest=%s''',
                         (sha256(token.encode()).digest(),))
                        assert cur.rowcount==1
                # verify identity must reject revoked session even for empty batch
                try:sink.verified_identity()
                except (RelayRefused,psycopg.Error):pass
                else:raise AssertionError('Revoked PG session accepted')
        print('PASS: V5.3 PG17 synthetic digest relay, forced RLS, crash replay, ACK and cleanup')
        print('BLOCKED: actual contents, mutable cursor history, operational identity and production deployment')
        return 0
    except Exception as exc:
        print(f'FAIL: V5.3 stage={stage} type={type(exc).__name__} (sensitive data withheld)',file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(run())
