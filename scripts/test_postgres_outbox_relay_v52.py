"""V5.2 PG17 integration: signed synthetic actor and commit-before-ACK replay.

Called INSIDE the existing V2.8 disposable PG supervisor after V5.0 gates.
The actual B2B application and production PostgreSQL never use this runner.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import os
import secrets
import sqlite3
import sys
import tempfile
from pathlib import Path


def run() -> int:
    if (os.getenv('JW_ENV','').casefold()=='production'
            or os.getenv('JW_PG_CI_ALLOW')!='ONLY_EPHEMERAL_LOCAL_DATABASE'
            or os.getenv('JW_PG_ALLOW_TEST_WRITES')!='ONLY_EPHEMERAL_DATABASE'
            or os.getenv('JW_PG_OUTBOX_V51')!='ONLY_DISPOSABLE_LAB'
            or os.getenv('JW_PG_RELAY_V52')!='ONLY_DISPOSABLE_LAB'
            or os.getenv('JW_PG_LAB_V52')!='ONLY_DISPOSABLE_LAB'
            or os.getenv('JW_PG_LAB_V50')!='ONLY_DISPOSABLE_LAB'):
        print('NOT RUN: V5.2 ephemeral PG/SQLite relay flags unavailable')
        return 2
    stage='dsn-preflight'
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from scripts.test_postgres_writer_v40 import _verified_lab_uri
        from app.pg_outbox_relay_v52 import Pg17LabSink, RelayRefused, relay_batch, STATE
        from app.pg_transition_outbox_v51 import install_disposable_outbox
        admin = os.environ['JW_PG_TEST_ADMIN_DSN']
        app = os.environ['JW_PG_TEST_APP_DSN']
        app_uri = _verified_lab_uri(conninfo_to_dict(admin),conninfo_to_dict(app))
        if not app_uri.startswith('postgresql://'):
            raise ValueError('Invalid ephemeral PG17 application URI')
    except (ImportError,KeyError,ValueError,RuntimeError):
        print('NOT RUN: V5.2 disposable driver or credentials unavailable')
        return 2
    token = secrets.token_urlsafe(48)
    token_b = secrets.token_urlsafe(48)
    try:
        stage='prepare-restricted-disposable-ledger'
        with psycopg.connect(admin, connect_timeout=5) as pg:
            with pg.cursor() as cur:
                cur.execute('''CREATE SCHEMA jw_relay_v52 AUTHORIZATION postgres''')
                cur.execute('''CREATE TABLE jw_relay_v52.inbox (
                   stream_id text NOT NULL CHECK(stream_id ~ '^[0-9a-f]{32}$'),
                   source_seq bigint NOT NULL CHECK(source_seq>0),
                   tenant_id text NOT NULL,
                   actor_id text NOT NULL,
                   event_type text NOT NULL CHECK(event_type='message.insert'),
                   entity_ref text NOT NULL,
                   source_digest text NOT NULL CHECK(source_digest ~ '^[0-9a-f]{64}$'),
                   inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                   PRIMARY KEY(stream_id,source_seq))''')
                cur.execute('ALTER TABLE jw_relay_v52.inbox ENABLE ROW LEVEL SECURITY')
                cur.execute('ALTER TABLE jw_relay_v52.inbox FORCE ROW LEVEL SECURITY')
                cur.execute('''CREATE POLICY jw_v52_rls_read ON jw_relay_v52.inbox
                   FOR SELECT TO jw_app USING
                   (tenant_id=jw_guard.current_tenant()
                       AND actor_id=jw_guard.current_actor())''')
                cur.execute('''CREATE POLICY jw_v52_rls_insert ON jw_relay_v52.inbox
                   FOR INSERT TO jw_app WITH CHECK
                   (tenant_id=jw_guard.current_tenant()
                       AND actor_id=jw_guard.current_actor())''')
                cur.execute('REVOKE ALL ON SCHEMA jw_relay_v52 FROM PUBLIC')
                cur.execute('REVOKE ALL ON jw_relay_v52.inbox FROM PUBLIC')
                cur.execute('GRANT USAGE ON SCHEMA jw_relay_v52 TO jw_app')
                cur.execute('GRANT SELECT,INSERT ON jw_relay_v52.inbox TO jw_app')
                for name, actor, value in [('tenant_a','ua',token),('tenant_b','ub',token_b)]:
                    cur.execute('''INSERT INTO jw_guard.authenticated_sessions
                       (token_digest,org_id,user_id,mfa_verified,expires_at)
                       VALUES (%s,%s,%s,true,%s)''',
                       (sha256(value.encode()).digest(), name, actor,
                        datetime.now(timezone.utc)+timedelta(minutes=8)))
        stage='source-fixture-and-first-relay'
        with tempfile.TemporaryDirectory(prefix='jw-v52-') as work:
            path = Path(work)/'disposable-sqlite.db'
            with sqlite3.connect(path, isolation_level=None) as src:
                src.execute('PRAGMA foreign_keys=ON')
                src.executescript('''
                 CREATE TABLE messenger_messages (id text PRIMARY KEY,
                   sender_org text NOT NULL, sender_user text NOT NULL,
                   connection_id text NOT NULL,body text NOT NULL);
                 CREATE TABLE messenger_edits(id text PRIMARY KEY,message_id text);
                 CREATE TABLE messenger_attachments(message_id text PRIMARY KEY,data BLOB);
                 CREATE TABLE messenger_receipts(message_id text PRIMARY KEY,receiver_org text);
                 CREATE TABLE messenger_read_positions(connection_id text,org_id text,
                      last_read_seq integer,PRIMARY KEY(connection_id,org_id));''')
                install_disposable_outbox(src)
                a = Pg17LabSink(app_uri,token)
                b = Pg17LabSink(app_uri,token_b)
                src.execute('''INSERT INTO messenger_messages VALUES
                     ('v52_id1','tenant_a','ua','chat_ab','PRIVATE_SYNTHETIC_BODY')''')
                first = relay_batch(src,a)
                assert first['delivered']==1 and first['ack_seq']==1
                assert first['cutover_approved'] is False
                stage='cross-tenant-and-signed-actor-check'
                src.execute('''INSERT INTO messenger_messages VALUES
                     ('v52_id2','tenant_a','ua','chat_ab','SECOND_PRIVATE_BODY')''')
                try:
                    relay_batch(src,b)
                except RelayRefused:
                    pass
                else:raise AssertionError('Cross-tenant source relay not refused')
                assert src.execute('SELECT ack_seq FROM '+STATE).fetchone()[0]==1
                stage='crash-between-pg-commit-and-sqlite-ack'
                def crash(): raise RuntimeError('Synthetic crash AFTER durable PG commit')
                try:
                    relay_batch(src,a,after_pg_commit=crash)
                except RuntimeError:
                    pass
                else:raise AssertionError('Crash injection did not interrupt ACK')
                assert src.execute('SELECT ack_seq FROM '+STATE).fetchone()[0]==1
                with psycopg.connect(admin,connect_timeout=5) as pg:
                    with pg.cursor() as cur:
                        cur.execute('SELECT COUNT(*) FROM jw_relay_v52.inbox')
                        assert cur.fetchone()[0]==2
                stage='idempotent-replay-and-checkpoint'
                assert relay_batch(src,a)['ack_seq']==2
                assert relay_batch(src,a)['delivered']==0
                with psycopg.connect(admin,connect_timeout=5) as pg:
                    with pg.cursor() as cur:
                        cur.execute('''SELECT COUNT(*),COUNT(DISTINCT source_seq),
                                       MIN(tenant_id),MIN(actor_id)
                                       FROM jw_relay_v52.inbox''')
                        assert cur.fetchone()==(2,2,'tenant_a','ua')
                        cur.execute("SELECT bool_and(entity_ref <> 'PRIVATE_SYNTHETIC_BODY') FROM jw_relay_v52.inbox")
                        assert cur.fetchone()==(True,)
                stage='revoke-and-new-event-denial'
                with psycopg.connect(admin,connect_timeout=5) as pg:
                    with pg.cursor() as cur:
                        cur.execute('''UPDATE jw_guard.authenticated_sessions
                            SET revoked_at=clock_timestamp() WHERE token_digest=%s''',
                            (sha256(token.encode()).digest(),))
                        assert cur.rowcount==1
                src.execute('''INSERT INTO messenger_messages VALUES
                     ('v52_id3','tenant_a','ua','chat_ab','THIRD_PRIVATE_BODY')''')
                try:
                    relay_batch(src,a)
                except (RelayRefused,psycopg.Error):
                    pass
                else:raise AssertionError('Revoked PG actor accepted')
                assert src.execute('SELECT ack_seq FROM '+STATE).fetchone()[0]==2
                stage='revoke-postgres-insert-role-security'
                with psycopg.connect(admin,connect_timeout=5) as pg:
                    with pg.cursor() as cur:
                        cur.execute('''SELECT relrowsecurity,relforcerowsecurity
                            FROM pg_class WHERE oid='jw_relay_v52.inbox'::regclass''')
                        assert cur.fetchone()==(True,True)
        print('PASS: V5.2 real ephemeral PG17 message-reference relay, signed RLS, '
              'crash replay dedup, revoke denial, post-commit SQLite checkpoint and cleanup')
        print('BLOCKED: no business message payload replication, attachment/receipt event relay or production cutover')
        return 0
    except Exception as exc:
        print('FAIL: V5.2 stage='+stage+' type='+type(exc).__name__+
              ' (credentials and message references redacted)',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(run())
