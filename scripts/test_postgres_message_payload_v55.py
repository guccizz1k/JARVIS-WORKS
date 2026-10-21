"""Live disposable PG17 full text payload test (never production)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile

from app.pg_transition_outbox_v51 import install_disposable_outbox
from app.pg_mutation_snapshot_v54 import install_lab_snapshots
from app.pg_message_payload_v55 import Pg17PayloadLabSink, relay_payloads, RelayRefused, STATE

SCHEMA = '''
CREATE TABLE messenger_connections(id TEXT PRIMARY KEY,org_a TEXT,org_b TEXT);
CREATE TABLE messenger_messages(id TEXT PRIMARY KEY,sender_org TEXT,sender_user TEXT,
 connection_id TEXT,kind TEXT,body TEXT,version INTEGER,
 created_at TEXT,edited_at TEXT,order_id TEXT,immutable_order_snapshot TEXT,
 actor_name TEXT);
CREATE TABLE messenger_edits(id TEXT PRIMARY KEY,message_id TEXT,previous_body TEXT,
 new_body TEXT,actor_user TEXT,edited_at TEXT,version INTEGER);
CREATE TABLE messenger_attachments(message_id TEXT PRIMARY KEY,data BLOB);
CREATE TABLE messenger_receipts(message_id TEXT PRIMARY KEY,receiver_org TEXT);
CREATE TABLE messenger_read_positions(connection_id TEXT,org_id TEXT,last_read_seq INTEGER,
 PRIMARY KEY(connection_id,org_id));
CREATE TRIGGER messenger_edit_no_update BEFORE UPDATE ON messenger_edits
 BEGIN SELECT RAISE(ABORT,'protected'); END;
CREATE TRIGGER messenger_edit_no_delete BEFORE DELETE ON messenger_edits
 BEGIN SELECT RAISE(ABORT,'protected'); END;
'''


def run():
    stage='preflight'
    if (os.getenv('JW_ENV','').casefold()=='production'
        or os.getenv('JW_PG_CI_ALLOW')!='ONLY_EPHEMERAL_LOCAL_DATABASE'
        or os.getenv('JW_PG_ALLOW_TEST_WRITES')!='ONLY_EPHEMERAL_DATABASE'
        or os.getenv('JW_PG_LAB_V54')!='ONLY_DISPOSABLE_LAB'
        or os.getenv('JW_PG_LAB_V55')!='ONLY_DISPOSABLE_LAB'):
        print('NOT RUN: V5.5 ephemeral PG17 authorization missing')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from scripts.test_postgres_writer_v40 import _verified_lab_uri
        admin=os.environ['JW_PG_TEST_ADMIN_DSN']
        app=os.environ['JW_PG_TEST_APP_DSN']
        app_uri=_verified_lab_uri(conninfo_to_dict(admin),conninfo_to_dict(app))
        if not app_uri.startswith('postgresql://'):
            raise ValueError('PG app DSN invalid')
    except (ImportError,KeyError,ValueError,RuntimeError):
        print('NOT RUN: V5.5 verified PG17 disposable connection unavailable')
        return 2
    token=secrets.token_urlsafe(48)
    token_b=secrets.token_urlsafe(48)
    try:
        stage='signed-row-level-security-setup'
        with psycopg.connect(admin,connect_timeout=5) as pg:
            with pg.cursor() as cur:
                cur.execute('CREATE SCHEMA jw_payload_v55 AUTHORIZATION postgres')
                cur.execute('''CREATE TABLE jw_payload_v55.messages (
                  stream_id text NOT NULL CHECK(stream_id ~ '^[0-9a-f]{32}$'),
                  source_seq bigint NOT NULL CHECK(source_seq>0),
                  tenant_id text NOT NULL,
                  actor_id text NOT NULL,
                  entity_ref text NOT NULL,
                  connection_id text NOT NULL,
                  body text NOT NULL,
                  created_at text NOT NULL,
                  content_sha256 text NOT NULL CHECK(content_sha256 ~ '^[0-9a-f]{64}$'),
                  recorded_at timestamptz DEFAULT clock_timestamp(),
                  PRIMARY KEY(stream_id,source_seq))''')
                cur.execute('ALTER TABLE jw_payload_v55.messages ENABLE ROW LEVEL SECURITY')
                cur.execute('ALTER TABLE jw_payload_v55.messages FORCE ROW LEVEL SECURITY')
                cur.execute('''CREATE POLICY v55_read ON jw_payload_v55.messages
                  FOR SELECT TO jw_app USING
                  (tenant_id=jw_guard.current_tenant() AND actor_id=jw_guard.current_actor())''')
                cur.execute('''CREATE POLICY v55_insert ON jw_payload_v55.messages
                  FOR INSERT TO jw_app WITH CHECK
                  (tenant_id=jw_guard.current_tenant() AND actor_id=jw_guard.current_actor())''')
                cur.execute('REVOKE ALL ON SCHEMA jw_payload_v55 FROM PUBLIC')
                cur.execute('REVOKE ALL ON jw_payload_v55.messages FROM PUBLIC')
                cur.execute('GRANT USAGE ON SCHEMA jw_payload_v55 TO jw_app')
                cur.execute('GRANT SELECT,INSERT ON jw_payload_v55.messages TO jw_app')
                for tenant,actor,value in [('tenant_a','ua',token),('tenant_b','ub',token_b)]:
                    cur.execute('''INSERT INTO jw_guard.authenticated_sessions
                      (token_digest,org_id,user_id,mfa_verified,expires_at)
                      VALUES (%s,%s,%s,true,%s)''',
                      (sha256(value.encode()).digest(),tenant,actor,
                       datetime.now(timezone.utc)+timedelta(minutes=8)))
        stage='write-time-source-message'
        with tempfile.TemporaryDirectory(prefix='jw-v55-') as td:
            with sqlite3.connect(Path(td)/'s.db',isolation_level=None) as src:
                src.execute('PRAGMA foreign_keys=ON')
                src.executescript(SCHEMA)
                install_disposable_outbox(src)
                install_lab_snapshots(src)
                src.execute("INSERT INTO messenger_connections VALUES ('thread','tenant_a','tenant_b')")
                body='V5.5 isolated PG17 UTF8 본문 🔒'
                created='2026-10-21T13:01:02.123456Z'
                src.execute('''INSERT INTO messenger_messages VALUES
                  ('m1','tenant_a','ua','thread','text',?,1,?,NULL,NULL,NULL,'')''',
                  (body,created))
                sink=Pg17PayloadLabSink(app_uri,token)
                other=Pg17PayloadLabSink(app_uri,token_b)
                stage='signed-cross-tenant-denial'
                try:relay_payloads(src,other)
                except (RelayRefused,psycopg.Error):pass
                else:raise AssertionError('Other company may replicate message')
                assert src.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]==0
                stage='pg-first-commit-crash'
                def crash():raise RuntimeError('synthetic failure between commits')
                try:relay_payloads(src,sink,after_pg_commit=crash)
                except RuntimeError:pass
                else:raise AssertionError('Failure injection was not executed')
                assert src.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]==0
                stage='exact-replay-idempotence'
                assert relay_payloads(src,sink)=={'delivered':1,'ack_seq':1,'cutover_approved':False}
                assert relay_payloads(src,sink)['delivered']==0
                with psycopg.connect(admin,connect_timeout=5) as pg:
                    with pg.cursor() as cur:
                        cur.execute('''SELECT tenant_id,actor_id,connection_id,body,created_at,content_sha256
                          FROM jw_payload_v55.messages''')
                        assert cur.fetchall()==[('tenant_a','ua','thread',body,created,sha256(body.encode()).hexdigest())]
                        cur.execute('''SELECT relrowsecurity,relforcerowsecurity
                          FROM pg_class WHERE oid='jw_payload_v55.messages'::regclass''')
                        assert cur.fetchone()==(True,True)
                        cur.execute("SELECT has_table_privilege('jw_app','jw_payload_v55.messages','UPDATE'),has_table_privilege('jw_app','jw_payload_v55.messages','DELETE')")
                        assert cur.fetchone()==(False,False)
                stage='signed-other-tenant-read-denial'
                with other._delegate._connect() as pg:
                    with pg.cursor() as cur:
                        other._delegate._bind(cur)
                        cur.execute('SELECT count(*) FROM jw_payload_v55.messages')
                        assert cur.fetchone()[0]==0
                stage='order-event-no-ACK-advance'
                src.execute('''INSERT INTO messenger_messages VALUES
                  ('m2','tenant_a','ua','thread','order','invalid order data',1,?,NULL,'o1','{}','Manager')''',(created,))
                try:relay_payloads(src,sink)
                except RelayRefused:pass
                else:raise AssertionError('Order payload was incorrectly accepted')
                assert src.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]==1
                stage='revoked-signed-session-denial'
                with psycopg.connect(admin,connect_timeout=5) as pg:
                    with pg.cursor() as cur:
                        cur.execute('UPDATE jw_guard.authenticated_sessions SET revoked_at=clock_timestamp() WHERE token_digest=%s',
                                    (sha256(token.encode()).digest(),))
                        assert cur.rowcount==1
                try:sink.verified_identity()
                except (RelayRefused,psycopg.Error):pass
                else:raise AssertionError('Revoked PG token accepted')
        print('PASS: V5.5 ephemeral PostgreSQL 17 full text payload equality, idempotent replay, signed RLS, source ACK and cleanup')
        print('BLOCKED: edited/attachment/order payloads, operational identity, live cutover and public deployment')
        return 0
    except Exception as exc:
        print(f'FAIL: V5.5 stage={stage} type={type(exc).__name__} (payload and credentials redacted)',file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(run())
