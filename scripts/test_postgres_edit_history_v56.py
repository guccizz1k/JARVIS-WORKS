"""Isolated PG17 live proof: version-one original and immutable edit events."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
import os
import secrets
import sqlite3
import sys
import tempfile

from app.pg_transition_outbox_v51 import install_disposable_outbox
from app.pg_mutation_snapshot_v54 import install_lab_snapshots
from app.pg_edit_history_v56 import relay_edits, Pg17EditLabSink, STATE, RelayRefused
from scripts.test_postgres_message_payload_v55 import SCHEMA


def run():
    stage='authorization'
    if (os.getenv('JW_ENV','').casefold() == 'production' or
        os.getenv('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE' or
        os.getenv('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE' or
        any(os.getenv(f'JW_PG_LAB_V{v}') != 'ONLY_DISPOSABLE_LAB' for v in (54,55,56))):
        print('NOT RUN: V5.6 PG17 isolated proof not authorized')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from scripts.test_postgres_writer_v40 import _verified_lab_uri
        admin=os.environ['JW_PG_TEST_ADMIN_DSN']
        app=os.environ['JW_PG_TEST_APP_DSN']
        app_uri=_verified_lab_uri(conninfo_to_dict(admin),conninfo_to_dict(app))
        if not app_uri.startswith('postgresql://'):
            raise ValueError('not a supported signed lab URI')
    except (ImportError, KeyError, ValueError, RuntimeError):
        print('NOT RUN: V5.6 verified disposable PG17 credentials unavailable')
        return 2
    token=secrets.token_urlsafe(48)
    other_token=secrets.token_urlsafe(48)
    try:
        stage='RLS-schema'
        with psycopg.connect(admin,connect_timeout=5) as pg:
            with pg.cursor() as cur:
                cur.execute('CREATE SCHEMA jw_edits_v56 AUTHORIZATION postgres')
                cur.execute('''CREATE TABLE jw_edits_v56.events (
                   stream_id text NOT NULL CHECK(stream_id ~ '^[0-9a-f]{32}$'),
                   source_seq bigint NOT NULL CHECK(source_seq>0),
                   tenant_id text NOT NULL, actor_id text NOT NULL,
                   event_type text NOT NULL CHECK(event_type IN
                      ('message.insert','edit.insert','message.body_changed')),
                   entity_ref text NOT NULL, connection_id text NOT NULL,
                   message_id text NOT NULL, message_version integer NOT NULL
                      CHECK(message_version>=1), body text NOT NULL,
                   created_at text NOT NULL,
                   body_sha256 text NOT NULL CHECK(body_sha256 ~ '^[0-9a-f]{64}$'),
                   edit_id text NOT NULL,
                   PRIMARY KEY(stream_id,source_seq))''')
                cur.execute('ALTER TABLE jw_edits_v56.events ENABLE ROW LEVEL SECURITY')
                cur.execute('ALTER TABLE jw_edits_v56.events FORCE ROW LEVEL SECURITY')
                cur.execute('''CREATE POLICY v56_select ON jw_edits_v56.events FOR SELECT
                   TO jw_app USING(tenant_id=jw_guard.current_tenant()
                        AND actor_id=jw_guard.current_actor())''')
                cur.execute('''CREATE POLICY v56_insert ON jw_edits_v56.events FOR INSERT
                   TO jw_app WITH CHECK(tenant_id=jw_guard.current_tenant()
                        AND actor_id=jw_guard.current_actor())''')
                cur.execute('REVOKE ALL ON SCHEMA jw_edits_v56 FROM PUBLIC')
                cur.execute('REVOKE ALL ON jw_edits_v56.events FROM PUBLIC')
                cur.execute('GRANT USAGE ON SCHEMA jw_edits_v56 TO jw_app')
                cur.execute('GRANT SELECT,INSERT ON jw_edits_v56.events TO jw_app')
                for tenant,actor,secret in [('tenant_a','ua',token),('tenant_b','ub',other_token)]:
                    cur.execute('''INSERT INTO jw_guard.authenticated_sessions
                        (token_digest,org_id,user_id,mfa_verified,expires_at)
                        VALUES(%s,%s,%s,true,%s)''',
                        (sha256(secret.encode()).digest(),tenant,actor,
                         datetime.now(timezone.utc)+timedelta(minutes=8)))
        stage='disposable-SQLite-edit-evidence'
        with tempfile.TemporaryDirectory(prefix='jw-v56-') as temp:
            with sqlite3.connect(Path(temp)/'source.db',isolation_level=None) as source:
                source.execute('PRAGMA foreign_keys=ON')
                source.executescript(SCHEMA)
                install_disposable_outbox(source)
                install_lab_snapshots(source)
                source.execute("INSERT INTO messenger_connections VALUES('thread','tenant_a','tenant_b')")
                original='원본 그대로 📝'
                edits=['수정본 2 📌','수정본 3 🧾']
                created='2026-10-21T13:01:02.123456Z'
                source.execute('''INSERT INTO messenger_messages VALUES
                    ('m1','tenant_a','ua','thread','text',?,1,?,NULL,NULL,NULL,'')''',
                    (original,created))
                prev=original
                for version,body in enumerate(edits,2):
                    date=f'2026-10-21T13:01:0{version}.123456Z'
                    source.execute('INSERT INTO messenger_edits VALUES(?,?,?,?,?,?,?)',
                                   (f'e{version}','m1',prev,body,'ua',date,version))
                    source.execute('UPDATE messenger_messages SET body=?,version=?,edited_at=? WHERE id=?',
                                   (body,version,date,'m1'))
                    prev=body
                sink=Pg17EditLabSink(app_uri,token)
                wrong=Pg17EditLabSink(app_uri,other_token)
                stage='cross-tenant-signed-denial'
                try: relay_edits(source,wrong)
                except (RelayRefused,psycopg.Error): pass
                else: raise AssertionError('Other tenant may replicate sender data')
                assert source.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]==0
                stage='PG-commit-before-SQLite-checkpoint-crash'
                def injected_crash(): raise RuntimeError('postcommit crash')
                try: relay_edits(source,sink,after_pg_commit=injected_crash)
                except RuntimeError: pass
                else: raise AssertionError('Postcommit crash hook did not execute')
                assert source.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]==0
                stage='durable-PG-replay-originals-and-edits'
                result=relay_edits(source,sink)
                assert result=={'delivered':5,'ack_seq':5,'cutover_approved':False}
                assert relay_edits(source,sink)['delivered']==0
                with psycopg.connect(admin,connect_timeout=5) as pg:
                    with pg.cursor() as cur:
                        cur.execute('''SELECT source_seq,event_type,message_version,body,
                          body_sha256,edit_id FROM jw_edits_v56.events ORDER BY source_seq''')
                        rows=cur.fetchall()
                        assert [(r[0],r[1],r[2],r[3],r[5]) for r in rows]==[
                            (1,'message.insert',1,original,''),
                            (2,'edit.insert',2,edits[0],'e2'),
                            (3,'message.body_changed',2,edits[0],'e2'),
                            (4,'edit.insert',3,edits[1],'e3'),
                            (5,'message.body_changed',3,edits[1],'e3'),
                        ]
                        assert all(r[4]==sha256(r[3].encode('utf-8')).hexdigest() for r in rows)
                        cur.execute('''SELECT relrowsecurity,relforcerowsecurity
                            FROM pg_class WHERE oid='jw_edits_v56.events'::regclass''')
                        assert cur.fetchone()==(True,True)
                        cur.execute("SELECT has_table_privilege('jw_app','jw_edits_v56.events','UPDATE'),has_table_privilege('jw_app','jw_edits_v56.events','DELETE')")
                        assert cur.fetchone()==(False,False)
                stage='forbidden-other-tenant-select'
                with wrong._delegate._connect() as pg:
                    with pg.cursor() as cur:
                        wrong._delegate._bind(cur)
                        cur.execute('SELECT COUNT(*) FROM jw_edits_v56.events')
                        assert cur.fetchone()[0]==0
                stage='unverified-read-event-denial'
                source.execute("INSERT INTO messenger_read_positions VALUES('thread','tenant_a',4)")
                try: relay_edits(source,sink)
                except RelayRefused: pass
                else: raise AssertionError('Read cursor without actor accepted')
                assert source.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]==5
                stage='signed-revocation-denial'
                with psycopg.connect(admin,connect_timeout=5) as pg:
                    with pg.cursor() as cur:
                        cur.execute('UPDATE jw_guard.authenticated_sessions SET revoked_at=clock_timestamp() WHERE token_digest=%s',
                                    (sha256(token.encode()).digest(),))
                        assert cur.rowcount==1
                try: sink.verified_identity()
                except (RelayRefused,psycopg.Error): pass
                else: raise AssertionError('Revoked token accepted')
        print('PASS: V5.6 live PG17 immutable initial body + edit history, replay, RLS, ACK and disposal')
        print('BLOCKED: attachment/receipt/read actor, orders, production identity and cutover')
        return 0
    except Exception as error:
        print(f'FAIL: V5.6 stage={stage} type={type(error).__name__} (secrets and payload withheld)',file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(run())
