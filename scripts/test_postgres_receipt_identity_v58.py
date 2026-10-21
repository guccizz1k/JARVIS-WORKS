"""V5.8 signed recipient PG17 live test using isolated ephemeral roles only."""
from __future__ import annotations
from datetime import datetime,timedelta,timezone
from hashlib import sha256
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile

from app.pg_transition_outbox_v51 import install_disposable_outbox
from app.pg_mutation_snapshot_v54 import install_lab_snapshots
from app.pg_receipt_identity_v58 import Pg17ReceiptLabSink,relay_receipts,STATE,RelayRefused
from tests.test_pg_receipt_identity_v58 import SCHEMA


def run():
    stage='authorization'
    if (os.getenv('JW_ENV','').casefold()=='production'
        or os.getenv('JW_PG_CI_ALLOW')!='ONLY_EPHEMERAL_LOCAL_DATABASE'
        or os.getenv('JW_PG_ALLOW_TEST_WRITES')!='ONLY_EPHEMERAL_DATABASE'
        or any(os.getenv(f'JW_PG_LAB_V{v}')!='ONLY_DISPOSABLE_LAB' for v in (54,55,57,58))):
        print('NOT RUN: V5.8 disposable PG17 receipt proof unauthorized')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from scripts.test_postgres_writer_v40 import _verified_lab_uri
        admin=os.environ['JW_PG_TEST_ADMIN_DSN'];app=os.environ['JW_PG_TEST_APP_DSN']
        app_uri=_verified_lab_uri(conninfo_to_dict(admin),conninfo_to_dict(app))
        if not app_uri.startswith('postgresql://'):raise ValueError('Invalid app lab DSN')
    except (ImportError,KeyError,ValueError,RuntimeError):
        print('NOT RUN: V5.8 disposable PG17 credentials unavailable')
        return 2
    sender_token=secrets.token_urlsafe(48);receiver_token=secrets.token_urlsafe(48)
    try:
        stage='PG17 signed receiving actor row-level security'
        with psycopg.connect(admin,connect_timeout=5) as pg:
            with pg.cursor() as cur:
                cur.execute('CREATE SCHEMA jw_receipt_v58 AUTHORIZATION postgres')
                cur.execute('''CREATE TABLE jw_receipt_v58.receipts (
                   stream_id text NOT NULL CHECK(stream_id ~ '^[0-9a-f]{32}$'),
                   source_seq bigint NOT NULL CHECK(source_seq>0),
                   tenant_id text NOT NULL,actor_id text NOT NULL,
                   message_id text NOT NULL,sender_org text NOT NULL,sender_user text NOT NULL,
                   connection_id text NOT NULL,actor_name text NOT NULL,received_at text NOT NULL,
                   order_snapshot_sha256 text NOT NULL CHECK(order_snapshot_sha256 ~ '^[0-9a-f]{64}$'),
                   order_seq bigint NOT NULL CHECK(order_seq>0),
                   PRIMARY KEY(stream_id,source_seq))''')
                cur.execute('ALTER TABLE jw_receipt_v58.receipts ENABLE ROW LEVEL SECURITY')
                cur.execute('ALTER TABLE jw_receipt_v58.receipts FORCE ROW LEVEL SECURITY')
                cur.execute('''CREATE POLICY receipt_read ON jw_receipt_v58.receipts FOR SELECT TO jw_app
                   USING(tenant_id=jw_guard.current_tenant() AND actor_id=jw_guard.current_actor())''')
                cur.execute('''CREATE POLICY receipt_write ON jw_receipt_v58.receipts FOR INSERT TO jw_app
                   WITH CHECK(tenant_id=jw_guard.current_tenant() AND actor_id=jw_guard.current_actor())''')
                cur.execute('REVOKE ALL ON SCHEMA jw_receipt_v58 FROM PUBLIC')
                cur.execute('REVOKE ALL ON jw_receipt_v58.receipts FROM PUBLIC')
                cur.execute('GRANT USAGE ON SCHEMA jw_receipt_v58 TO jw_app')
                cur.execute('GRANT SELECT,INSERT ON jw_receipt_v58.receipts TO jw_app')
                for tenant,actor,token in [('tenant_a','ua',sender_token),('tenant_b','ub',receiver_token)]:
                    cur.execute('''INSERT INTO jw_guard.authenticated_sessions
                        (token_digest,org_id,user_id,mfa_verified,expires_at)
                        VALUES(%s,%s,%s,true,%s)''',
                        (sha256(token.encode()).digest(),tenant,actor,datetime.now(timezone.utc)+timedelta(minutes=8)))
        stage='SQLite signed recipient snapshot fixture'
        with tempfile.TemporaryDirectory(prefix='jw-v58-') as td:
            with sqlite3.connect(Path(td)/'source.db',isolation_level=None) as source:
                source.execute('PRAGMA foreign_keys=ON');source.executescript(SCHEMA)
                install_disposable_outbox(source);install_lab_snapshots(source)
                source.execute("INSERT INTO messenger_connections VALUES('thread','tenant_a','tenant_b')")
                source.execute("INSERT INTO users VALUES('ua','tenant_a'),('ub','tenant_b')")
                snapshot='{"order":"A-001","total":30000}'
                source.execute('''INSERT INTO messenger_messages VALUES
                    ('m1','tenant_a','ua','thread','order','발주서 A-001',1,'2026-10-21T14:01:00Z',NULL,'ord1',?,'발신담당')''',(snapshot,))
                source.execute("INSERT INTO messenger_receipts VALUES('m1','tenant_b','ub','수신담당','2026-10-21T14:01:01Z')")
                authorized=Pg17ReceiptLabSink(app_uri,receiver_token)
                wrong=Pg17ReceiptLabSink(app_uri,sender_token)
                stage='sender-actor-cannot-sign-receipt'
                try:relay_receipts(source,wrong)
                except (RelayRefused,psycopg.Error):pass
                else:raise AssertionError('Sender signed recipient receipt')
                assert source.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]==0
                stage='postcommit-crash-before-SQLite-ACK'
                try:relay_receipts(source,authorized,after_pg_commit=lambda:(_ for _ in ()).throw(RuntimeError('injected')))
                except RuntimeError:pass
                else:raise AssertionError('Crash injection not reached')
                assert source.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]==0
                stage='signed-receipt-replay-byte-parity'
                assert relay_receipts(source,authorized)=={'delivered':1,'ack_seq':2,'cutover_approved':False}
                assert relay_receipts(source,authorized)['delivered']==0
                with psycopg.connect(admin,connect_timeout=5) as pg:
                    with pg.cursor() as cur:
                        cur.execute('''SELECT source_seq,tenant_id,actor_id,message_id,sender_org,
                        actor_name,received_at,order_snapshot_sha256,order_seq FROM jw_receipt_v58.receipts''')
                        assert cur.fetchall()==[(2,'tenant_b','ub','m1','tenant_a','수신담당',
                          '2026-10-21T14:01:01Z',sha256(snapshot.encode()).hexdigest(),1)]
                        cur.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='jw_receipt_v58.receipts'::regclass")
                        assert cur.fetchone()==(True,True)
                        cur.execute("SELECT has_table_privilege('jw_app','jw_receipt_v58.receipts','UPDATE'),has_table_privilege('jw_app','jw_receipt_v58.receipts','DELETE')")
                        assert cur.fetchone()==(False,False)
                stage='sender-read-denial'
                with wrong._delegate._connect() as pg:
                    with pg.cursor() as cur:
                        wrong._delegate._bind(cur)
                        cur.execute('SELECT COUNT(*) FROM jw_receipt_v58.receipts')
                        assert cur.fetchone()[0]==0
                stage='refuse-delayed-receipt-unverified-sequence'
                source.execute("INSERT INTO messenger_messages VALUES('m2','tenant_a','ua','thread','order','p',1,'now',NULL,'ord2','{}','발신')")
                source.execute("INSERT INTO messenger_messages VALUES('m3','tenant_a','ua','thread','text','plain',1,'now',NULL,NULL,NULL,'')")
                source.execute("INSERT INTO messenger_receipts VALUES('m2','tenant_b','ub','수신','now')")
                try:relay_receipts(source,authorized)
                except RelayRefused:pass
                else:raise AssertionError('Delayed unverified receipt was accepted')
                assert source.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]==2
                stage='signed-user-revocation'
                with psycopg.connect(admin,connect_timeout=5) as pg:
                    with pg.cursor() as cur:
                        cur.execute('UPDATE jw_guard.authenticated_sessions SET revoked_at=clock_timestamp() WHERE token_digest=%s',
                                    (sha256(receiver_token.encode()).digest(),))
                        assert cur.rowcount==1
                try:authorized.verified_identity()
                except (RelayRefused,psycopg.Error):pass
                else:raise AssertionError('Revoked recipient signed PG evidence')
        print('PASS: V5.8 PG17 signed receiving employee, receipt digest, exact replay, RLS and cleanup')
        print('BLOCKED: delayed/nonadjacent receipts, read cursor actor, live business cutover')
        return 0
    except Exception as exc:
        print(f'FAIL: V5.8 stage={stage} type={type(exc).__name__} (identity and content redacted)',file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(run())
