"""Isolated PostgreSQL 17 live attachment-byte parity / replay proof."""
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
from app.pg_attachment_payload_v57 import Pg17AttachmentLabSink,relay_attachments,RelayRefused,STATE
from scripts.test_postgres_message_payload_v55 import SCHEMA as SIMPLE

SCHEMA=SIMPLE.replace('messenger_attachments(message_id TEXT PRIMARY KEY,data BLOB)',
    'messenger_attachments(message_id TEXT PRIMARY KEY,filename TEXT,mime TEXT,data BLOB,size_bytes INTEGER,content_hash TEXT)')+'''
CREATE TRIGGER messenger_attachment_no_update BEFORE UPDATE ON messenger_attachments
 BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER messenger_attachment_no_delete BEFORE DELETE ON messenger_attachments
 BEGIN SELECT RAISE(ABORT,'immutable'); END;
'''

def run():
    stage='permission'
    if (os.getenv('JW_ENV','').casefold()=='production'
        or os.getenv('JW_PG_CI_ALLOW')!='ONLY_EPHEMERAL_LOCAL_DATABASE'
        or os.getenv('JW_PG_ALLOW_TEST_WRITES')!='ONLY_EPHEMERAL_DATABASE'
        or any(os.getenv(f'JW_PG_LAB_V{x}')!='ONLY_DISPOSABLE_LAB' for x in (54,55,56,57))):
        print('NOT RUN: V5.7 disposable PG17 authorization not satisfied')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from scripts.test_postgres_writer_v40 import _verified_lab_uri
        admin=os.environ['JW_PG_TEST_ADMIN_DSN'];app=os.environ['JW_PG_TEST_APP_DSN']
        app_uri=_verified_lab_uri(conninfo_to_dict(admin),conninfo_to_dict(app))
        if not app_uri.startswith('postgresql://'):raise ValueError('Invalid PG lab DSN')
    except (ImportError,KeyError,ValueError,RuntimeError):
        print('NOT RUN: Verified disposable PG17 credentials unavailable')
        return 2
    a_token=secrets.token_urlsafe(48); b_token=secrets.token_urlsafe(48)
    try:
        stage='PG17 restricted append-only schema'
        with psycopg.connect(admin,connect_timeout=5) as pg:
            with pg.cursor() as cur:
                cur.execute('CREATE SCHEMA jw_attach_v57 AUTHORIZATION postgres')
                cur.execute('''CREATE TABLE jw_attach_v57.blobs (
                    stream_id text NOT NULL CHECK(stream_id ~ '^[0-9a-f]{32}$'),
                    source_seq bigint NOT NULL CHECK(source_seq>0),
                    tenant_id text NOT NULL, actor_id text NOT NULL,
                    message_id text NOT NULL, connection_id text NOT NULL,
                    filename text NOT NULL, mime text NOT NULL,
                    data bytea NOT NULL,
                    size_bytes integer NOT NULL CHECK(size_bytes>0 AND size_bytes<=5242880),
                    created_at text NOT NULL,
                    content_sha256 text NOT NULL CHECK(content_sha256 ~ '^[0-9a-f]{64}$'),
                    create_seq bigint NOT NULL CHECK(create_seq>0),
                    PRIMARY KEY(stream_id,source_seq))''')
                cur.execute('ALTER TABLE jw_attach_v57.blobs ENABLE ROW LEVEL SECURITY')
                cur.execute('ALTER TABLE jw_attach_v57.blobs FORCE ROW LEVEL SECURITY')
                cur.execute('''CREATE POLICY v57_read ON jw_attach_v57.blobs FOR SELECT
                    TO jw_app USING(tenant_id=jw_guard.current_tenant()
                    AND actor_id=jw_guard.current_actor())''')
                cur.execute('''CREATE POLICY v57_insert ON jw_attach_v57.blobs FOR INSERT
                    TO jw_app WITH CHECK(tenant_id=jw_guard.current_tenant()
                    AND actor_id=jw_guard.current_actor())''')
                cur.execute('REVOKE ALL ON SCHEMA jw_attach_v57 FROM PUBLIC')
                cur.execute('REVOKE ALL ON jw_attach_v57.blobs FROM PUBLIC')
                cur.execute('GRANT USAGE ON SCHEMA jw_attach_v57 TO jw_app')
                cur.execute('GRANT SELECT,INSERT ON jw_attach_v57.blobs TO jw_app')
                for tenant,actor,secret in [('tenant_a','ua',a_token),('tenant_b','ub',b_token)]:
                    cur.execute('''INSERT INTO jw_guard.authenticated_sessions
                       (token_digest,org_id,user_id,mfa_verified,expires_at)
                       VALUES (%s,%s,%s,true,%s)''',
                       (sha256(secret.encode()).digest(),tenant,actor,
                        datetime.now(timezone.utc)+timedelta(minutes=8)))
        stage='atomic SQLite attachment source'
        with tempfile.TemporaryDirectory(prefix='jw-v57-') as td:
            with sqlite3.connect(Path(td)/'source.db',isolation_level=None) as source:
                source.execute('PRAGMA foreign_keys=ON');source.executescript(SCHEMA)
                install_disposable_outbox(source);install_lab_snapshots(source)
                source.execute("INSERT INTO messenger_connections VALUES('thread','tenant_a','tenant_b')")
                contents=b'%PDF-1.7\n'+bytes(range(256))*12+b'%%EOF'
                name='사업자등록증.pdf';created='2026-10-21T18:50:00.123456Z'
                source.execute('''INSERT INTO messenger_messages VALUES
                   ('m1','tenant_a','ua','thread','text',?,1,?,NULL,NULL,NULL,'')''',
                   ('첨부파일: '+name,created))
                source.execute('INSERT INTO messenger_attachments VALUES(?,?,?,?,?,?)',
                               ('m1',name,'application/pdf',contents,len(contents),sha256(contents).hexdigest()))
                real=Pg17AttachmentLabSink(app_uri,a_token)
                wrong=Pg17AttachmentLabSink(app_uri,b_token)
                stage='cross-tenant signed write denial'
                try:relay_attachments(source,wrong)
                except (RelayRefused,psycopg.Error):pass
                else:raise AssertionError('Cross-tenant attachment write permitted')
                assert source.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]==0
                stage='post-PG-commit and before-ACK crash'
                try:relay_attachments(source,real,after_pg_commit=lambda:(_ for _ in ()).throw(RuntimeError('injected crash')))
                except RuntimeError:pass
                else:raise AssertionError('Crash hook not executed')
                assert source.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]==0
                stage='durable complete byte readback and replay'
                assert relay_attachments(source,real)=={'delivered':1,'ack_seq':2,'cutover_approved':False}
                assert relay_attachments(source,real)['delivered']==0
                with psycopg.connect(admin,connect_timeout=5) as pg:
                    with pg.cursor() as cur:
                        cur.execute('SELECT source_seq,filename,mime,data,size_bytes,content_sha256,create_seq FROM jw_attach_v57.blobs')
                        rows=cur.fetchall()
                        assert rows==[(2,name,'application/pdf',contents,len(contents),sha256(contents).hexdigest(),1)]
                        cur.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='jw_attach_v57.blobs'::regclass")
                        assert cur.fetchone()==(True,True)
                        cur.execute("SELECT has_table_privilege('jw_app','jw_attach_v57.blobs','UPDATE'),has_table_privilege('jw_app','jw_attach_v57.blobs','DELETE')")
                        assert cur.fetchone()==(False,False)
                stage='signed cross-tenant read isolation'
                with wrong._delegate._connect() as pg:
                    with pg.cursor() as cur:
                        wrong._delegate._bind(cur)
                        cur.execute('SELECT COUNT(*) FROM jw_attach_v57.blobs')
                        assert cur.fetchone()[0]==0
                stage='unsupported receipt remains blocked'
                source.execute("INSERT INTO messenger_receipts VALUES('m1','tenant_b')")
                try:relay_attachments(source,real)
                except RelayRefused:pass
                else:raise AssertionError('Receipt silently passed as attachment')
                assert source.execute(f'SELECT ack_seq FROM {STATE}').fetchone()[0]==2
                stage='signed session revocation'
                with psycopg.connect(admin,connect_timeout=5) as pg:
                    with pg.cursor() as cur:
                        cur.execute('UPDATE jw_guard.authenticated_sessions SET revoked_at=clock_timestamp() WHERE token_digest=%s',
                                    (sha256(a_token.encode()).digest(),))
                        assert cur.rowcount==1
                try:real.verified_identity()
                except (RelayRefused,psycopg.Error):pass
                else:raise AssertionError('Revoked user may write attachment')
        print('PASS: V5.7 PG17 exact attachment bytes, signed RLS, postcommit replay, checkpoint and cleanup')
        print('BLOCKED: receipt actor signatures, object-storage production, business cutover')
        return 0
    except Exception as error:
        print(f'FAIL: V5.7 stage={stage} type={type(error).__name__} (filename, data and credentials withheld)',file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(run())
