"""V4.5 real disposable PostgreSQL 17 evidence-parity HTTP gate.

Actual website-cookie auth was independently established in V4.4. This test
uses a synthetic cookie dependency to isolate the 7-table evidence/RLS seam.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
import os
import re
import secrets
import sqlite3
import sys
import tempfile

# FastAPI resolves deferred dependency annotations from this module's globals.
# Do not import Request only inside run(); that makes req a query parameter (422).
from fastapi import Request


class AuditAssertion(AssertionError):
    """Deterministic synthetic fixture failure label; never contains user data."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def require(ok: bool, code: str) -> None:
    if not ok:
        raise AuditAssertion(code)


def run() -> int:
    if (os.getenv('JW_ENV', '').casefold() == 'production'
            or os.getenv('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE'
            or os.getenv('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE'
            or any(os.getenv('JW_PG_LAB_V'+str(n)) != 'ONLY_DISPOSABLE_LAB'
                   for n in range(35,46))):
        print('NOT RUN: V4.5 disposable evidence lab is not authorized')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from fastapi import HTTPException
        from fastapi.testclient import TestClient
        from app.pg_evidence_shadow_v45 import create_review_app
        from app.pg_cookie_shadow_v44 import ReviewBinding
        from app.pg_messenger_review import MessengerReviewAdapter
        from app.pg_migration_shadow_v36 import source_records
        from app.pg_migration_compat_v37 import stage_compat, verify_compat, drop_compat
        from scripts.v36_synthetic_fixture import fixture
        from scripts.test_postgres_writer_v40 import _verified_lab_uri
        admin=os.environ['JW_PG_TEST_ADMIN_DSN']
        dsn=_verified_lab_uri(conninfo_to_dict(admin),
                              conninfo_to_dict(os.environ['JW_PG_TEST_APP_DSN']))
        assert re.fullmatch(r'jw_v20_test_[a-f0-9]{12}',conninfo_to_dict(admin)['dbname'])
        adapter=MessengerReviewAdapter(dsn)
        adapter._check_dsn()
    except (ImportError,KeyError,TypeError,ValueError,AssertionError):
        print('NOT RUN: missing safe PG17 V4.5 dependencies or disposable DSN')
        return 2
    stage='setup'
    token=secrets.token_urlsafe(40)
    digest=sha256(token.encode()).digest()
    cookie=secrets.token_urlsafe(40)
    thread=secrets.token_hex(16)
    installed=False
    cleanup_ok=True
    passed=False
    failed_stage=None
    failed_code=None
    cleanup_error=None
    with tempfile.TemporaryDirectory(prefix='jw-v45-synthetic-') as d:
        dbpath=Path(d)/'evidence.db'
        original=fixture()
        try:
            # No destructive production migration. Modify ONLY V3.6 fixture IDs.
            original.execute('PRAGMA foreign_keys=OFF')
            original.execute('UPDATE messenger_connections SET id=? WHERE id=?',(thread,'thread_ab'))
            original.execute('UPDATE messenger_messages SET connection_id=? WHERE connection_id=?',(thread,'thread_ab'))
            original.execute('UPDATE messenger_read_positions SET connection_id=? WHERE connection_id=?',(thread,'thread_ab'))
            original.commit()
            original.execute('PRAGMA foreign_keys=ON')
            require(original.execute('PRAGMA foreign_key_check').fetchone() is None, 'SOURCE_FOREIGN_KEY')
            with sqlite3.connect(dbpath) as site:
                original.backup(site)
            original.close()
            with sqlite3.connect(dbpath) as site:
                records=source_records(site)
            stage='immutable-V3.7-typed-compat-stage'
            with psycopg.connect(admin,autocommit=True,connect_timeout=5) as pg:
                try:
                    stage_compat(pg,records)
                    installed=True
                    require(verify_compat(pg,records)['rows']==len(records), 'PG_TYPED_STAGE_PARITY')
                    with pg.cursor() as cur:
                        cur.execute('''INSERT INTO jw_guard.authenticated_sessions
                            (token_digest,org_id,user_id,mfa_verified,expires_at)
                            VALUES (%s,'tenant_a','ua',true,%s)''',
                            (digest,datetime.now(timezone.utc)+timedelta(minutes=10)))
                    @contextmanager
                    def sqlite_conn():
                        con=sqlite3.connect(dbpath,isolation_level=None)
                        try:yield con
                        finally:con.close()
                    def website_cookie(req:Request):
                        if req.cookies.get('jw_v45_synthetic_cookie')!=cookie:
                            raise HTTPException(401,'Synthetic cookie required')
                        return {'org_id':'tenant_a','id':'ua'}
                    def broker(org,user,target):
                        assert (org,user,target)==('tenant_a','ua',thread)
                        return ReviewBinding('tenant_a','ua','tenant_a','ua',thread,token,
                            (('tenant_a','tenant_a'),('tenant_b','tenant_b')),
                            (('ua','ua'),('ub','ub')))
                    isolated=create_review_app(dsn=dsn,adapter=adapter,sqlite_conn=sqlite_conn,
                        trusted_broker=broker,website_current_user=website_cookie)
                    stage='RLS-full-evidence-HTTP-parity'
                    with TestClient(isolated,base_url='https://testserver') as client:
                        endpoint='/lab45/threads/'+thread+'/evidence'
                        require(client.get(endpoint).status_code==401, 'COOKIE_REQUIRED')
                        require(client.get(endpoint,headers={'X-JW-Lab-Session':token}).status_code==401, 'FORGED_HEADER_REJECTED')
                        client.cookies.set('jw_v45_synthetic_cookie',cookie)
                        baseline=client.get(endpoint)
                        # Only a fixed allowlist from our own API may enter logs.
                        # Never print response.text, SQL, cookies, tokens or DSNs.
                        if baseline.status_code != 200:
                            try:
                                code = baseline.json().get('code', 'UNKNOWN')
                            except (ValueError, AttributeError, TypeError):
                                code = 'UNKNOWN'
                            if code not in ('PG_UNAVAILABLE', 'AUTH_DENIED',
                                            'THREAD_NOT_FOUND', 'INVALID_THREAD'):
                                code = 'UNKNOWN'
                            raise AuditAssertion('BASELINE_HTTP_'+str(baseline.status_code)
                                                 +'_'+code)
                        response=baseline.json()
                        state = response.get('status')
                        if state not in ('MATCH', 'MISMATCH', 'INCOMPLETE',
                                         'EMPTY_EVIDENCE', 'EMPTY_UNVERIFIED', 'UNSUPPORTED'):
                            state = 'UNKNOWN'
                        require(response.get('status')=='MATCH' and response.get('evidence_parity') is True,
                                'EVIDENCE_STATUS_'+state)
                        require(response.get('cutover_approved') is False, 'CUTOVER_PROTECTION')
                        require(response.get('counts',{}).get('messenger_messages')==3, 'EVIDENCE_COUNT_MESSENGER_MESSAGES')
                        require(response.get('counts',{}).get('messenger_attachments')==1, 'EVIDENCE_COUNT_MESSENGER_ATTACHMENTS')
                        require(response.get('counts',{}).get('messenger_edits')==1, 'EVIDENCE_COUNT_MESSENGER_EDITS')
                        require(response.get('counts',{}).get('messenger_receipts')==1, 'EVIDENCE_COUNT_MESSENGER_RECEIPTS')
                        require(response.get('counts',{}).get('messenger_read_positions')==1, 'EVIDENCE_COUNT_MESSENGER_READ_POSITIONS')
                        require(token not in baseline.text and 'PG' not in baseline.text, 'RESPONSE_PRIVACY')
                        require(client.post(endpoint).status_code==405, 'WRITE_ROUTE_REFUSED')
                        stage='byte-and-receipt-tamper-detection'
                        with sqlite3.connect(dbpath) as site:
                            site.execute("UPDATE messenger_attachments SET filename='FORGED.png' WHERE message_id='msg_file'")
                        bad=client.get(endpoint)
                        require(bad.status_code==200 and bad.json().get('status')=='MISMATCH', 'ATTACHMENT_TAMPER_DETECTION')
                        with sqlite3.connect(dbpath) as site:
                            site.execute("UPDATE messenger_attachments SET filename='synthetic-한글.png' WHERE message_id='msg_file'")
                            site.execute("DELETE FROM messenger_receipts WHERE message_id='msg_order'")
                        require(client.get(endpoint).json().get('status')=='MISMATCH', 'RECEIPT_REMOVAL_DETECTION')
                        stage='PG-session-revocation'
                        with pg.cursor() as cur:
                            cur.execute('UPDATE jw_guard.authenticated_sessions SET revoked_at=clock_timestamp() WHERE token_digest=%s',(digest,))
                            require(cur.rowcount==1, 'SESSION_REVOKE_ROWS')
                        denied=client.get(endpoint)
                        require(denied.status_code in (403,503), 'SESSION_REVOKE_HTTP_'+str(denied.status_code))
                        require(not denied.json().get('evidence_parity'), 'REVOKED_SESSION_PARITY')
                    passed=True
                finally:
                    # Preserve the ACTUAL failed test stage. A finally block must
                    # never mask the primary assertion with a cleanup phase name.
                    if installed:
                        try:
                            drop_compat(pg)
                            with pg.cursor() as cur:
                                cur.execute('SELECT to_regnamespace(%s)',('jw_migration_v37',))
                                require(cur.fetchone()==(None,), 'SCHEMA_STILL_EXISTS')
                        except Exception as exc:
                            cleanup_ok=False
                            cleanup_error=(exc.code if isinstance(exc, AuditAssertion)
                                           else type(exc).__name__)
        except Exception as exc:
            failed_stage=stage
            failed_code=exc.code if isinstance(exc, AuditAssertion) else type(exc).__name__
            print('FAIL: V4.5 PG17 evidence stage='+failed_stage+' code='+failed_code+
                  ' (details redacted)',file=sys.stderr)
    if not cleanup_ok:
        print('FAIL: V4.5 ephemeral evidence-schema cleanup code='+
              str(cleanup_error)+' (details redacted)',file=sys.stderr)
        return 1
    if passed and failed_stage is None:
        print('PASS: V4.5 PG17 RLS evidence bytes, edits, receipts, order snapshot and requester read position; cleanup')
        return 0
    return 1


if __name__=='__main__':
    raise SystemExit(run())
