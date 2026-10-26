"""Real PG17 + FastAPI TestClient integration against synthetic A/B/C sessions.

Invoked ONLY inside the pre-existing disposable PG17 gate, after V2.8 tests.
Never publishes an HTTP port; never uses customer records or production DB.
"""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import os
import re
import secrets
from urllib.parse import quote


def run():
    if os.getenv('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE':
        print('NOT RUN: explicit ephemeral SQL gate missing')
        return 2
    admin_dsn = os.getenv('JW_PG_TEST_ADMIN_DSN', '')
    app_dsn = os.getenv('JW_PG_TEST_APP_DSN', '')
    if not admin_dsn or not app_dsn:
        print('NOT RUN: local disposable database session not provided')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from fastapi.testclient import TestClient
        from app.pg_messenger_review import MessengerReviewAdapter
        from app.pg_messenger_lab import create_lab_app
    except ImportError:
        print('NOT RUN: PG17 FastAPI test dependencies unavailable')
        return 2
    opts = conninfo_to_dict(app_dsn)
    db_name = opts.get('dbname', '')
    if (not re.fullmatch(r'jw_v20_test_[0-9a-f]{12}',db_name)
            or opts.get('host') not in ('127.0.0.1','localhost','::1')
            or opts.get('user') != 'jw_app' or not opts.get('password')):
        print('NOT RUN: rejected non-ephemeral lab connection')
        return 2
    uri = ('postgresql://' + quote(opts['user'],safe='') + ':'
           + quote(opts['password'],safe='') + '@' + opts['host']
           + ':' + str(opts.get('port','5432')) + '/' + db_name)
    tokens = {tenant:secrets.token_urlsafe(40) for tenant in ('tenant_a','tenant_b','tenant_c')}
    try:
        with psycopg.connect(admin_dsn) as db:
            with db.cursor() as c:
                c.execute('SELECT current_database(), current_user')
                if c.fetchone() != (db_name,'postgres'):
                    raise AssertionError('Admin must be disposable PG test role')
                for tenant, user in [('tenant_a','ua'),('tenant_b','ub'),('tenant_c','uc')]:
                    token=tokens[tenant]
                    c.execute('''INSERT INTO jw_guard.authenticated_sessions
                        (token_digest,org_id,user_id,mfa_verified,expires_at)
                        VALUES(%s,%s,%s,true,%s)''',(
                        sha256(token.encode()).digest(),tenant,user,
                        datetime.now(timezone.utc)+timedelta(minutes=30)))
        app = create_lab_app(adapter=MessengerReviewAdapter(uri))
        h=lambda tenant:{'X-JW-Lab-Session':tokens[tenant]}
        with TestClient(app) as client:
            assert client.get('/lab/threads/chat_ab/messages').status_code == 401
            ra=client.get('/lab/threads/chat_ab/messages?limit=100',headers=h('tenant_a'))
            rb=client.get('/lab/threads/chat_ab/messages',headers=h('tenant_b'))
            rc=client.get('/lab/threads/chat_ab/messages',headers=h('tenant_c'))
            assert ra.status_code==200 and ra.json()['messages'], 'A lost its own chat'
            assert rb.status_code==200 and rb.json()['messages'], 'B lost shared chat'
            assert rc.status_code==200 and rc.json()['messages']==[], 'C accessed A/B chat'
            key=secrets.token_hex(16)
            sent=client.post('/lab/threads/chat_ab/messages',headers=h('tenant_a'),
                             json={'content':'synthetic FastAPI PG17 write','request_id':key})
            assert sent.status_code==201, 'A write denied'
            mid,seq=sent.json()['id'],sent.json()['message_seq']
            assert isinstance(seq,int) and seq>0
            read=client.get('/lab/threads/chat_ab/messages?after='+str(seq-1),headers=h('tenant_b'))
            assert read.status_code==200 and any(x['id']==mid for x in read.json()['messages'])
            forbidden=client.post('/lab/threads/chat_ab/messages',headers=h('tenant_c'),
                json={'content':'cross-tenant forgery','request_id':secrets.token_hex(16)})
            assert forbidden.status_code==403, 'C was able to send to A/B chat'
            assert tokens['tenant_c'] not in forbidden.text and 'postgresql://' not in forbidden.text
            read_ack=client.put('/lab/threads/chat_ab/read',headers=h('tenant_a'),json={'last_seq':seq})
            assert read_ack.status_code==200, 'Legitimate read position update failed'
            cross_ack=client.put('/lab/threads/chat_ab/read',headers=h('tenant_c'),json={'last_seq':seq})
            assert cross_ack.status_code==403, 'Third company forged read marker'
            duplicate=client.post('/lab/threads/chat_ab/messages',headers=h('tenant_a'),
                        json={'content':'duplicate','request_id':key})
            assert duplicate.status_code==409, 'Duplicate request was not rejected'
            with psycopg.connect(admin_dsn) as db:
                with db.cursor() as c:
                    c.execute('''UPDATE jw_guard.authenticated_sessions SET revoked_at=clock_timestamp()
                        WHERE token_digest=%s''',(sha256(tokens['tenant_a'].encode()).digest(),))
                    assert c.rowcount == 1
            after_revocation=client.get('/lab/threads/chat_ab/messages',headers=h('tenant_a'))
            assert after_revocation.status_code==403, 'Revoked PG synthetic session remained active'
            assert client.get('/lab/threads/chat_ab/messages',headers=h('tenant_b')).status_code==200
        print('PASS: V3.5 FastAPI TestClient + real PG17 tenant isolation, writes, reads, idempotency, revocation')
        return 0
    except Exception as exc:
        print('FAIL: V3.5 PostgreSQL API lab gate: '+type(exc).__name__+' (details redacted)')
        return 1
