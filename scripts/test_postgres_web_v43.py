"""V4.3 opt-in real PG17 -> FastAPI HTTP boundary integration, synthetic only.

This test is invoked INSIDE the historical disposable cluster supervisor.
It does not listen on ports, touch app.main, migrate SQLite, or use customer data.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import os
import re
import secrets
import sys


def run() -> int:
    required = ('JW_PG_LAB_V43', 'JW_PG_LAB_V42', 'JW_PG_LAB_V41',
                'JW_PG_LAB_V40', 'JW_PG_LAB_V38')
    if (any(os.getenv(k) != 'ONLY_DISPOSABLE_LAB' for k in required)
            or os.getenv('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE'
            or os.getenv('JW_ENV', '').lower() == 'production'):
        print('NOT RUN: V4.3 disposable integration authorization missing')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from fastapi.testclient import TestClient
        from app.pg_web_bridge_v43 import create_lab_app
        from app.pg_messenger_review import MessengerReviewAdapter
        from scripts.test_postgres_writer_v40 import _verified_lab_uri
        admin = os.getenv('JW_PG_TEST_ADMIN_DSN', '')
        app = os.getenv('JW_PG_TEST_APP_DSN', '')
        a, b = conninfo_to_dict(admin), conninfo_to_dict(app)
        dsn = _verified_lab_uri(a, b)
        MessengerReviewAdapter(dsn)._check_dsn()
        if not re.fullmatch(r'jw_v20_test_[a-f0-9]{12}', a.get('dbname', '')):
            raise ValueError('Non-ephemeral database forbidden')
    except (ImportError, TypeError, ValueError, RuntimeError):
        print('NOT RUN: V4.3 guarded PG17 dependencies unavailable')
        return 2

    tokens = {company: secrets.token_urlsafe(40) for company in
              ('tenant_a','tenant_b','tenant_c')}
    digests = [sha256(t.encode()).digest() for t in tokens.values()]
    path = '/lab43/api/messenger/threads/chat_ab/messages'
    stage = 'synthetic-session-fixture'
    ok = False
    cleaned = True
    try:
        with psycopg.connect(admin, connect_timeout=5) as pg:
            with pg.cursor() as cur:
                for company, actor in (('tenant_a','ua'),('tenant_b','ub'),('tenant_c','uc')):
                    cur.execute('''INSERT INTO jw_guard.authenticated_sessions
                        (token_digest,org_id,user_id,mfa_verified,expires_at)
                        VALUES(%s,%s,%s,true,%s)''',
                        (sha256(tokens[company].encode()).digest(), company, actor,
                         datetime.now(timezone.utc) + timedelta(minutes=10)))
        def hdr(company):
            return {'X-JW-Lab-Session': tokens[company]}
        def assert_private(response):
            assert response.headers['Cache-Control'] == 'no-store'
            assert response.headers['X-Content-Type-Options'] == 'nosniff'
            for token in tokens.values():
                assert token not in response.text
            assert 'postgresql://' not in response.text

        stage = 'isolated-web-route-smoke'
        with TestClient(create_lab_app(dsn)) as client:
            key = secrets.token_hex(16)
            body = {'content':'synthetic V4.3 HTTP + PG17', 'request_id':key}
            first = client.post(path, json=body, headers=hdr('tenant_a'))
            assert first.status_code == 201, 'Fresh web message not committed'
            assert_private(first)
            mid = first.json()['id']
            seq = first.json()['message_seq']
            assert type(seq) is int and seq >= 1

            stage = 'http-replay-and-conflict'
            again = client.post(path, json=body, headers=hdr('tenant_a'))
            assert again.status_code == 200
            assert again.json() == {**first.json(), 'replayed': True}
            mismatch = client.post(path, json={**body,'content':'modified'},headers=hdr('tenant_a'))
            assert mismatch.status_code == 409
            assert mismatch.json()['code'] == 'IDEMPOTENCY_CONFLICT'

            stage = 'concurrent-http-duplicate-and-database-exactly-once'
            # Exercise the actual HTTP -> Psycopg path with separate requests,
            # not merely the lower-level V4.0 transaction race.
            parallel_key = secrets.token_hex(16)
            parallel_body = {'content':'synthetic V4.3 concurrent exactly once',
                             'request_id':parallel_key}
            with ThreadPoolExecutor(max_workers=2) as pool:
                jobs = [pool.submit(client.post, path, json=parallel_body,
                                    headers=hdr('tenant_a')) for _ in range(2)]
                pair = [f.result(timeout=20) for f in jobs]
            assert sorted(x.status_code for x in pair) == [200,201]
            assert len({x.json()['id'] for x in pair}) == 1
            assert len({x.json()['message_seq'] for x in pair}) == 1
            assert sorted(x.json()['replayed'] for x in pair) == [False,True]
            with psycopg.connect(admin,connect_timeout=5) as pg:
                with pg.cursor() as cur:
                    cur.execute('''SELECT COUNT(*),COUNT(DISTINCT message_seq)
                                   FROM public.messenger_messages
                                   WHERE sender_org=%s AND request_id=%s''',
                                ('tenant_a',parallel_key))
                    assert cur.fetchone() == (1,1)

            stage = 'http-paginated-read-and-partner'
            read = client.get(path, params={'after':seq-1},headers=hdr('tenant_a'))
            assert read.status_code == 200
            assert any(x['id']==mid and x['mine'] for x in read.json()['messages'])
            partner = client.get(path, params={'after':seq-1}, headers=hdr('tenant_b'))
            assert partner.status_code == 200
            assert any(x['id']==mid and not x['mine'] for x in partner.json()['messages'])
            outsider = client.get(path, headers=hdr('tenant_c'))
            assert outsider.status_code == 404
            assert outsider.json()['code'] == 'THREAD_NOT_FOUND'
            outsider_write = client.post(path, json={**body,'request_id':secrets.token_hex(16)},
                                        headers=hdr('tenant_c'))
            assert outsider_write.status_code == 404

            stage = 'authorization-and-validation'
            assert client.post(path,json=body).status_code==401
            assert client.get(path).status_code==401
            assert client.get(path,headers={'Cookie':'jw_local_dev_session=' + tokens['tenant_a']}).status_code==401
            assert client.post(path,json={**body,'sender_org':'tenant_b'},headers=hdr('tenant_a')).status_code==422
            assert client.post(path,json={**body,'request_id':'INVALID'},headers=hdr('tenant_a')).status_code==422
            assert client.get(path,params={'after':-1},headers=hdr('tenant_a')).status_code==422
            assert client.get('/docs').status_code==404
            assert client.delete(path,headers=hdr('tenant_a')).status_code==405
            absent = client.get('/lab43/api/messenger/threads/not_real/messages',headers=hdr('tenant_a'))
            assert absent.status_code==404

            stage = 'cross-check-exact-pg-row'
            with psycopg.connect(admin, connect_timeout=5) as pg:
                with pg.cursor() as cur:
                    cur.execute('''SELECT id,message_seq,body,COUNT(*) OVER ()
                         FROM public.messenger_messages
                         WHERE sender_org='tenant_a' AND request_id=%s''',(key,))
                    row=cur.fetchone()
                    assert row == (mid, seq, body['content'], 1), 'Exact database evidence mismatch'
                    # Database-authoritative revocation, not just HTTP cookie invalidation.
                    cur.execute('''UPDATE jw_guard.authenticated_sessions
                         SET revoked_at=clock_timestamp() WHERE token_digest=%s''',
                         (digests[0],))
                    assert cur.rowcount == 1
            stage = 'revoke-http-boundary'
            revoked_read=client.get(path,headers=hdr('tenant_a'))
            revoked_write=client.post(path,json={**body,'request_id':secrets.token_hex(16)},
                                      headers=hdr('tenant_a'))
            assert revoked_read.status_code == revoked_write.status_code == 403
            assert revoked_read.json()['code'] == 'TENANT_DENIED'
            assert revoked_write.json()['code'] == 'TENANT_DENIED'
            assert client.get(path,headers=hdr('tenant_b')).status_code==200
            for result in (first,again,mismatch,read,partner,outsider,revoked_read,revoked_write):
                assert_private(result)
        ok = True
    except Exception as exc:
        # Never log SQL exception messages, request bodies, DSNs or tokens.
        print('FAIL: V4.3 HTTP/PG17 stage=' + stage +
              ' type=' + type(exc).__name__ + ' (details redacted)',file=sys.stderr)
    finally:
        # The disposable outer supervisor DROPS the whole database on every path.
        # Also remove test-only sessions if possible; failures must not PASS.
        try:
            with psycopg.connect(admin, connect_timeout=5) as pg:
                with pg.cursor() as cur:
                    cur.execute('''DELETE FROM jw_guard.authenticated_sessions
                        WHERE token_digest=ANY(%s)''',(digests,))
        except Exception as exc:
            cleaned = False
            print('FAIL: V4.3 fixture cleanup type=' + type(exc).__name__ +
                  ' (details redacted)',file=sys.stderr)
    if ok and cleaned:
        print('PASS: V4.3 real PG17 FastAPI HTTP send/read/replay/conflict, '
              'tenant RLS, revocation, error contract and test fixture cleanup')
        return 0
    return 1


if __name__=='__main__':
    raise SystemExit(run())
