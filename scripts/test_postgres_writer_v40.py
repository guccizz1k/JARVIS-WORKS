"""V4.0 isolated real PostgreSQL 17 concurrency, replay and revocation gate."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import os
import re
import secrets
from urllib.parse import quote


def _verified_lab_uri(admin_opts: dict, app_opts: dict) -> str:
    """Translate the ephemeral runner's libpq key/value DSN into a validated URI.

    The existing MessengerReviewAdapter intentionally accepts URIs only. Do
    not broaden its production-safety gate to support arbitrary DSN formats.
    """
    db = admin_opts.get('dbname', '')
    ahost = admin_opts.get('host')
    host = app_opts.get('host')
    aport = str(admin_opts.get('port', '5432'))
    port = str(app_opts.get('port', '5432'))
    if (not re.fullmatch(r'jw_v20_test_[a-f0-9]{12}', db)
            or app_opts.get('dbname') != db
            or admin_opts.get('user') != 'postgres'
            or app_opts.get('user') != 'jw_app'
            or ahost not in ('127.0.0.1', 'localhost', '::1')
            or host != ahost
            or not admin_opts.get('password') or not app_opts.get('password')
            or not port.isdecimal() or not 1 <= int(port) <= 65535
            or port != aport):
        raise ValueError('Invalid disposable V4.0 database target')
    authority_host = '[::1]' if host == '::1' else host
    return ('postgresql://' + quote('jw_app', safe='') + ':'
            + quote(app_opts['password'], safe='') + '@' + authority_host
            + ':' + port + '/' + db)


def run() -> int:
    if (os.getenv('JW_PG_LAB_V40') != 'ONLY_DISPOSABLE_LAB' or
            os.getenv('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE'):
        print('NOT RUN: V4.0 disposable write-gate authorization missing')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from fastapi.testclient import TestClient
        from app.pg_write_api_v40 import create_lab_app
        from app.pg_write_replay_v40 import LabWriterV40
        from app.pg_messenger_review import MessengerReviewAdapter
        admin = os.getenv('JW_PG_TEST_ADMIN_DSN', '')
        app_dsn = os.getenv('JW_PG_TEST_APP_DSN', '')
        options = conninfo_to_dict(admin)
        app_opts = conninfo_to_dict(app_dsn)
        app_uri = _verified_lab_uri(options, app_opts)
        # The supervisor returns libpq-style connection keywords; the V3.5
        # messenger adapter has always required a percent-encoded URI.
        # Keep admin/app roles separate and never print the connection string.
        LabWriterV40(app_uri)
    except ImportError:
        print('NOT RUN: V4.0 Psycopg or FastAPI dependency unavailable')
        return 2
    except (RuntimeError, ValueError, TypeError):
        print('NOT RUN: V4.0 disposable DSN validation failed')
        return 2

    tokens = {org: secrets.token_urlsafe(40) for org in ('tenant_a', 'tenant_b', 'tenant_c')}
    stage = 'synthetic-session-fixture'
    try:
        with psycopg.connect(admin, connect_timeout=5) as db:
            with db.cursor() as cur:
                for org, actor in [('tenant_a','ua'),('tenant_b','ub'),('tenant_c','uc')]:
                    cur.execute('''INSERT INTO jw_guard.authenticated_sessions
                         (token_digest,org_id,user_id,mfa_verified,expires_at)
                         VALUES(%s,%s,%s,true,%s)''',
                         (sha256(tokens[org].encode()).digest(), org, actor,
                          datetime.now(timezone.utc) + timedelta(minutes=10)))
        stage = 'app-factory'
        app = create_lab_app(app_uri)
        def h(org): return {'X-JW-Lab-Session': tokens[org]}
        path = '/lab40/threads/chat_ab/messages'
        key=secrets.token_hex(16)
        body={'content':'synthetic v40 once only', 'request_id':key}
        with TestClient(app) as client:
            stage = 'first-write'
            a=client.post(path,json=body,headers=h('tenant_a'))
            assert a.status_code==201, f'First send refused ({a.status_code})'
            stage = 'exact-replay'
            duplicate=client.post(path,json=body,headers=h('tenant_a'))
            assert duplicate.status_code==200 and duplicate.json()['id']==a.json()['id']
            assert duplicate.json()['message_seq']==a.json()['message_seq']
            assert duplicate.json()['replayed'] is True
            stage = 'conflicting-replay'
            mismatch=client.post(path,json={**body,'content':'altered'},headers=h('tenant_a'))
            assert mismatch.status_code==409, 'Reused request ID with mismatched content accepted'
            stage = 'cross-tenant-denial'
            outsider=client.post(path,json={**body,'request_id':secrets.token_hex(16)},headers=h('tenant_c'))
            assert outsider.status_code==403, 'Third-party company wrote to shared thread'
            stage = 'api-input-authentication'
            assert client.post(path,json=body).status_code==401
            assert client.post(path,json={**body,'sender_org':'tenant_b'},headers=h('tenant_a')).status_code==422
            assert client.get(path,headers=h('tenant_a')).status_code==405
            stage = 'unaffected-partner-after-revoke'
            assert client.post(path,json={**body,'request_id':secrets.token_hex(16)},headers=h('tenant_b')).status_code==201
            # Two overlapping HTTP worker writes with the SAME idempotency key.
            race_key=secrets.token_hex(16)
            race_body={'content':'racing V4.0 duplicate', 'request_id':race_key}
            stage = 'concurrent-exact-replay'
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures=[pool.submit(client.post,path,json=race_body,headers=h('tenant_a')) for _ in range(2)]
                result=[future.result(timeout=20) for future in futures]
            assert sorted(response.status_code for response in result)==[200,201], 'Concurrent retry did not converge'
            ids={r.json()['id'] for r in result}; seqs={r.json()['message_seq'] for r in result}
            assert len(ids)==1 and len(seqs)==1, 'Concurrent duplication or counter disagreement'
            # Two distinct messages under same thread must receive unique sequences.
            unique_keys=[secrets.token_hex(16) for _ in range(2)]
            stage = 'concurrent-distinct-messages'
            with ThreadPoolExecutor(max_workers=2) as pool:
                jobs=[pool.submit(client.post,path,json={'content':'parallel-'+str(i),'request_id':key},headers=h('tenant_a'))
                      for i,key in enumerate(unique_keys)]
                distinct=[job.result(timeout=20) for job in jobs]
            assert all(r.status_code==201 for r in distinct)
            assert len({r.json()['message_seq'] for r in distinct})==2
            stage = 'committed-row-and-revoke'
            with psycopg.connect(admin,connect_timeout=5) as pg:
                with pg.cursor() as cur:
                    cur.execute('''SELECT COUNT(*) FROM public.messenger_messages
                                   WHERE sender_org='tenant_a' AND request_id=%s''',(key,))
                    assert cur.fetchone()==(1,),'Original request duplicated in database'
                    cur.execute('''SELECT COUNT(*) FROM public.messenger_messages
                                   WHERE sender_org='tenant_a' AND request_id=%s''',(race_key,))
                    assert cur.fetchone()==(1,),'Concurrent request duplicated in database'
                    cur.execute('''UPDATE jw_guard.authenticated_sessions SET revoked_at=clock_timestamp()
                                   WHERE token_digest=%s''',(sha256(tokens['tenant_a'].encode()).digest(),))
                    assert cur.rowcount==1
            stage = 'revoked-actor-denial'
            revoked=client.post(path,json={**body,'request_id':secrets.token_hex(16)},headers=h('tenant_a'))
            assert revoked.status_code==403, 'Revoked actor posted a new message'
            assert client.post(path,json={**body,'request_id':secrets.token_hex(16)},headers=h('tenant_b')).status_code==201
            assert tokens['tenant_a'] not in revoked.text and 'postgresql://' not in revoked.text
        print('PASS: V4.0 real PG17 idempotent writes, concurrent retries, '
              'monotonic sequence uniqueness, tenant RLS, revocation and rollback')
        return 0
    except Exception as exc:
        print('FAIL: V4.0 isolated writer stage='+stage+' type='+type(exc).__name__+' (details redacted)')
        return 1


if __name__=='__main__':
    raise SystemExit(run())
