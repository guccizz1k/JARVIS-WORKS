"""V4.1 isolated PG17 committed-write recovery and rollback security drill.

Runs only inside the existing disposable CI cluster after the V4.0 suite.
Never touches production, real organizations, app.main or persistent databases.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import os
import secrets
import uuid

from scripts.test_postgres_writer_v40 import _verified_lab_uri


class ExpectedRollback(RuntimeError):
    """Synthetic injected failure; must cancel a still-uncommitted message."""


def check_persisted_row(*, rows, request_id: str, sender_org: str, content: str,
                        expected_id: str, expected_seq: int):
    """Verify exactly one durable committed message with the original evidence."""
    if len(rows) != 1 or type(expected_seq) is not int or expected_seq <= 0:
        raise AssertionError('Persisted row count or sequence mismatch')
    row = rows[0]
    if row != (expected_id, expected_seq, request_id, sender_org, content):
        raise AssertionError('Persisted immutable message evidence changed')


def run() -> int:
    if (os.getenv('JW_PG_LAB_V41') != 'ONLY_DISPOSABLE_LAB'
            or os.getenv('JW_PG_LAB_V40') != 'ONLY_DISPOSABLE_LAB'
            or os.getenv('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE'):
        print('NOT RUN: V4.1 disposable/recovery gate authorization absent')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from fastapi.testclient import TestClient
        from app.pg_write_api_v40 import create_lab_app
        from app.pg_messenger_review import MessengerReviewAdapter
        admin = os.getenv('JW_PG_TEST_ADMIN_DSN', '')
        app_dsn = os.getenv('JW_PG_TEST_APP_DSN', '')
        uri = _verified_lab_uri(conninfo_to_dict(admin), conninfo_to_dict(app_dsn))
        # Refuse arbitrary roles and URL grammar prior to any test writes.
        adapter = MessengerReviewAdapter(uri)
        adapter._check_dsn()
    except (ImportError, RuntimeError, ValueError, TypeError):
        print('NOT RUN: V4.1 safe disposable PG17 or dependencies unavailable')
        return 2

    tokens = {org: secrets.token_urlsafe(40) for org in ('tenant_a', 'tenant_b', 'tenant_c')}
    stage = 'create-synthetic-auth-sessions'
    thread = 'chat_ab'
    path = '/lab40/threads/chat_ab/messages'
    key = secrets.token_hex(16)
    body = {'content': 'v41 durable recovery checkpoint', 'request_id': key}
    head = lambda org: {'X-JW-Lab-Session': tokens[org]}
    try:
        # New token rows only in the randomly provisioned jw_v20_test_* DB.
        with psycopg.connect(admin, connect_timeout=5) as db:
            with db.cursor() as cur:
                for org, actor in (('tenant_a', 'ua'), ('tenant_b', 'ub'), ('tenant_c', 'uc')):
                    cur.execute('''INSERT INTO jw_guard.authenticated_sessions
                        (token_digest,org_id,user_id,mfa_verified,expires_at)
                        VALUES(%s,%s,%s,true,%s)''',
                        (sha256(tokens[org].encode()).digest(), org, actor,
                         datetime.now(timezone.utc) + timedelta(minutes=10)))
        stage = 'write-before-recreated-app'
        with TestClient(create_lab_app(uri)) as client:
            first = client.post(path, json=body, headers=head('tenant_a'))
            assert first.status_code == 201, 'First durable message refused'
            original_id = first.json()['id']
            original_seq = first.json()['message_seq']
            assert first.json()['replayed'] is False and isinstance(original_seq, int)

        # Create a new app and new PG connections, never reuse the old TestClient.
        stage = 'recreated-app-exact-replay'
        with TestClient(create_lab_app(uri)) as client:
            retry = client.post(path, json=body, headers=head('tenant_a'))
            assert retry.status_code == 200, 'Durable message incorrectly reinserted'
            assert retry.json() == {'id': original_id, 'message_seq': original_seq, 'replayed': True}
            stage = 'recreated-app-conflict'
            conflict = client.post(path, json={**body, 'content': 'changed'}, headers=head('tenant_a'))
            assert conflict.status_code == 409
            stage = 'partner-read-and-outsider-denial'
            visible = adapter.list_messages(tokens['tenant_b'], thread, after=original_seq-1, limit=100)
            assert len([m for m in visible if m[0] == original_id]) == 1
            assert adapter.list_messages(tokens['tenant_c'], thread, after=0) == []

        stage = 'durable-single-row-evidence'
        with psycopg.connect(admin, connect_timeout=5) as db:
            with db.cursor() as cur:
                cur.execute('''SELECT id,message_seq,request_id,sender_org,body
                         FROM public.messenger_messages WHERE sender_org=%s AND request_id=%s''',
                         ('tenant_a', key))
                check_persisted_row(rows=cur.fetchall(), request_id=key,
                                    sender_org='tenant_a', content=body['content'],
                                    expected_id=original_id, expected_seq=original_seq)

        stage = 'read-pre-interruption-thread-counter'
        with psycopg.connect(admin, connect_timeout=5) as db:
            with db.cursor() as cur:
                cur.execute('SELECT last_seq FROM jw_guard.messenger_counters WHERE connection_id=%s', (thread,))
                before_abort = cur.fetchone()[0]
                assert before_abort >= original_seq

        rollback_key = secrets.token_hex(16)
        interrupted_id = uuid.uuid4().hex
        stage = 'inject-uncommitted-write-failure'
        try:
            with adapter.verified_transaction(tokens['tenant_a'], readonly=False) as (cur, tenant, actor):
                cur.execute('''INSERT INTO public.messenger_messages
                    (id,connection_id,sender_org,sender_user,kind,body,request_id)
                    VALUES (%s,%s,%s,%s,'text',%s,%s) RETURNING message_seq''',
                    (interrupted_id, thread, tenant, actor, 'v41 injected failure', rollback_key))
                assert cur.fetchone()[0] == before_abort + 1
                raise ExpectedRollback('Synthetic failure after insert, before commit')
            raise AssertionError('Injected failure did not abort transaction')
        except ExpectedRollback:
            pass
        stage = 'rollback-evidence-absent'
        with psycopg.connect(admin, connect_timeout=5) as db:
            with db.cursor() as cur:
                cur.execute('''SELECT COUNT(*) FROM public.messenger_messages
                               WHERE id=%s OR (sender_org=%s AND request_id=%s)''',
                            (interrupted_id, 'tenant_a', rollback_key))
                assert cur.fetchone() == (0,), 'Uncommitted evidence survived rollback'
                cur.execute('SELECT last_seq FROM jw_guard.messenger_counters WHERE connection_id=%s', (thread,))
                assert cur.fetchone() == (before_abort,), 'Rollback left sequence counter advanced'

        stage = 'retry-interrupted-operation'
        with TestClient(create_lab_app(uri)) as client:
            retried = client.post(path, json={'content':'v41 injected failure',
                                              'request_id':rollback_key}, headers=head('tenant_a'))
            assert retried.status_code == 201
            assert retried.json()['replayed'] is False
            assert retried.json()['message_seq'] == before_abort + 1
            stage = 'retry-committed-exactly-once'
            replay = client.post(path, json={'content':'v41 injected failure',
                                              'request_id':rollback_key}, headers=head('tenant_a'))
            assert replay.status_code == 200 and replay.json()['id'] == retried.json()['id']

        stage = 'revoke-after-reconnection'
        with psycopg.connect(admin, connect_timeout=5) as db:
            with db.cursor() as cur:
                cur.execute('''UPDATE jw_guard.authenticated_sessions
                    SET revoked_at=clock_timestamp() WHERE token_digest=%s''',
                    (sha256(tokens['tenant_a'].encode()).digest(),))
                assert cur.rowcount == 1
        with TestClient(create_lab_app(uri)) as client:
            denied = client.post(path,json={'content':'must be rejected',
                           'request_id':secrets.token_hex(16)},headers=head('tenant_a'))
            assert denied.status_code == 403, 'Revoked user authorized after reconnect'
            stage = 'unaffected-partner-recovery'
            allowed = client.post(path,json={'content':'partner healthy',
                           'request_id':secrets.token_hex(16)},headers=head('tenant_b'))
            assert allowed.status_code == 201, 'Partner denied by unrelated revocation'
            assert 'postgresql://' not in denied.text and tokens['tenant_a'] not in denied.text

        print('PASS: V4.1 real PG17 recreated-app durable replay, bilateral read, '
              'injected rollback, retry exactly once, revocation and partner recovery')
        return 0
    except Exception as exc:
        # Minimal stage without SQL, token, actor names, data values or DSN.
        print('FAIL: V4.1 isolated recovery stage='+stage+' type='+type(exc).__name__+
              ' (sensitive details redacted)')
        return 1


if __name__=='__main__':
    raise SystemExit(run())
