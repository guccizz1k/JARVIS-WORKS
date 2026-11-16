"""Real loopback HTTPS messenger/admin smoke against disposable tenant SQLite.

Never touches connected Supabase, Render or production accounts.
"""
import os
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


def test_v223_messenger_and_admin_real_loopback_https(tmp_path):
    cert = tmp_path / 'server.crt'
    key = tmp_path / 'server.key'
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '1',
        '-nodes', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout', str(key), '-out', str(cert)
    ], check=True, capture_output=True)
    key.chmod(0o600)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    db_path = tmp_path / 'isolated-messenger.db'
    env = {
        **os.environ,
        'JW_ENV': 'review',
        'DEMO_SEED': '1',
        'JARVIS_DB_PATH': str(db_path),
        'JW_ROOT_UI': 'owner-visual-review',
        'JW_APPROVED_UI_REVIEW': 'ISOLATED_REVIEW_ONLY',
        'JW_NO_EXTERNAL_DATABASE': '1',
    }
    for secret in ('BOOTSTRAP_EMAIL', 'BOOTSTRAP_PASSWORD', 'BOOTSTRAP_ORG', 'JW_INSECURE_LOCAL_DEV'):
        env.pop(secret, None)
    origin = f'https://127.0.0.1:{port}'
    context = ssl.create_default_context(cafile=str(cert))
    with (tmp_path / 'https-server.log').open('w') as server_log:
        proc = subprocess.Popen([
            sys.executable, '-m', 'uvicorn', 'app.owner_review_app_v223:app', '--host', '127.0.0.1',
            '--port', str(port), '--ssl-certfile', str(cert), '--ssl-keyfile', str(key)
        ], cwd=ROOT, env=env, stdout=server_log, stderr=subprocess.STDOUT)
        clients = []
        try:
            def client():
                c = httpx.Client(verify=context, trust_env=False, timeout=8.0)
                clients.append(c)
                return c

            probe = client()
            for _ in range(120):
                assert proc.poll() is None, 'Isolated HTTPS process exited'
                try:
                    if probe.get(origin + '/api/health').status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                time.sleep(0.1)
            else:
                raise AssertionError('Isolated HTTPS readiness timeout')

            def login(c, email):
                r = c.post(origin + '/api/login', json={
                    'email': email, 'password': 'Demo!2026secure',
                })
                assert r.status_code == 200, (email, r.status_code)
                assert r.cookies.get('jw_session') or r.headers.get('set-cookie')
                return r.json()

            a, b = client(), client()
            alice = login(a, 'demo@hanbit.example')
            bob = login(b, 'demo@bada.example')
            org_a, org_b = alice['user']['org_id'], bob['user']['org_id']
            assert org_a != org_b
            csrf_a, csrf_b = alice['csrf_token'], bob['csrf_token']
            headers_a = {'X-CSRF-Token': csrf_a}
            headers_b = {'X-CSRF-Token': csrf_b}

            directory = a.get(origin + '/api/messenger/directory')
            assert directory.status_code == 200
            assert any(x['org_id'] == org_b for x in directory.json())
            assert all(x['org_id'] != org_a for x in directory.json())

            # Creation is explicit. CSRF-free writes must be rejected.
            url = origin + '/api/messenger/threads'
            assert a.post(url, json={'recipient_org_id': org_b}).status_code == 403
            made = a.post(url, json={'recipient_org_id': org_b}, headers=headers_a)
            assert made.status_code == 201, made.status_code
            tid = made.json()['id']
            assert len(tid) == 32
            assert b.get(origin + '/api/messenger/threads').status_code == 200

            send_url = origin + f'/api/messenger/threads/{tid}/messages'
            request_id = uuid.uuid4().hex
            payload = {'content': 'Synthetic real HTTPS message', 'request_id': request_id}
            assert a.post(send_url, json=payload).status_code == 403
            sent = a.post(send_url, json=payload, headers=headers_a)
            assert sent.status_code == 201, sent.status_code
            mid = sent.json()['id']
            repeated = a.post(send_url, json=payload, headers=headers_a)
            assert repeated.status_code == 201
            assert repeated.json()['id'] == mid  # idempotent retry
            messages_b = b.get(send_url)
            assert messages_b.status_code == 200
            found = [m for m in messages_b.json() if m['id'] == mid]
            assert len(found) == 1 and found[0]['mine'] is False
            assert found[0]['sender_org'] == org_a
            assert found[0]['body'] == payload['content']
            read = b.post(origin + f'/api/messenger/threads/{tid}/read',
                          json={'last_message_id': mid}, headers=headers_b)
            assert read.status_code == 200 and read.json()['status'] == 'read'

            # Authenticated personal profile & UI preferences are real HTTPS server state.
            p_before=a.get(origin+'/api/account/profile')
            assert p_before.status_code==200
            p_obj=p_before.json()
            assert p_obj['id']==alice['user']['id'] and p_obj['org_id']==org_a
            assert p_obj['version']==0
            assert a.post(origin+'/api/account/profile',
                          json={'version':0,'name':'Synthetic HTTPS Renamed'}).status_code==403
            p_update=a.post(origin+'/api/account/profile',
                            headers=headers_a,json={'version':0,'name':'Synthetic HTTPS Renamed'})
            assert p_update.status_code==200, p_update.status_code
            assert p_update.json()['version']==1
            assert a.get(origin+'/api/account/profile').json()['name']=='Synthetic HTTPS Renamed'
            assert a.get(origin+'/api/me').json()['name']=='Synthetic HTTPS Renamed'
            assert a.post(origin+'/api/account/profile',headers=headers_a,
                          json={'version':0,'name':'Stale'}).status_code==409
            assert b.get(origin+'/api/account/profile').json()['name']!= 'Synthetic HTTPS Renamed'
            options=a.get(origin+'/api/account/preferences')
            assert options.status_code==200
            assert options.json()['version']==0
            op=a.post(origin+'/api/account/preferences',headers=headers_a,json={
                'version':0,'compact_view':True,'messenger_auto_refresh':False})
            assert op.status_code==200, op.status_code
            assert op.json()['version']==1
            assert a.get(origin+'/api/account/preferences').json()['compact_view'] is True
            assert b.get(origin+'/api/account/preferences').json()['compact_view'] is False
            assert a.post(origin+'/api/account/preferences',headers=headers_a,json={
                'version':0,'compact_view':False,'messenger_auto_refresh':True}).status_code==409

            # Immutable trade-statement index: production-style flow, isolated HTTPS only.
            quotes=a.get(origin+'/api/quotes')
            assert quotes.status_code==200 and quotes.json()
            quote_id=quotes.json()[0]['id']
            for transition in ('sent','accepted'):
                changed=a.post(origin+f'/api/quotes/{quote_id}/status',
                               headers=headers_a,json={'status':transition})
                assert changed.status_code==200,(transition,changed.status_code)
            ordered=a.post(origin+'/api/orders/from-quote',headers=headers_a,
                           json={'quote_id':quote_id,'due_date':'2099-12-30'})
            assert ordered.status_code==201,ordered.status_code
            order_id=ordered.json()['id']
            for transition in ('processing','fulfilled'):
                changed=a.post(origin+f'/api/orders/{order_id}/status',
                               headers=headers_a,json={'status':transition})
                assert changed.status_code==200,(transition,changed.status_code)
            minted=a.post(origin+'/api/automation/statements/from-order',headers=headers_a,
                          json={'order_id':order_id})
            assert minted.status_code==201,minted.status_code
            statement=minted.json()
            assert statement['org_id']==org_a and statement['order_id']==order_id
            listing=a.get(origin+'/api/automation/statements')
            assert listing.status_code==200
            assert any(x['id']==statement['id'] and x['order_id']==order_id
                       for x in listing.json())
            foreign=b.get(origin+'/api/automation/statements')
            assert foreign.status_code==200
            assert all(x['org_id']!=org_a for x in foreign.json())
            assert b.get(origin+'/api/automation/statements/'+statement['id']).status_code==404

            # An unrelated company can neither enumerate thread nor read messages.
            from app.main import hash_password, now
            other_org = uuid.uuid4().hex
            other_user = uuid.uuid4().hex
            with sqlite3.connect(db_path) as db:
                db.execute('INSERT INTO organizations VALUES(?,?,?)', (other_org, 'Isolated C', now()))
                db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)', (
                    other_user, other_org, 'tenant-c@example.invalid',
                    hash_password('StrongSynthetic!2026'), 'C admin', 'admin', now()))
            other = client()
            r = other.post(origin + '/api/login', json={
                'email': 'tenant-c@example.invalid', 'password': 'StrongSynthetic!2026'})
            assert r.status_code == 200
            assert other.get(send_url).status_code == 404

            # Staff management: reauthentication, tenant check, and session revocation.
            staff_id = uuid.uuid4().hex
            with sqlite3.connect(db_path) as db:
                db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)', (
                    staff_id, org_a, 'staff-e2e@example.invalid',
                    hash_password('StrongSynthetic!2026'), 'QA employee', 'member', now()))
            staff = client()
            sr = staff.post(origin + '/api/login', json={
                'email': 'staff-e2e@example.invalid', 'password': 'StrongSynthetic!2026'})
            assert sr.status_code == 200
            staff_url = origin + f'/api/security/users/{staff_id}/disable'
            assert a.post(staff_url, json={'admin_password': 'Demo!2026secure'}).status_code == 403
            assert b.post(staff_url, headers=headers_b,
                          json={'admin_password': 'Demo!2026secure'}).status_code == 404
            disabled = a.post(staff_url, headers=headers_a,
                              json={'admin_password': 'Demo!2026secure'})
            assert disabled.status_code == 200, disabled.status_code
            assert disabled.json().get('sessions_revoked') is True
            assert staff.get(origin + '/api/me').status_code == 401
            enabled = a.post(origin + f'/api/security/users/{staff_id}/enable',
                             headers=headers_a, json={'admin_password': 'Demo!2026secure'})
            assert enabled.status_code == 200, enabled.status_code
            assert staff.post(origin + '/api/login', json={
                'email': 'staff-e2e@example.invalid',
                'password': 'StrongSynthetic!2026'}).status_code == 200

            # Admin session revocation is scoped to company, never global.
            a_other = client()
            login(a_other, 'demo@hanbit.example')
            overview = a.get(origin + '/api/security/overview')
            assert overview.status_code == 200
            extra = [s for s in overview.json()['sessions'] if not s['is_current']]
            assert extra
            sid = extra[-1]['id']
            rev = a.post(origin + f'/api/security/sessions/{sid}/revoke', headers=headers_a)
            assert rev.status_code == 200, rev.status_code
            assert b.post(origin + f'/api/security/sessions/{sid}/revoke', headers=headers_b).status_code == 404
        finally:
            for c in clients:
                c.close()
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
