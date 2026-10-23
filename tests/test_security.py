"""Focused web session, cross-site request and privacy regression checks."""
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest


def test_https_host_cookie_and_no_browser_bearer(client):
    r = client.post('/api/login', json={'email':'demo@hanbit.example','password':'Demo!2026secure'})
    assert r.status_code == 200
    assert 'token' not in r.json()
    assert 'csrf_token' in r.json()
    assert 'HttpOnly' in r.headers['set-cookie']
    assert 'Secure' in r.headers['set-cookie']
    assert 'SameSite=strict' in r.headers['set-cookie']
    assert '__Host-jw_session=' in r.headers['set-cookie']
    assert client.get('/api/me').json()['csrf_token'] == r.json()['csrf_token']
    assert 'sessionStorage' not in client.get('/static/app.js').text
    assert 'localStorage' not in client.get('/static/app.js').text


def test_csrf_rejected_on_business_mutation(api,client):
    data = {'name':'보안 검증 거래처'}
    raw = {'Cookie': api.auth['Cookie']}
    r = client.post('/api/customers',json=data,headers=raw)
    assert r.status_code == 403
    r = client.post('/api/customers',json=data,headers={**raw,'X-CSRF-Token':'forged'})
    assert r.status_code == 403
    ok = api.post('/customers',data)
    assert ok.status_code == 201
    assert sum(x['name']=='보안 검증 거래처' for x in api.get('/customers').json()) == 1


def test_cross_site_and_unknown_session_blocked(api,client):
    assert client.post('/api/customers',json={'name':'차단됨'},headers={**api.auth,'Origin':'https://attacker.test'}).status_code == 403
    assert client.post('/api/customers',json={'name':'차단됨'},headers={**api.auth,'Sec-Fetch-Site':'cross-site'}).status_code == 403
    assert client.get('/api/customers',headers={'Authorization':'Bearer arbitrary','Cookie':'unknown=1'}).status_code == 401
    assert client.get('/api/customers',headers={'Cookie':'__Host-jw_session=forged-not-a-valid-cookie'}).status_code == 401
    assert not any(x['name']=='차단됨' for x in api.get('/customers').json())


def test_logout_revokes_old_cookie_and_csrf(client,api):
    headers = api.auth.copy()
    assert api.post('/logout',{}).status_code == 200
    assert client.get('/api/me',headers=headers).status_code == 401
    assert client.post('/api/customers',json={'name':'재사용'},headers=headers).status_code == 401


def test_session_expiry_authoritatively_enforced(api,client):
    import app.main as backend
    with backend.transaction() as c:
        c.execute('UPDATE sessions SET expires_at=?',((datetime.now(ZoneInfo('Asia/Seoul'))-timedelta(seconds=10)).isoformat(),))
    assert client.get('/api/me',headers=api.auth).status_code == 401


def test_privacy_sensitive_fields_omitted_from_new_audit(api):
    r=api.post('/customers',{'name':'민감정보 통제','contact_name':'김비밀','email':'secret@private.example','phone':'010-9876-1234'})
    assert r.status_code==201
    cid=r.json()['id']
    assert api.put('/customers/'+cid,{'name':'민감정보 통제 수정','contact_name':'이비밀','email':'secret2@private.example','phone':'010-2222-3333'}).status_code==200
    logs=api.get('/audit').json()
    rows=[x['detail'] for x in logs if x['entity_type']=='customer' and x['entity_id']==cid]
    assert len(rows)==2
    for row in rows:
        for sensitive in ['김비밀','이비밀','secret@private.example','secret2@private.example','010-9876-1234','010-2222-3333']:
            assert sensitive not in row
    assert 'changed_fields' in rows[0]


def test_security_headers_and_demo_production_guard(client,monkeypatch,tmp_path):
    import app.main as backend
    r=client.get('/')
    assert r.headers['x-frame-options']=='DENY'
    assert "script-src 'self'" in r.headers['content-security-policy']
    assert 'strict-transport-security' in r.headers
    assert r.headers['x-content-type-options']=='nosniff'
    monkeypatch.setenv('JW_ENV','production')
    monkeypatch.setattr(backend,'DB_PATH',tmp_path/'no-demo.db')
    with pytest.raises(RuntimeError,match='DEMO_SEED'):
        backend.init_db()


def test_legacy_bearer_sessions_invalidated_without_erasing_business_data(tmp_path,monkeypatch):
    import sqlite3
    import app.main as backend
    path=tmp_path/'old-version.db'
    old_schema=backend.SCHEMA.replace(
        "  expires_at TEXT NOT NULL, csrf_token TEXT NOT NULL DEFAULT '',\n  id TEXT UNIQUE, created_at TEXT NOT NULL DEFAULT ''",
        "  expires_at TEXT NOT NULL"
    )
    with sqlite3.connect(path) as c:
        c.executescript(old_schema)
        c.execute('INSERT INTO organizations VALUES(?,?,?)',('org','기존 회사',backend.now()))
        c.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                  ('user','org','member@old.local','test','담당자','admin',backend.now()))
        c.execute('INSERT INTO sessions VALUES(?,?,?)',('old-secret-hash','user','2099-12-31T00:00:00+09:00'))
        c.execute('INSERT INTO customers VALUES(?,?,?,?,?,?,?,?)',
                  ('customer','org','보존할 거래처','','','','',backend.now()))
    monkeypatch.setattr(backend,'DB_PATH',path)
    monkeypatch.delenv('DEMO_SEED',raising=False)
    backend.init_db()
    with backend.conn() as c:
        assert c.execute('SELECT count(*) FROM sessions').fetchone()[0] == 0
        assert c.execute('SELECT name FROM customers WHERE id=?',('customer',)).fetchone()[0]=='보존할 거래처'
        assert 'csrf_token' in {x['name'] for x in c.execute('PRAGMA table_info(sessions)')}
