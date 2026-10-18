"""Admin-only read-only security center with cross-tenant and session revocation tests."""
from datetime import datetime
import app.main as backend


def headers_for(client, email, password):
    res=client.post('/api/login',json={'email':email,'password':password})
    assert res.status_code==200,res.text
    return {'Cookie':backend.SESSION_COOKIE+'='+res.cookies.get(backend.SESSION_COOKIE),
            'X-CSRF-Token':res.json()['csrf_token']}


def test_admin_only_tenant_scoped_security_overview(client):
    a=headers_for(client,'demo@hanbit.example','Demo!2026secure')
    b=headers_for(client,'demo@bada.example','Demo!2026secure')
    with backend.transaction() as c:
        org=c.execute("SELECT org_id FROM users WHERE email='demo@hanbit.example'").fetchone()['org_id']
        c.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                  ('new-member',org,'member@hanbit.example',backend.hash_password('Member-2026-Secure!'),
                   '영업 담당','member',backend.now()))
    m=headers_for(client,'member@hanbit.example','Member-2026-Secure!')
    assert client.get('/api/security/overview',headers=m).status_code==403
    overview=client.get('/api/security/overview',headers=a)
    assert overview.status_code==200
    data=overview.json()
    assert {u['name'] for u in data['users']}=={'한빛테크 관리자','영업 담당'}
    assert len(data['sessions'])==2
    assert all('csrf_token' not in item and 'token_hash' not in item for item in data['sessions'])
    assert data['mfa_enabled'] is False
    assert data['db_row_level_security_enabled'] is False
    other=client.get('/api/security/overview',headers=b).json()
    assert {u['name'] for u in other['users']}=={'바다유통 관리자'}
    assert all('한빛' not in (evt.get('actor_name') or '') for evt in other['events'])
    assert client.post('/api/security/sessions/invalid/revoke',headers=m,json={}).status_code==403
    assert client.post('/api/security/sessions/invalid/revoke',headers=a,json={}).status_code==404


def test_admin_revoke_other_user_session_only(client):
    a=headers_for(client,'demo@hanbit.example','Demo!2026secure')
    with backend.transaction() as c:
        org=c.execute("SELECT org_id FROM users WHERE email='demo@hanbit.example'").fetchone()['org_id']
        c.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                  ('staff',org,'staff@hanbit.example',backend.hash_password('Staff-2026-Secure!'),
                   '견적 담당','member',backend.now()))
    staff=headers_for(client,'staff@hanbit.example','Staff-2026-Secure!')
    overview=client.get('/api/security/overview',headers=a).json()
    staff_session=next(s for s in overview['sessions'] if s['user_name']=='견적 담당')
    admin_session=next(s for s in overview['sessions'] if s['is_current'])
    assert client.post('/api/security/sessions/'+staff_session['id']+'/revoke',headers=a,json={}).status_code==200
    assert client.get('/api/me',headers=staff).status_code==401
    assert client.get('/api/me',headers=a).status_code==200
    assert client.post('/api/security/sessions/'+staff_session['id']+'/revoke',headers=a,json={}).status_code==404
    assert client.post('/api/security/sessions/'+admin_session['id']+'/revoke',headers=a,json={}).status_code==400
    assert any(x['event_type']=='session_revoked' for x in client.get('/api/security/overview',headers=a).json()['events'])


def test_security_center_csrf_and_cross_company_revoke_blocked(client):
    a=headers_for(client,'demo@hanbit.example','Demo!2026secure')
    b=headers_for(client,'demo@bada.example','Demo!2026secure')
    other=client.get('/api/security/overview',headers=b).json()['sessions'][0]['id']
    assert client.post('/api/security/sessions/'+other+'/revoke',headers=a,json={}).status_code==404
    assert client.post('/api/security/sessions/'+other+'/revoke',headers={'Cookie':a['Cookie']},json={}).status_code==403
    assert client.get('/api/me',headers=b).status_code==200


def test_failed_login_security_event_minimal_and_no_credentials(client):
    admin=headers_for(client,'demo@hanbit.example','Demo!2026secure')
    failed=client.post('/api/login',json={'email':'demo@hanbit.example','password':'do-not-log-this-secret'})
    assert failed.status_code==401
    overview=client.get('/api/security/overview',headers=admin).json()
    assert overview['failed_logins_24h']==1
    assert any(evt['event_type']=='login_failed' for evt in overview['events'])
    data=str(overview)
    assert 'do-not-log-this-secret' not in data
    assert 'password_hash' not in data


def test_v110_migration_preserves_existing_authenticated_sessions(tmp_path,monkeypatch):
    import sqlite3
    path=tmp_path/'legacy.db'
    schema=backend.SCHEMA.replace(
        "  expires_at TEXT NOT NULL, csrf_token TEXT NOT NULL DEFAULT '',\n  id TEXT UNIQUE, created_at TEXT NOT NULL DEFAULT ''",
        "  expires_at TEXT NOT NULL, csrf_token TEXT NOT NULL DEFAULT ''")
    with sqlite3.connect(path) as c:
        c.executescript(schema)
        c.execute('INSERT INTO organizations VALUES(?,?,?)',('o1','과거 고객사',backend.now()))
        c.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                  ('u1','o1','legacy@example.com',backend.hash_password('Valid-Pass-12345'),'관리자','admin',backend.now()))
        c.execute('INSERT INTO sessions VALUES(?,?,?,?)',('a'*64,'u1','2099-12-31T00:00:00+09:00','csrf-value'))
    monkeypatch.setattr(backend,'DB_PATH',path)
    monkeypatch.delenv('DEMO_SEED',raising=False)
    backend.init_db()
    with backend.conn() as c:
        row=c.execute('SELECT * FROM sessions').fetchone()
        assert row['csrf_token']=='csrf-value'
        assert row['token_hash']=='a'*64
        assert len(row['id'])==32
        assert c.execute('SELECT count(*) FROM users').fetchone()[0]==1


def test_admin_can_revoke_own_secondary_session_without_ending_current(client):
    primary=headers_for(client,'demo@hanbit.example','Demo!2026secure')
    secondary=headers_for(client,'demo@hanbit.example','Demo!2026secure')
    all_sessions=client.get('/api/security/overview',headers=primary).json()['sessions']
    other=next(s for s in all_sessions if not s['is_current'])
    assert client.post('/api/security/sessions/'+other['id']+'/revoke',headers=primary,json={}).status_code==200
    assert client.get('/api/me',headers=primary).status_code==200
    assert client.get('/api/me',headers=secondary).status_code==401
