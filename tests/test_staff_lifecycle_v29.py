"""Offboarding, identity isolation and restoration without resurrecting sessions."""
import app.main as core
from tests.test_security_center import headers_for

PW='Demo!2026secure'

def add_member(org,role='member',name='employee'):
    with core.transaction() as db:
        db.execute('INSERT INTO users VALUES (?,?,?,?,?,?,?)',
            (name,org,name+'@test.example',core.hash_password('StrongStaff-2026!'),name,role,core.now()))

def test_disable_revokes_active_access_preserves_chat_and_reenable_requires_login(client):
    admin=headers_for(client,'demo@hanbit.example',PW)
    with core.conn() as db:
        org=db.execute("SELECT org_id FROM users WHERE email='demo@hanbit.example'").fetchone()[0]
    add_member(org)
    employee=headers_for(client,'employee@test.example','StrongStaff-2026!')
    assert client.get('/api/me',headers=employee).status_code==200
    wrong=client.post('/api/security/users/employee/disable',json={'admin_password':'wrong'},headers=admin)
    assert wrong.status_code==403
    assert client.get('/api/me',headers=employee).status_code==200
    disabled=client.post('/api/security/users/employee/disable',json={'admin_password':PW},headers=admin)
    assert disabled.status_code==200
    assert client.get('/api/me',headers=employee).status_code==401
    assert client.post('/api/login',json={'email':'employee@test.example','password':'StrongStaff-2026!'}).status_code==401
    assert client.post('/api/security/users/employee/disable',json={'admin_password':PW},headers=admin).status_code==409
    assert client.post('/api/security/users/employee/enable',json={'admin_password':'wrong'},headers=admin).status_code==403
    assert client.post('/api/security/users/employee/enable',json={'admin_password':PW},headers=admin).status_code==200
    assert client.get('/api/me',headers=employee).status_code==401
    assert client.post('/api/login',json={'email':'employee@test.example','password':'StrongStaff-2026!'}).status_code==200
    with core.conn() as db:
        assert [r[0] for r in db.execute("SELECT event_type FROM security_events WHERE event_type LIKE 'staff_%'")] == ['staff_disabled','staff_enabled']

def test_no_cross_org_disable_or_reenable_and_csrf(client):
    a=headers_for(client,'demo@hanbit.example',PW)
    b=headers_for(client,'demo@bada.example',PW)
    with core.conn() as db:
        org=db.execute("SELECT org_id FROM users WHERE email='demo@bada.example'").fetchone()[0]
    add_member(org,name='staffb')
    assert client.post('/api/security/users/staffb/disable',json={'admin_password':PW},headers=a).status_code==404
    assert client.post('/api/security/users/staffb/disable',json={'admin_password':PW},headers={'Cookie':b['Cookie']}).status_code==403
    assert client.post('/api/security/users/staffb/disable',json={'admin_password':PW},headers=b).status_code==200
    assert client.post('/api/security/users/staffb/enable',json={'admin_password':PW},headers=a).status_code==404

def test_current_admin_cannot_self_disable(client):
    admin=headers_for(client,'demo@hanbit.example',PW)
    uid=client.get('/api/me',headers=admin).json()['id']
    assert client.post(f'/api/security/users/{uid}/disable',json={'admin_password':PW},headers=admin).status_code==409
    assert client.get('/api/me',headers=admin).status_code==200

def test_last_other_active_admin_is_not_disabled(client):
    admin=headers_for(client,'demo@hanbit.example',PW)
    with core.conn() as db:
        org=db.execute("SELECT org_id FROM users WHERE email='demo@hanbit.example'").fetchone()[0]
    add_member(org,role='admin',name='admin2')
    assert client.post('/api/security/users/admin2/disable',json={'admin_password':PW},headers=admin).status_code==200
    assert client.post('/api/security/users/admin2/enable',json={'admin_password':PW},headers=admin).status_code==200

def test_worker_cannot_disable_colleague(client):
    admin=headers_for(client,'demo@hanbit.example',PW)
    with core.conn() as db:
        org=db.execute("SELECT org_id FROM users WHERE email='demo@hanbit.example'").fetchone()[0]
    add_member(org,name='worker1');add_member(org,name='worker2')
    worker=headers_for(client,'worker1@test.example','StrongStaff-2026!')
    assert client.post('/api/security/users/worker2/disable',json={'admin_password':'StrongStaff-2026!'},headers=worker).status_code==403
    assert client.post('/api/security/users/worker2/disable',json={'admin_password':PW},headers=admin).status_code==200

def test_migration_idempotent_preserves_sessions(client):
    user=headers_for(client,'demo@hanbit.example',PW)
    core.init_db();core.init_db()
    assert client.get('/api/me',headers=user).status_code==200
    with core.conn() as db:
        assert 'staff_disabled' in {r['name'] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'

def test_disabled_staff_not_returned_as_logged_in_from_secondary_sessions(client):
    admin=headers_for(client,'demo@hanbit.example',PW)
    with core.conn() as db:
        org=db.execute("SELECT org_id FROM users WHERE email='demo@hanbit.example'").fetchone()[0]
    add_member(org,name='staffx')
    h1=headers_for(client,'staffx@test.example','StrongStaff-2026!')
    h2=headers_for(client,'staffx@test.example','StrongStaff-2026!')
    assert client.post('/api/security/users/staffx/disable',json={'admin_password':PW},headers=admin).status_code==200
    assert client.get('/api/me',headers=h1).status_code==401
    assert client.get('/api/me',headers=h2).status_code==401
    with core.conn() as db:
        assert db.execute("SELECT count(*) FROM sessions WHERE user_id='staffx'").fetchone()[0]==0

def test_no_credential_disclosure_in_staff_security_audit(client):
    admin=headers_for(client,'demo@hanbit.example',PW)
    with core.conn() as db:
        org=db.execute("SELECT org_id FROM users WHERE email='demo@hanbit.example'").fetchone()[0]
    add_member(org,name='staffz')
    assert client.post('/api/security/users/staffz/disable',json={'admin_password':PW},headers=admin).status_code==200
    data=client.get('/api/security/overview',headers=admin).json()
    assert PW not in str(data)
    assert 'password_hash' not in str(data)
    assert next(x for x in data['users'] if x['id']=='staffz')['disabled_at']
