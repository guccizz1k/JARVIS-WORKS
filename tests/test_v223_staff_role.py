"""Independent adversarial QA: protected role changes only in isolated review."""
import pytest
from fastapi.testclient import TestClient
from app import main
from app.owner_review_app_v223 import app as owner_app


@pytest.fixture
def env(tmp_path,monkeypatch):
    monkeypatch.setenv('JW_ENV','review')
    monkeypatch.setenv('JW_ROOT_UI','owner-visual-review')
    monkeypatch.setenv('JW_APPROVED_UI_REVIEW','ISOLATED_REVIEW_ONLY')
    monkeypatch.setenv('DEMO_SEED','1')
    monkeypatch.setattr(main,'DB_PATH',tmp_path/'role-security.db')
    with TestClient(owner_app,base_url='https://testserver') as c:
        with main.transaction() as db:
            org_a=db.execute("SELECT org_id FROM users WHERE email='demo@hanbit.example'").fetchone()['org_id']
            staff=main.ident()
            db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',(
                staff,org_a,'role-security@example.invalid',
                main.hash_password('SyntheticStaffPassword!'),
                'Synthetic Staff','member',main.now()))
            foreign=db.execute("SELECT id FROM users WHERE email='demo@bada.example'").fetchone()['id']
        yield {'client':c,'staff':staff,'foreign':foreign}


def login(c,email,password='Demo!2026secure'):
    r=c.post('/api/login',json={'email':email,'password':password})
    assert r.status_code==200,r.text
    token=r.cookies.get(main.SESSION_COOKIE)
    assert token
    return {'Cookie':main.SESSION_COOKIE+'='+token,
            'X-CSRF-Token':r.json()['csrf_token']}


def role(env,actor,target,expected,new,password='Demo!2026secure'):
    return env['client'].post('/api/account/staff/'+target+'/role',
          headers=actor,json={'expected_role':expected,'target_role':new,
                              'admin_password':password})


def test_promote_demote_revokes_existing_session_and_audits(env):
    c=env['client']
    actor=login(c,'demo@hanbit.example')
    staff=login(c,'role-security@example.invalid','SyntheticStaffPassword!')
    assert c.get('/api/me',headers=staff).json()['role']=='member'
    promoted=role(env,actor,env['staff'],'member','admin')
    assert promoted.status_code==200,promoted.text
    assert promoted.json()=={'ok':True,'user_id':env['staff'],
                              'role':'admin','sessions_revoked':True}
    assert c.get('/api/me',headers=staff).status_code==401
    new=login(c,'role-security@example.invalid','SyntheticStaffPassword!')
    assert c.get('/api/me',headers=new).json()['role']=='admin'
    demoted=role(env,actor,env['staff'],'admin','member')
    assert demoted.status_code==200,demoted.text
    assert demoted.json()['sessions_revoked'] is True
    assert c.get('/api/me',headers=new).status_code==401
    with main.conn() as db:
        records=db.execute("SELECT detail FROM audit_logs WHERE action='role_changed' ORDER BY rowid").fetchall()
    assert len(records)==2
    audit_text=' '.join(r['detail'] for r in records)
    assert 'Demo!2026secure' not in audit_text
    assert 'SyntheticStaffPassword!' not in audit_text
    assert 'admin' in audit_text and 'member' in audit_text


def test_bad_credentials_target_and_self_guard(env):
    c=env['client'];actor=login(c,'demo@hanbit.example')
    assert role(env,actor,env['staff'],'member','admin','not-valid').status_code==403
    assert role(env,actor,env['foreign'],'member','admin').status_code==404
    current=c.get('/api/me',headers=actor).json()['id']
    assert role(env,actor,current,'admin','member').status_code==409
    with main.conn() as db:
        assert db.execute('SELECT role FROM users WHERE id=?',(env['staff'],)).fetchone()[0]=='member'


def test_non_admin_cannot_change_roles(env):
    c=env['client'];member=login(c,'role-security@example.invalid','SyntheticStaffPassword!')
    assert role(env,member,env['staff'],'member','admin').status_code==403
    assert role(env,member,env['foreign'],'member','admin').status_code==403


def test_csrf_origin_strict_schema_and_optimistic_role_conflicts(env):
    c=env['client'];actor=login(c,'demo@hanbit.example')
    path='/api/account/staff/'+env['staff']+'/role'
    payload={'expected_role':'member','target_role':'admin',
             'admin_password':'Demo!2026secure'}
    assert c.post(path,headers={'Cookie':actor['Cookie']},json=payload).status_code==403
    assert c.post(path,headers={**actor,'Origin':'https://other.invalid'},json=payload).status_code==403
    assert c.post(path,headers=actor,json={**payload,'target_role':'owner'}).status_code==422
    assert c.post(path,headers=actor,json={**payload,'is_superuser':True}).status_code==422
    assert role(env,actor,env['staff'],'admin','member').status_code==409
    noop=role(env,actor,env['staff'],'member','member')
    assert noop.status_code==200 and noop.json()['sessions_revoked'] is False


def test_isolated_review_only_role_route_not_in_original_app(env):
    target='/api/account/staff/{target_id}/role'
    assert not any(getattr(r,'path',None)==target for r in main.app.routes)
    assert any(getattr(r,'path',None)==target for r in owner_app.routes)
