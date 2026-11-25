"""Independent regression for self-scoped CAS profile and preferences."""
import sqlite3
from fastapi.testclient import TestClient

from app import main
from app.owner_review_app_v223 import app as owner_app
import pytest

@pytest.fixture
def client(tmp_path, monkeypatch):
    # Only the isolated owner preview gains optional settings tables.
    monkeypatch.setenv('JW_ENV','review')
    monkeypatch.setenv('JW_ROOT_UI','owner-visual-review')
    monkeypatch.setenv('JW_APPROVED_UI_REVIEW','ISOLATED_REVIEW_ONLY')
    monkeypatch.setenv('DEMO_SEED','1')
    monkeypatch.delenv('BOOTSTRAP_EMAIL',raising=False)
    monkeypatch.setattr(main,'DB_PATH',tmp_path/'owner-review.db')
    with TestClient(owner_app,base_url='https://testserver') as c:
        yield c

@pytest.fixture
def api(client):
    class Wrapper:
        def __init__(self,c):self.c=c
        def login(self,email='demo@hanbit.example',password='Demo!2026secure'):
            r=self.c.post('/api/login',json={'email':email,'password':password})
            if r.status_code==200:
                token=r.cookies.get(main.SESSION_COOKIE)
                self.auth={'Cookie':main.SESSION_COOKIE+'='+token,
                           'X-CSRF-Token':r.json()['csrf_token']}
            return r
        def req(self,method,path,json=None):
            return self.c.request(method,'/api'+path,json=json,headers=self.auth)
        def get(self,path):return self.req('GET',path)
        def post(self,path,json):return self.req('POST',path,json)
    wrapper=Wrapper(client)
    assert wrapper.login().status_code==200
    return wrapper


def test_profile_is_self_scoped_and_versioned(api):
    before = api.get('/account/profile')
    assert before.status_code == 200
    obj = before.json()
    assert obj['version'] == 0
    assert obj['org_id'] and obj['id'] and obj['email'] and obj['name']
    assert 'csrf_token' not in obj and 'password_hash' not in obj
    changed = api.post('/account/profile', {'version':0,'name':'합성 테스트 사용자'})
    assert changed.status_code == 200, changed.text
    assert changed.json()['version'] == 1
    assert changed.json()['name'] == '합성 테스트 사용자'
    assert api.get('/account/profile').json()['name'] == '합성 테스트 사용자'
    assert api.get('/me').json()['name'] == '합성 테스트 사용자'


def test_profile_conflict_and_idempotent_noop(api):
    initial = api.get('/account/profile').json()
    changed = api.post('/account/profile', {'version':0,'name':'변경된 이름'})
    assert changed.status_code == 200
    rejected = api.post('/account/profile', {'version':0,'name':'오래된 쓰기'})
    assert rejected.status_code == 409
    assert api.get('/account/profile').json()['name'] == '변경된 이름'
    noop = api.post('/account/profile', {'version':1,'name':'변경된 이름'})
    assert noop.status_code == 200 and noop.json()['version'] == 1


def test_profile_validation_fails_closed(api):
    assert api.post('/account/profile', {'version':0,'name':'\x00bad'}).status_code == 422
    assert api.post('/account/profile', {'version':0,'name':'     '}).status_code == 422
    assert api.post('/account/profile', {'version':0,'name':'x'*81}).status_code == 422
    assert api.post('/account/profile', {'version':'0','name':'safe'}).status_code == 422
    assert api.post('/account/profile', {'version':0,'name':'safe','role':'admin'}).status_code == 422


def test_preferences_defaults_and_versioned_changes(api):
    initial = api.get('/account/preferences')
    assert initial.status_code == 200
    obj = initial.json()
    assert obj['compact_view'] is False
    assert obj['messenger_auto_refresh'] is True
    assert obj['version'] == 0
    changed = api.post('/account/preferences',{
        'version':0,'compact_view':True,'messenger_auto_refresh':False})
    assert changed.status_code == 200, changed.text
    assert changed.json()['version'] == 1
    assert changed.json()['compact_view'] is True
    assert changed.json()['messenger_auto_refresh'] is False
    assert api.get('/account/preferences').json() == changed.json()
    assert api.post('/account/preferences',{
        'version':0,'compact_view':False,'messenger_auto_refresh':True}).status_code == 409
    assert api.get('/account/preferences').json()['compact_view'] is True
    assert api.post('/account/preferences',{
        'version':1,'compact_view':True,'messenger_auto_refresh':False}).json()['version'] == 1


def test_preferences_reject_untyped_and_unapproved_payloads(api):
    assert api.post('/account/preferences',{
        'version':0,'compact_view':'true','messenger_auto_refresh':True}).status_code == 422
    assert api.post('/account/preferences',{
        'version':0,'compact_view':True,'messenger_auto_refresh':True,
        'remote_server_url':'https://attacker.invalid'}).status_code == 422
    assert api.post('/account/preferences',{
        'version':0,'compact_view':True}).status_code == 422


def test_profile_and_preferences_require_cookie_and_csrf(api):
    assert api.c.get('/api/account/profile').status_code == 200  # TestClient owns same cookie
    assert api.c.post('/api/account/profile',
      json={'version':0,'name':'No CSRF'}).status_code == 403
    assert api.c.post('/api/account/preferences',
      json={'version':0,'compact_view':True,'messenger_auto_refresh':False}).status_code == 403
    with TestClient(owner_app,base_url='https://testserver') as outsider:
        assert outsider.get('/api/account/profile').status_code == 401
        assert outsider.get('/api/account/preferences').status_code == 401


def test_tenant_users_have_independent_profiles(client):
    first = client.post('/api/login',json={
        'email':'demo@hanbit.example','password':'Demo!2026secure'})
    assert first.status_code == 200
    token_a = first.cookies.get(main.SESSION_COOKIE)
    headers_a={'Cookie':main.SESSION_COOKIE+'='+token_a,
               'X-CSRF-Token':first.json()['csrf_token']}
    second = client.post('/api/login',json={
        'email':'demo@bada.example','password':'Demo!2026secure'})
    assert second.status_code == 200
    token_b = second.cookies.get(main.SESSION_COOKIE)
    headers_b={'Cookie':main.SESSION_COOKIE+'='+token_b,
               'X-CSRF-Token':second.json()['csrf_token']}
    before_b = client.get('/api/account/profile',headers=headers_b).json()
    changed = client.post('/api/account/profile',headers=headers_a,
                          json={'version':0,'name':'A Only'})
    assert changed.status_code == 200,changed.text
    assert client.get('/api/account/profile',headers=headers_b).json()==before_b
    preferences = client.post('/api/account/preferences',headers=headers_a,
        json={'version':0,'compact_view':True,'messenger_auto_refresh':False})
    assert preferences.status_code == 200
    assert client.get('/api/account/preferences',headers=headers_b).json()['compact_view'] is False
    assert client.get('/api/account/'+before_b['id'],headers=headers_a).status_code == 404


def test_profile_changes_have_bounded_audit_without_plaintext(api):
    assert api.post('/account/profile',{'version':0,'name':'비밀 아닌 표시 이름'}).status_code == 200
    with main.conn() as db:
        row=db.execute("""SELECT detail FROM audit_logs WHERE action='display_name_changed'
                            ORDER BY rowid DESC LIMIT 1""").fetchone()
    assert row is not None
    assert '비밀 아닌 표시 이름' not in row['detail']
    assert 'version' in row['detail']


def test_preferences_persist_across_client_recreation(api):
    assert api.post('/account/preferences', {
        'version':0,'compact_view':True,'messenger_auto_refresh':False
    }).status_code == 200
    with TestClient(owner_app,base_url='https://testserver') as restarted:
        r=restarted.post('/api/login',json={
            'email':'demo@hanbit.example','password':'Demo!2026secure'})
        assert r.status_code == 200
        prefs=restarted.get('/api/account/preferences')
        assert prefs.status_code == 200
        assert prefs.json()['version'] == 1
        assert prefs.json()['compact_view'] is True
    with main.conn() as db:
        cols=[x['name'] for x in db.execute('PRAGMA table_info(users)')]
    assert cols==['id','org_id','email','password_hash','name','role','created_at']
