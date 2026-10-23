"""V8.5 auth service boundary tests; SQL runs separately against Supabase."""
import hashlib
import os
import secrets
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import pg_auth_v85 as auth


class SqlFailure(Exception):
    sqlstate = '23514'


class FakeCursor:
    def __init__(self, candidate=None, login=('jw_auth_login', False,False,False,False), role=('jw_auth_stage_v85',), trading_membership=False):
        self.connection = None
        self.calls=[]
        self.login=login
        self.role=role
        self.trading_membership=trading_membership
        self.candidate=candidate or ('user01','org01',make_hash('testpass'),'',-1,False,0,None)
        self.result=None
        self.fail_issue=False
        self.revoked=True
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def execute(self,sql,params=None):
        self.calls.append((sql,params))
        if 'SELECT session_user' in sql: self.result=self.login
        elif 'pg_has_role' in sql: self.result=(self.trading_membership,)
        elif sql.strip()=='SELECT current_user': self.result=self.role
        elif 'v85_auth_candidate' in sql: self.result=self.candidate
        elif 'v85_auth_issue_session' in sql:
            if self.fail_issue: raise SqlFailure('Invalid recovery proof')
            self.result=('new-session',)
        elif 'v85_auth_check_csrf' in sql: self.result=(self.revoked,)
        elif 'v85_auth_revoke_session' in sql: self.result=(self.revoked,)
        else: self.result=(None,)
    def fetchone(self): return self.result


class FakeDb:
    def __init__(self,**kwargs):
        self.cur=FakeCursor(**kwargs)
        self.cur.connection=self
        self.tx=0
        self.rolled_back=0
    def __enter__(self): return self
    def __exit__(self,*args): return False
    @contextmanager
    def transaction(self):
        self.tx+=1
        try: yield self
        except Exception:
            self.rolled_back+=1
            raise
    def cursor(self):return self.cur


def make_hash(password='testpass'):
    salt=bytes.fromhex('0123456789abcdef0123456789abcdef')
    digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,260_000)
    return f'pbkdf2_sha256$260000${salt.hex()}${digest.hex()}'


@pytest.fixture
def prepared(monkeypatch):
    monkeypatch.setenv('JW_PG_AUTH_V85','ISOLATED_DEV_AUTH_ONLY')
    monkeypatch.delenv('JW_ENV',raising=False)
    monkeypatch.delenv('JW_INSECURE_LOCAL_DEV',raising=False)
    db=FakeDb()
    monkeypatch.setattr(auth,'_connect',lambda:db)
    return db


def request(password='testpass',otp=None,recovery_code=None):
    return auth.LoginPayload(email='valid@EXAMPLE.com',password=password,otp=otp,recovery_code=recovery_code)


def test_feature_default_off(monkeypatch):
    monkeypatch.delenv('JW_PG_AUTH_V85',raising=False)
    app=FastAPI()
    assert not auth.register_v85_auth(app)
    assert TestClient(app).post('/api/pg-stage/v85/login',json={'email':'a@b.com','password':'x'}).status_code==404


@pytest.mark.parametrize('danger', ['production','prod'])
def test_production_fails_closed(monkeypatch,danger):
    monkeypatch.setenv('JW_PG_AUTH_V85','ISOLATED_DEV_AUTH_ONLY')
    monkeypatch.setenv('JW_ENV',danger)
    assert not auth.register_v85_auth(FastAPI())


def test_insecure_dev_fails_closed(monkeypatch):
    monkeypatch.setenv('JW_PG_AUTH_V85','ISOLATED_DEV_AUTH_ONLY')
    monkeypatch.setenv('JW_INSECURE_LOCAL_DEV','1')
    assert not auth.register_v85_auth(FastAPI())


def test_password_legacy_compatibility():
    assert auth.verify_legacy_pbkdf2('testpass',make_hash('testpass'))
    assert not auth.verify_legacy_pbkdf2('wrong',make_hash('testpass'))
    assert not auth.verify_legacy_pbkdf2('testpass',make_hash().replace('260000','1'))
    assert not auth.verify_legacy_pbkdf2('testpass','not-a-real-hash')


def test_valid_login_issues_postgres_session_without_plaintext(prepared):
    token, csrf, exp=auth.login_session(request())
    assert len(token)>30 and len(csrf)>30
    assert prepared.tx==2  # outer transaction and issue savepoint
    logs=prepared.cur.calls
    assert any('SET LOCAL ROLE jw_auth_stage_v85' in q for q,p in logs)
    assert any('v85_auth_candidate' in q and p==('valid@example.com',) for q,p in logs)
    assert any('v85_auth_issue_session' in q and p[1]==hashlib.sha256(token.encode()).hexdigest() for q,p in logs)
    assert not any(token in str(p) for q,p in logs)
    assert not any('jw_app_dev' in q for q,p in logs if q.startswith('SET LOCAL ROLE'))


def test_wrong_password_is_persistently_counted(prepared):
    with pytest.raises(Exception) as caught:
        auth.login_session(request(password='wrong'))
    assert getattr(caught.value,'status_code',None)==401
    assert any('v85_auth_failed' in q for q,p in prepared.cur.calls)
    assert not any('v85_auth_issue_session' in q for q,p in prepared.cur.calls)


def test_unknown_user_also_runs_legacy_pbkdf2(prepared,monkeypatch):
    prepared.cur.candidate=(None,None,None,None,None,False,0,None)
    track=[]
    original=auth.verify_legacy_pbkdf2
    monkeypatch.setattr(auth,'verify_legacy_pbkdf2',lambda pw,pw_hash:track.append(pw_hash) or original(pw,pw_hash))
    with pytest.raises(Exception): auth.login_session(request())
    assert track==[auth.FAKE_HASH]


def test_lockout_does_not_issue(prepared):
    from datetime import datetime,timezone
    c=list(prepared.cur.candidate)
    c[-2]=5
    c[-1]=datetime.now(timezone.utc).isoformat()
    prepared.cur.candidate=tuple(c)
    with pytest.raises(Exception) as caught:auth.login_session(request())
    assert getattr(caught.value,'status_code',None)==429
    assert not any('v85_auth_issue_session' in q for q,p in prepared.cur.calls)


def test_disabled_user_denied(prepared):
    c=list(prepared.cur.candidate);c[5]=True;prepared.cur.candidate=tuple(c)
    with pytest.raises(Exception) as caught:auth.login_session(request())
    assert getattr(caught.value,'status_code',None)==401


def test_totp_mfa_required_and_single_step(prepared,monkeypatch):
    c=list(prepared.cur.candidate);c[3]='fernet-encrypted';c[4]=500;prepared.cur.candidate=tuple(c)
    monkeypatch.setattr(auth,'secret_for_user',lambda _: 'TESTSECRET')
    monkeypatch.setattr(auth,'match_totp',lambda secret,code,last: 502 if code=='123456' and last==500 else None)
    with pytest.raises(Exception):auth.login_session(request())
    assert not any('v85_auth_issue_session' in q for q,p in prepared.cur.calls)
    prepared.cur.calls.clear()
    auth.login_session(request(otp='123456'))
    assert any('v85_auth_issue_session' in q and p[3]==502 for q,p in prepared.cur.calls)


def test_wrong_recovery_code_counted_not_500(prepared):
    c=list(prepared.cur.candidate);c[3]='fernet-encrypted';prepared.cur.candidate=tuple(c)
    prepared.cur.fail_issue=True
    with pytest.raises(Exception) as caught:
        auth.login_session(request(recovery_code='a'*32))
    assert getattr(caught.value,'status_code',None)==401
    assert prepared.rolled_back==1  # only savepoint rolls back
    assert any('v85_auth_failed' in q for q,p in prepared.cur.calls)


def test_admin_login_rejected(prepared):
    prepared.cur.login=('postgres',False,False,False,False)
    with pytest.raises(Exception) as caught:auth.login_session(request())
    assert getattr(caught.value,'status_code',None)==503
    assert not any('v85_auth_candidate' in q for q,p in prepared.cur.calls)



def test_trading_role_membership_rejected(prepared):
    prepared.cur.trading_membership=True
    with pytest.raises(Exception) as caught:auth.login_session(request())
    assert getattr(caught.value,'status_code',None)==503
    assert not any('SET LOCAL ROLE jw_auth_stage_v85' in q for q,p in prepared.cur.calls)


def test_role_delegation_verified(prepared):
    prepared.cur.role=('jw_app_dev',)
    with pytest.raises(Exception) as caught:auth.login_session(request())
    assert getattr(caught.value,'status_code',None)==503


def test_http_cookie_csrf_contract(prepared):
    app=FastAPI(); assert auth.register_v85_auth(app)
    r=TestClient(app,base_url='https://testserver').post('/api/pg-stage/v85/login',json={'email':'valid@example.com','password':'testpass'})
    assert r.status_code==200, r.text
    assert 'Secure' in r.headers['set-cookie']
    assert 'HttpOnly' in r.headers['set-cookie']
    assert 'SameSite=strict' in r.headers['set-cookie']
    assert r.json()['backend']=='postgresql_auth_stage'
    assert 'csrf_token' in r.json()


def test_logout_requires_csrf(prepared):
    app=FastAPI();auth.register_v85_auth(app)
    c=TestClient(app,base_url='https://testserver')
    c.cookies.set(auth.COOKIE,'test-token-'+'x'*60)
    assert c.post('/api/pg-stage/v85/logout').status_code==401
    assert not any('v85_auth_revoke_session' in q for q,p in prepared.cur.calls)
    response=c.post('/api/pg-stage/v85/logout',headers={'X-CSRF-Token':'csrf-test'})
    assert response.status_code==200,response.text
    assert any('v85_auth_check_csrf' in q for q,p in prepared.cur.calls)


def test_two_dsns_must_not_be_equal(monkeypatch):
    monkeypatch.setenv('JW_PG_AUTH_V85','ISOLATED_DEV_AUTH_ONLY')
    monkeypatch.setenv('JW_PG_AUTH_STAGE_DSN','postgres://same')
    monkeypatch.setenv('JW_PG_STAGE_DSN','postgres://same')
    with pytest.raises(RuntimeError,match='separate'):
        auth._connect()


def test_no_legacy_main_mutation():
    import hashlib
    current=Path(__file__).parents[1]/'app'/'main.py'
    assert hashlib.sha256(current.read_bytes()).hexdigest()=='e4584787c8ee97a417656e62297507caa7d618f4146398342dabc23c8a6ab25f'


def test_migration_sql_role_grants_and_no_password_exposure():
    sql=(Path(__file__).parents[1]/'migrations'/'v85_auth_stage.sql').read_text()
    for fn in ('v85_auth_candidate','v85_auth_failed','v85_auth_issue_session','v85_auth_revoke_session','v85_auth_check_csrf'):
        assert f'CREATE FUNCTION jw_dev.{fn}' in sql
        assert f'GRANT EXECUTE ON FUNCTION jw_dev.{fn}' in sql
        assert f'REVOKE ALL ON FUNCTION jw_dev.{fn}' in sql
    assert 'NOLOGIN NOINHERIT NOBYPASSRLS' in sql
    assert 'CREATE POLICY' not in sql
    assert 'GRANT SELECT ON jw_dev.users' not in sql
