"""V8.9 auth/RLS stage + V9 message RPC integration: fail-closed tests.

Uses a model DB driver. These tests are NOT real PostgreSQL RLS E2E.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import pg_v90_integrated_entry as mod


TOKEN = 'test-session-token-' + 's' * 40
SESSION = 'secure-csrf-token'


class FakeCursor:
    def __init__(self, db):
        self.db = db
        self.description = None
        self.row = None
        self.rows = []

    def __enter__(self): return self
    def __exit__(self, *args): return False

    def execute(self, sql, params=None):
        self.db.sqls.append((sql, params))
        self.description = None
        self.row = None
        self.rows = []
        if 'FROM pg_catalog.pg_roles' in sql:
            self.row = self.db.login
        elif 'pg_has_role(session_user' in sql:
            self.row = (self.db.data_auth_member if "'MEMBER'" in sql else self.db.data_can_set_auth,)
        elif 'SELECT current_user, actor_id, org_id' in sql:
            self.row = None if self.db.session_revoked else self.db.identity
        elif 'jw_dev.search_messenger_companies_v90' in sql:
            self.description = [D(x) for x in ('org_id', 'company_name')]
            self.rows = [('B', 'Other Co')]
        elif 'jw_dev.v90_send_text' in sql:
            self.description = [D(x) for x in ('message_id', 'message_cursor', 'replayed')]
            self.rows = [('msg1', 1, False)]
        elif 'jw_dev.v90_sync_messages' in sql or 'jw_dev.v90_sync_edits' in sql:
            self.description = [D(x) for x in ('message_id',)]
            self.rows = []
        elif 'jw_dev.v90_start_chat' in sql:
            self.description = [D('connection_id')]
            self.rows = [('c1',)]
        elif 'jw_dev.v90_mark_read' in sql:
            self.description = [D('cursor')]
            self.rows = [(1,)]

    def fetchone(self):return self.row
    def fetchall(self):return self.rows


class D:
    def __init__(self, name):self.name=name


class FakeDB:
    def __init__(self, *, login=None, identity=None, revoked=False):
        self.login=login if login is not None else ('jw_stage_login', False, False, False, False)
        self.identity=identity if identity is not None else ('jw_app_dev', 'actorA','A','member',SESSION,'A Co')
        self.session_revoked=revoked
        self.data_can_set_auth=False
        self.data_auth_member=False
        self.sqls=[]
        self.transactions=0
        self.closed=0
    def __enter__(self):return self
    def __exit__(self,*args):self.closed+=1;return False
    @contextmanager
    def transaction(self):
        self.transactions+=1
        yield self
    def cursor(self):return FakeCursor(self)


@pytest.fixture
def f(monkeypatch):
    monkeypatch.setenv('JW_PG_STAGE_V84','ISOLATED_DEV_READ_ONLY')
    monkeypatch.setenv('JW_PG_AUTH_V85','ISOLATED_DEV_AUTH_ONLY')
    monkeypatch.setenv('JW_PG_MESSENGER_V90','ISOLATED_DEV_MESSENGER_ONLY')
    monkeypatch.setenv('JW_V90_ALLOWED_ORIGINS','https://testserver')
    monkeypatch.setenv('JW_ENV','development')
    monkeypatch.delenv('JW_INSECURE_LOCAL_DEV',raising=False)
    db=FakeDB()
    monkeypatch.setattr(mod.stage,'_connect', lambda:db)
    app=FastAPI()
    assert mod.register_v90_messenger(app)
    client=TestClient(app,base_url='https://testserver')
    client.cookies.set('__Host-jw_session',TOKEN)
    return client,db,monkeypatch


def test_stage_off_by_default(monkeypatch):
    monkeypatch.delenv('JW_PG_MESSENGER_V90',raising=False)
    assert not mod.register_v90_messenger(FastAPI())


def test_prod_is_never_enabled(f):
    _,_,monkeypatch=f
    monkeypatch.setenv('JW_ENV','production')
    assert not mod.v90_enabled()
    assert not mod.register_v90_messenger(FastAPI())


def test_missing_auth_or_read_gate_refused(f):
    _,_,monkeypatch=f
    monkeypatch.delenv('JW_PG_AUTH_V85')
    assert not mod.v90_enabled()
    monkeypatch.setenv('JW_PG_AUTH_V85','ISOLATED_DEV_AUTH_ONLY')
    monkeypatch.delenv('JW_PG_STAGE_V84')
    assert not mod.v90_enabled()


def test_non_https_origins_fail_closed(f):
    _,_,monkeypatch=f
    for bad in ['', 'http://testserver','https://testserver/','*','https://testserver/path']:
        monkeypatch.setenv('JW_V90_ALLOWED_ORIGINS',bad)
        with pytest.raises(RuntimeError):mod.register_v90_messenger(FastAPI())


def test_missing_cookie_denied_before_db(f):
    client,db,_=f
    client.cookies.clear()
    r=client.get('/api/pg-stage/v90/companies')
    assert r.status_code==401
    assert db.transactions==0


def test_valid_session_directory_requires_role_and_session_hash(f):
    client,db,_=f
    r=client.get('/api/pg-stage/v90/companies')
    assert r.status_code==200,r.text
    assert r.json()==[{'org_id':'B','company_name':'Other Co'}]
    statements=[s for s,_ in db.sqls]
    assert statements.index('SET LOCAL ROLE jw_app_dev')<next(i for i,s in enumerate(statements) if 'stage_identity_v84' in s)
    assert statements.index('SET LOCAL ROLE jw_app_dev')<next(i for i,s in enumerate(statements) if 'search_messenger_companies_v90' in s)
    assert TOKEN not in repr(db.sqls)
    # One authorization transaction AND a second gateway transaction. Both recheck role and session.
    assert sum('stage_identity_v84' in s for s in statements)==2


def test_invalid_or_expired_session_denied(f):
    client,db,_=f
    db.session_revoked=True
    assert client.get('/api/pg-stage/v90/companies').status_code==401
    assert not any('search_messenger_companies_v90' in s for s,p in db.sqls)


def test_privileged_login_refused(f):
    client,db,_=f
    db.login=('postgres',False,False,False,False)
    r=client.get('/api/pg-stage/v90/companies')
    assert r.status_code==503
    assert not any('SET LOCAL ROLE' in s for s,p in db.sqls)


def test_bypassrls_role_refused(f):
    client,db,_=f
    db.login=('stage_login',False,True,False,False)
    assert client.get('/api/pg-stage/v90/companies').status_code==503


def test_csrf_mutations_denied_before_db_rpc(f):
    client,db,_=f
    r=client.post('/api/pg-stage/v90/chats',json={'other_org_id':'B'})
    assert r.status_code==403
    assert not any('v90_start_chat' in s for s,p in db.sqls)
    r=client.post('/api/pg-stage/v90/chats',headers={'X-CSRF-Token':'wrong'},json={'other_org_id':'B'})
    assert r.status_code==403


def test_csrf_correct_and_business_role_each_rpc(f):
    client,db,_=f
    r=client.post('/api/pg-stage/v90/chats',headers={'X-CSRF-Token':SESSION},json={'other_org_id':'B'})
    assert r.status_code==200,r.text
    assert r.json()['connection_id']=='c1'
    assert sum('stage_identity_v84' in s for s,p in db.sqls)==2
    assert sum('SET LOCAL ROLE jw_app_dev' in s for s,p in db.sqls)==2


def test_revocation_between_authorize_and_gateway_must_deny(f,monkeypatch):
    client,db,_=f
    original=mod._pg_validated_cursor
    count={'n':0}
    @contextmanager
    def expire_after_first(identity):
        count['n']+=1
        if count['n']==2:db.session_revoked=True
        with original(identity) as ctx:
            yield ctx
    monkeypatch.setattr(mod,'_pg_validated_cursor',expire_after_first)
    assert client.get('/api/pg-stage/v90/companies').status_code==401


def test_ws_wrong_origin_no_gateway_io(f):
    client,db,_=f
    with pytest.raises(Exception):
        with client.websocket_connect('/api/pg-stage/v90/chats/c1/stream',headers={'Origin':'https://untrusted.example'}):
            pass
    assert db.transactions==0


def test_ws_session_verified_before_upgrade(f):
    client,db,_=f
    with client.websocket_connect('/api/pg-stage/v90/chats/c1/stream',headers={'Origin':'https://testserver'}) as ws:
        reply=ws.receive_json()
        assert reply['type']=='ready'
    assert sum('stage_identity_v84' in s for s,p in db.sqls)>=3


def test_pg_identity_endpoint_uses_new_pg_session_not_legacy_sqlite(f):
    client, db, _ = f
    r = client.get('/api/pg-stage/v90/me')
    assert r.status_code == 200, r.text
    assert r.json() == {'org_id': 'A', 'csrf_token': SESSION}
    assert r.headers['cache-control'] == 'no-store'
    assert any('SET LOCAL ROLE jw_app_dev' in sql for sql, _ in db.sqls)


def test_pg_identity_endpoint_revocation_and_missing_cookie(f):
    client, db, _ = f
    db.session_revoked = True
    assert client.get('/api/pg-stage/v90/me').status_code == 401
    db.session_revoked = False
    client.cookies.clear()
    assert client.get('/api/pg-stage/v90/me').status_code == 401


def test_business_login_must_not_adopt_authentication_role(f):
    client, db, _ = f
    db.data_can_set_auth = True
    db.data_auth_member = True
    resp = client.get('/api/pg-stage/v90/companies')
    assert resp.status_code == 503
    assert not any('SET LOCAL ROLE jw_app_dev' in sql for sql, _ in db.sqls)


def test_business_role_preflight_is_before_any_session_hash(f):
    client, db, _ = f
    resp = client.get('/api/pg-stage/v90/companies')
    assert resp.status_code == 200
    statements = [sql for sql, _ in db.sqls]
    i = next(i for i, s in enumerate(statements) if 'pg_has_role(session_user' in s)
    j = next(i for i, s in enumerate(statements) if 'SET LOCAL ROLE jw_app_dev' in s)
    assert i < j


def test_business_login_inherits_auth_role_without_set_privilege(f):
    client, db, _ = f
    db.data_can_set_auth = False  # SET ROLE forbidden
    db.data_auth_member = True   # but role permissions can be inherited
    response = client.get('/api/pg-stage/v90/companies')
    assert response.status_code == 503
    assert not any('SET LOCAL ROLE jw_app_dev' in q for q, _ in db.sqls)
