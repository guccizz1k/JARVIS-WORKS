"""V8.4 default-deny routing and real FastAPI request contract tests.

Fake DB simulates the API boundary; Supabase SQL scenarios run separately.
"""
from contextlib import contextmanager
import hashlib
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app import pg_api_v84 as stage

TOKEN = 'valid-test-token-' + 'x'*45


class Cursor:
    def __init__(self, *, identity=None, login=('jw_login',False,False,False,False)):
        self.calls=[]
        self.description=None
        self.identity=identity if identity is not None else ('jw_app_dev','a1','org-a','member','csrf-secret','My Org')
        self.login=login
        self.result=None
        self.result_list=[]
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def execute(self,sql,params=None):
        self.calls.append((sql,params))
        if 'SELECT session_user' in sql: self.result=self.login
        elif 'stage_identity_v84' in sql: self.result=self.identity
        elif 'SELECT id FROM jw_dev.invoices' in sql: self.result=('inv1',) if params[0]=='inv1' else None
        elif 'SELECT id,name,business_number' in sql:
            self.description=[type('D',(),{'name':x}) for x in ('id','name','business_number','contact_name','email','phone','created_at')]
            self.result_list=[('c1','A','','','','','2026')]
        else:
            self.description=[type('D',(),{'name':'id'})]
            self.result_list=[]
    def fetchone(self):return self.result
    def fetchall(self):return self.result_list


class DB:
    def __init__(self,**kwargs):self.cur=Cursor(**kwargs);self.transactions=0;self.rollback=False
    def __enter__(self):return self
    def __exit__(self,*a):return False
    @contextmanager
    def transaction(self):
        self.transactions+=1
        try:yield self
        except BaseException:
            self.rollback=True
            raise
    def cursor(self):return self.cur


def app_with_stage(monkeypatch,**dbopts):
    monkeypatch.setenv('JW_PG_STAGE_V84','ISOLATED_DEV_READ_ONLY')
    monkeypatch.delenv('JW_ENV',raising=False)
    monkeypatch.delenv('JW_INSECURE_LOCAL_DEV',raising=False)
    db=DB(**dbopts)
    monkeypatch.setattr(stage,'_connect',lambda:db)
    app=FastAPI()
    assert stage.register_stage_api(app)
    client=TestClient(app,base_url='https://testserver')
    return client,db


def cookie(client): client.cookies.set('__Host-jw_session',TOKEN)


def test_default_route_disabled(monkeypatch):
    monkeypatch.delenv('JW_PG_STAGE_V84',raising=False)
    app=FastAPI()
    assert not stage.register_stage_api(app)
    assert TestClient(app).get('/api/pg-stage/v84/me').status_code==404


def test_production_never_mounts(monkeypatch):
    monkeypatch.setenv('JW_PG_STAGE_V84','ISOLATED_DEV_READ_ONLY')
    monkeypatch.setenv('JW_ENV','production')
    app=FastAPI()
    assert not stage.register_stage_api(app)
    assert TestClient(app).get('/api/pg-stage/v84/me').status_code==404


def test_insecure_cookie_setting_rejected(monkeypatch):
    monkeypatch.setenv('JW_PG_STAGE_V84','ISOLATED_DEV_READ_ONLY')
    monkeypatch.setenv('JW_INSECURE_LOCAL_DEV','1')
    with pytest.raises(RuntimeError,match='secure cookies'):
        stage.register_stage_api(FastAPI())


def test_missing_cookie_does_not_connect(monkeypatch):
    c,db=app_with_stage(monkeypatch)
    r=c.get('/api/pg-stage/v84/me')
    assert r.status_code==401
    assert db.transactions==0


def test_valid_pg_identity_and_hash_and_read_only(monkeypatch):
    c,db=app_with_stage(monkeypatch)
    cookie(c)
    r=c.get('/api/pg-stage/v84/me')
    assert r.status_code==200, r.text
    assert r.json()=={'actor_id':'a1','org_id':'org-a','actor_role':'member','org_name':'My Org','backend':'postgresql_stage_read_only'}
    texts=[q for q,p in db.cur.calls]
    assert texts.index('SET TRANSACTION READ ONLY') < next(i for i,t in enumerate(texts) if 'SELECT session_user' in t)
    assert 'SET LOCAL ROLE jw_app_dev' in texts
    assert (hashlib.sha256(TOKEN.encode()).hexdigest(),) in [p for q,p in db.cur.calls]
    assert TOKEN not in str(db.cur.calls)


def test_no_untrusted_login(monkeypatch):
    c,db=app_with_stage(monkeypatch,login=('postgres',False,False,False,False))
    cookie(c)
    assert c.get('/api/pg-stage/v84/me').status_code==503
    assert not any('stage_identity_v84' in q for q,p in db.cur.calls)


def test_expired_identity_rejected(monkeypatch):
    c,db=app_with_stage(monkeypatch,identity=('jw_app_dev',None,None,None,None,None))
    cookie(c)
    assert c.get('/api/pg-stage/v84/me').status_code==401


def test_customers_list_bounded_parameter(monkeypatch):
    c,db=app_with_stage(monkeypatch)
    cookie(c)
    r=c.get('/api/pg-stage/v84/customers?limit=2')
    assert r.status_code==200
    assert r.json()[0]['id']=='c1'
    assert any(p==(2,) and 'jw_dev.customers' in q for q,p in db.cur.calls)
    assert c.get('/api/pg-stage/v84/customers?limit=101').status_code==422


def test_invoice_id_parameter_and_visibility(monkeypatch):
    c,db=app_with_stage(monkeypatch)
    cookie(c)
    assert c.get('/api/pg-stage/v84/invoices/no-access/payments').status_code==404
    assert c.get('/api/pg-stage/v84/invoices/inv1/payments').status_code==200
    assert any(p==('inv1',) for q,p in db.cur.calls)


def test_write_method_rejected(monkeypatch):
    c,db=app_with_stage(monkeypatch)
    cookie(c)
    assert c.post('/api/pg-stage/v84/customers',json={'name':'attack'}).status_code==405
    assert not any('INSERT ' in q or 'UPDATE ' in q for q,p in db.cur.calls)


def test_no_credentials_without_dsn(monkeypatch):
    monkeypatch.setenv('JW_PG_STAGE_V84','ISOLATED_DEV_READ_ONLY')
    monkeypatch.delenv('JW_PG_STAGE_DSN',raising=False)
    with pytest.raises(RuntimeError,match='DSN missing'):
        stage._connect()
