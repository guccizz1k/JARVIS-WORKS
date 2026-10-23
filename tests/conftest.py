import pytest
from fastapi.testclient import TestClient
import app.main as backend


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('DEMO_SEED','1')
    monkeypatch.delenv('BOOTSTRAP_EMAIL', raising=False)
    monkeypatch.setattr(backend,'DB_PATH',tmp_path/'test.db')
    with TestClient(backend.app, base_url='https://testserver') as c:
        yield c


@pytest.fixture
def api(client):
    class Wrapper:
        def __init__(self, c): self.c = c
        def login(self, email='demo@hanbit.example',password='Demo!2026secure'):
            res=self.c.post('/api/login',json={'email':email,'password':password})
            if res.status_code==200:
                cookie=res.cookies.get(backend.SESSION_COOKIE)
                self.auth={'Cookie':backend.SESSION_COOKIE+'='+cookie,'X-CSRF-Token':res.json()['csrf_token']}
            return res
        def req(self, method, path, json=None):
            return self.c.request(method, '/api'+path, json=json,headers=self.auth)
        def get(self,path):return self.req('GET',path)
        def post(self,path,json):return self.req('POST',path,json)
        def put(self,path,json):return self.req('PUT',path,json)
    w=Wrapper(client);assert w.login().status_code==200
    return w


@pytest.fixture
def quote_payload(api):
    customer=api.get('/customers').json()[0]
    return {'customer_id':customer['id'],'title':'정밀 견적','vat_mode':'taxable',
            'items':[{'name':'부품 A','quantity':3,'unit_price':101},
                     {'name':'부품 B','quantity':2,'unit_price':503}]}


def create_order(api,quote_payload, due='2099-12-30'):
    q=api.post('/quotes',quote_payload);assert q.status_code==201,q.text
    q=q.json()
    assert api.post(f"/quotes/{q['id']}/status",{'status':'sent'}).status_code==200
    assert api.post(f"/quotes/{q['id']}/status",{'status':'accepted'}).status_code==200
    o=api.post('/orders/from-quote',{'quote_id':q['id'],'due_date':due})
    assert o.status_code==201,o.text
    return q,o.json()


def create_invoice(api,quote_payload):
    q,o=create_order(api,quote_payload)
    assert api.post(f"/orders/{o['id']}/status",{'status':'processing'}).status_code==200
    assert api.post(f"/orders/{o['id']}/status",{'status':'fulfilled'}).status_code==200
    i=api.post('/invoices/from-order',{'order_id':o['id'],'due_date':'2099-12-31'})
    assert i.status_code==201,i.text
    return q,o,i.json()
