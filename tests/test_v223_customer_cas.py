"""Independent CAS customer editor checks against disposable review-only SQLite."""
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from app import main
from app.owner_review_app_v223 import app as owner_app

FIELDS=('name','business_number','contact_name','email','phone')

@pytest.fixture
def env(tmp_path,monkeypatch):
    monkeypatch.setenv('JW_ENV','review')
    monkeypatch.setenv('JW_ROOT_UI','owner-visual-review')
    monkeypatch.setenv('JW_APPROVED_UI_REVIEW','ISOLATED_REVIEW_ONLY')
    monkeypatch.setenv('DEMO_SEED','1')
    monkeypatch.setattr(main,'DB_PATH',tmp_path/'owner-customer.db')
    with TestClient(owner_app,base_url='https://testserver') as c:
        yield c

def login(c,email='demo@hanbit.example'):
    r=c.post('/api/login',json={'email':email,'password':'Demo!2026secure'})
    assert r.status_code==200,r.text
    token=r.cookies.get(main.SESSION_COOKIE)
    return {'Cookie':main.SESSION_COOKIE+'='+token,
            'X-CSRF-Token':r.json()['csrf_token']}

def make(c,h,name):
    r=c.post('/api/customers',headers=h,json={'name':name})
    assert r.status_code==201,r.text
    return r.json()

def payload(row,**updates):
    original={k:row[k] for k in FIELDS}
    return {'expected':original,'updated':{**original,**updates}}

def change(c,h,cid,p):
    return c.post('/api/review/customers/'+cid+'/update',headers=h,json=p)


def test_edit_customer_atomic_cas_and_server_readback(env):
    h=login(env)
    before=make(env,h,'QA 원본 고객')
    edited=change(env,h,before['id'],payload(before,name='QA 변경 고객',
                  contact_name='새 담당자',email='owner@example.invalid'))
    assert edited.status_code==200,edited.text
    result=edited.json()
    assert result['org_id']==before['org_id'] and result['id']==before['id']
    assert result['name']=='QA 변경 고객'
    assert result['contact_name']=='새 담당자'
    saved=[r for r in env.get('/api/customers',headers=h).json() if r['id']==before['id']]
    assert len(saved)==1 and saved[0]==result
    with main.conn() as db:
        r=db.execute("SELECT detail FROM audit_logs WHERE entity_id=? AND action='edit' ORDER BY rowid DESC LIMIT 1",
                     (before['id'],)).fetchone()
    assert r is not None
    assert 'owner@example.invalid' not in r['detail']
    assert 'contact_name' in r['detail']


def test_stale_write_rejected_no_lost_update_and_noop(env):
    h=login(env)
    before=make(env,h,'QA 동시 수정 원본')
    assert change(env,h,before['id'],payload(before,name='첫 번째 수정')).status_code==200
    stale=change(env,h,before['id'],payload(before,name='뒤늦은 수정'))
    assert stale.status_code==409
    current=next(r for r in env.get('/api/customers',headers=h).json() if r['id']==before['id'])
    assert current['name']=='첫 번째 수정'
    noop=change(env,h,before['id'],payload(current))
    assert noop.status_code==200 and noop.json()==current


def test_two_parallel_updates_exactly_one_commits(env):
    h=login(env)
    before=make(env,h,'QA 경합 원본')
    def send(name):
        with TestClient(owner_app,base_url='https://testserver') as c:
            return change(c,h,before['id'],payload(before,name=name)).status_code
    with ThreadPoolExecutor(max_workers=2) as ex:
        statuses=sorted(ex.map(send,['동시 A','동시 B']))
    assert statuses==[200,409],statuses


def test_cross_company_and_unknown_customer_fail_closed(env):
    alice=login(env)
    first=make(env,alice,'QA 기업 A 전용 고객')
    bob=login(env,'demo@bada.example')
    assert change(env,bob,first['id'],payload(first,name='타 기업 침해')).status_code==404
    assert change(env,alice,'f'*32,payload(first,name='없는 계정')).status_code==404
    with main.conn() as db:
        r=db.execute('SELECT name FROM customers WHERE id=?',(first['id'],)).fetchone()
    assert r['name']=='QA 기업 A 전용 고객'


def test_csrf_origin_validation_and_pydantic_strict_fields(env):
    h=login(env)
    row=make(env,h,'QA 검증 고객')
    p=payload(row,name='QA 새 고객')
    path='/api/review/customers/'+row['id']+'/update'
    assert env.post(path,headers={'Cookie':h['Cookie']},json=p).status_code==403
    assert env.post(path,headers={**h,'Origin':'https://attacker.invalid'},json=p).status_code==403
    assert change(env,h,row['id'],{**p,'extra':'malicious'}).status_code==422
    assert change(env,h,row['id'],payload(row,name='')).status_code==422
    assert change(env,h,row['id'],payload(row,email='not-an-email')).status_code==422


def test_duplicate_name_is_atomic_and_quote_snapshot_unchanged(env):
    h=login(env)
    before=make(env,h,'QA 원래 거래처')
    other=make(env,h,'QA 중복 대상')
    quotation=env.post('/api/quotes',headers=h,json={'customer_id':before['id'],
         'title':'합성 견적','vat_mode':'taxable',
         'items':[{'name':'부품','quantity':2,'unit_price':900}]})
    assert quotation.status_code==201,quotation.text
    duplicate=change(env,h,before['id'],payload(before,name=other['name']))
    assert duplicate.status_code==409
    success=change(env,h,before['id'],payload(before,name='QA 새 거래처명'))
    assert success.status_code==200,success.text
    quote=env.get('/api/quotes/'+quotation.json()['id'],headers=h)
    assert quote.status_code==200
    assert quote.json()['customer_name_snapshot']==before['name']
    assert quote.json()['customer_id']==before['id']


def test_review_only_route_not_in_protected_core(env):
    route='/api/review/customers/{customer_id}/update'
    assert all(getattr(r,'path',None)!=route for r in main.app.routes)
    assert any(getattr(r,'path',None)==route for r in owner_app.routes)
