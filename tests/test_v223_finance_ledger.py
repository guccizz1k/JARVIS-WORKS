"""Regression of authoritative invoice/payment/reversal/settlement business flow.

Uses original business engine and isolated synthetic review only; no new ledger
schema or server financial calculation is introduced.
"""
from concurrent.futures import ThreadPoolExecutor
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
    monkeypatch.setattr(main,'DB_PATH',tmp_path/'finance-ledger.db')
    with TestClient(owner_app,base_url='https://testserver') as client:
        yield client


def auth(c,email='demo@hanbit.example',password='Demo!2026secure'):
    r=c.post('/api/login',json={'email':email,'password':password})
    assert r.status_code==200,r.text
    return {'Cookie':main.SESSION_COOKIE+'='+r.cookies.get(main.SESSION_COOKIE),
            'X-CSRF-Token':r.json()['csrf_token']}


def create_invoice(c,h):
    customer=c.get('/api/customers',headers=h).json()[0]
    quote=c.post('/api/quotes',headers=h,json={
        'customer_id':customer['id'],'title':'Synthetic Reconciliation',
        'vat_mode':'taxable','items':[{'name':'Motor','quantity':3,'unit_price':1000}]})
    assert quote.status_code==201,quote.text
    qid=quote.json()['id']
    for state in ('sent','accepted'):
        r=c.post('/api/quotes/'+qid+'/status',headers=h,json={'status':state})
        assert r.status_code==200,r.text
    order=c.post('/api/orders/from-quote',headers=h,
                 json={'quote_id':qid,'due_date':'2099-12-30'})
    assert order.status_code==201,order.text
    oid=order.json()['id']
    for state in ('processing','fulfilled'):
        r=c.post('/api/orders/'+oid+'/status',headers=h,json={'status':state})
        assert r.status_code==200,r.text
    inv=c.post('/api/invoices/from-order',headers=h,
                json={'order_id':oid,'due_date':'2099-12-31'})
    assert inv.status_code==201,inv.text
    return inv.json(),oid


def pay(c,h,iid,reference,amount):
    return c.post('/api/invoices/'+iid+'/payments',headers=h,
        json={'reference':reference,'amount':amount,'paid_at':main.today(),'note':''})


def get(c,h,iid):
    return c.get('/api/invoices/'+iid,headers=h)


def test_end_to_end_invoice_to_partial_full_payment_reconciliation_and_reverse(env):
    owner=auth(env)
    invoice,oid=create_invoice(env,owner)
    iid=invoice['id']
    assert invoice['money']['total']==3300
    recon=env.get('/api/reconciliation/'+oid,headers=owner)
    assert recon.status_code==200
    data=recon.json()
    assert data['order_money']['total']==data['invoice_money']['total']==3300
    assert data['quote_to_order']==data['order_to_invoice']==[]
    assert data['has_invoice'] is True and data['safe_to_bill'] is False
    first=pay(env,owner,iid,'PAY-V223-00001',1100)
    assert first.status_code==201,first.text
    assert first.json()['paid']==1100 and first.json()['balance']==2200
    second=pay(env,owner,iid,'PAY-V223-00002',2200)
    assert second.status_code==201,second.text
    assert second.json()['paid']==3300 and second.json()['balance']==0
    assert second.json()['payment_status']=='paid'
    verified=get(env,owner,iid).json()
    assert len(verified['payments'])==2
    assert sum(p['amount'] for p in verified['payments'] if p['reversed_at'] is None)==3300
    second_payment=next(p for p in verified['payments'] if p['reference']=='PAY-V223-00002')
    reverse=env.post('/api/invoices/'+iid+'/payments/'+second_payment['id']+'/reverse',
                     headers=owner)
    assert reverse.status_code==200,reverse.text
    assert reverse.json()['paid']==1100 and reverse.json()['balance']==2200
    latest=get(env,owner,iid).json()
    assert latest['paid']==1100 and latest['balance']==2200
    assert next(p for p in latest['payments'] if p['id']==second_payment['id'])['reversed_at']
    assert env.post('/api/invoices/'+iid+'/payments/'+second_payment['id']+'/reverse',
                    headers=owner).status_code==409
    assert pay(env,owner,iid,'PAY-V223-00002',2200).status_code==409
    with main.conn() as db:
        audit=db.execute("""SELECT action,entity_type FROM audit_logs
            WHERE org_id=? AND entity_type='payment'""",(invoice['org_id'],)).fetchall()
    assert [r['action'] for r in audit].count('create')==2
    assert [r['action'] for r in audit].count('reverse')==1


def test_reference_idempotency_and_conflicting_replays(env):
    h=auth(env);invoice,_=create_invoice(env,h);iid=invoice['id']
    a=pay(env,h,iid,'PAY-REPLAY-00001',1000)
    assert a.status_code==201
    same=pay(env,h,iid,'PAY-REPLAY-00001',1000)
    assert same.status_code==201
    assert same.json()['paid']==1000
    assert len(get(env,h,iid).json()['payments'])==1
    conflict=pay(env,h,iid,'PAY-REPLAY-00001',1500)
    assert conflict.status_code==409
    assert len(get(env,h,iid).json()['payments'])==1
    overpay=pay(env,h,iid,'PAY-OVER-00001',2301)
    assert overpay.status_code==409
    assert get(env,h,iid).json()['paid']==1000


def test_two_parallel_payment_requests_same_reference_are_single_ledger_entry(env):
    h=auth(env);invoice,_=create_invoice(env,h)
    iid=invoice['id']
    def request(_):
        with TestClient(owner_app,base_url='https://testserver') as c:
            return pay(c,h,iid,'PAY-ATOMIC-00001',1100).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(request,(1,2)))
    assert results==[201,201],results
    latest=get(env,h,iid).json()
    assert latest['paid']==1100 and latest['balance']==2200
    assert len(latest['payments'])==1


def test_other_tenant_cannot_read_invoice_history_or_reverse(env):
    h=auth(env);invoice,oid=create_invoice(env,h)
    pay(env,h,invoice['id'],'PAY-PRIVATE-00001',1000)
    payment=get(env,h,invoice['id']).json()['payments'][0]
    foreign=auth(env,'demo@bada.example')
    iid=invoice['id']
    assert get(env,foreign,iid).status_code==404
    assert env.get('/api/invoices/'+iid+'/payments',headers=foreign).status_code==404
    assert env.get('/api/reconciliation/'+oid,headers=foreign).status_code==404
    assert env.post('/api/invoices/'+iid+'/payments/'+payment['id']+'/reverse',
                    headers=foreign).status_code==404
    assert pay(env,foreign,iid,'PAY-FOREIGN-0001',100).status_code==404
    assert get(env,h,iid).json()['paid']==1000


def test_member_can_record_but_only_admin_can_reverse(env):
    owner=auth(env);invoice,_=create_invoice(env,owner)
    with main.transaction() as db:
        org=invoice['org_id']
        db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',(
            main.ident(),org,'finance-member@example.invalid',
            main.hash_password('SyntheticFinancePassword!'),
            'Finance Member','member',main.now()))
    member=auth(env,'finance-member@example.invalid','SyntheticFinancePassword!')
    entry=pay(env,member,invoice['id'],'PAY-MEMBER-00001',1000)
    assert entry.status_code==201,entry.text
    pid=entry.json()['payments'][0]['id']
    denied=env.post('/api/invoices/'+invoice['id']+'/payments/'+pid+'/reverse',
                    headers=member)
    assert denied.status_code==403
    assert get(env,owner,invoice['id']).json()['paid']==1000


def test_csrf_origin_and_invalid_payment_input_do_not_change_ledger(env):
    owner=auth(env);invoice,_=create_invoice(env,owner);iid=invoice['id']
    path='/api/invoices/'+iid+'/payments'
    body={'reference':'PAY-CSRF-00001','amount':500,'paid_at':main.today(),'note':''}
    assert env.post(path,headers={'Cookie':owner['Cookie']},json=body).status_code==403
    assert env.post(path,headers={**owner,'Origin':'https://attacker.invalid'},
                    json=body).status_code==403
    assert env.post(path,headers=owner,json={**body,'reference':'short'}).status_code==422
    assert env.post(path,headers=owner,json={**body,'amount':0}).status_code==422
    assert env.post(path,headers=owner,json={**body,'amount':'500'}).status_code==422
    assert env.post(path,headers=owner,json={**body,'paid_at':'2099-01-01'}).status_code==400
    assert get(env,owner,iid).json()['paid']==0


def test_invoice_ledger_isolated_from_base_app_extensions(env):
    h=auth(env);invoice,oid=create_invoice(env,h)
    assert not any('/api/review/invoices/' in getattr(r,'path','')
                   for r in main.app.routes)
    after=env.get('/api/reconciliation/'+oid,headers=h).json()
    assert after['has_invoice'] is True
    assert after['review_state']=='clean'
    assert get(env,h,invoice['id']).json()['money']['total']==3300
