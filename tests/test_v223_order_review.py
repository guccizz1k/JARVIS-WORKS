"""Isolated owner-review order edit / acknowledgement adversarial regression."""
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
    monkeypatch.setattr(main,'DB_PATH',tmp_path/'order-review.db')
    with TestClient(owner_app,base_url='https://testserver') as c:
        yield c


def auth(c,email='demo@hanbit.example',password='Demo!2026secure'):
    response=c.post('/api/login',json={'email':email,'password':password})
    assert response.status_code==200,response.text
    token=response.cookies.get(main.SESSION_COOKIE)
    assert token
    return {'Cookie':main.SESSION_COOKIE+'='+token,
            'X-CSRF-Token':response.json()['csrf_token']}


def create_order(c,h):
    customers=c.get('/api/customers',headers=h).json()
    assert customers
    q=c.post('/api/quotes',headers=h,json={
        'customer_id':customers[0]['id'],
        'title':'Order Review Synthetic',
        'vat_mode':'taxable',
        'items':[{'name':'Motor cable','quantity':2,'unit_price':1000}]
    })
    assert q.status_code==201,q.text
    quote=q.json()
    for state in ('sent','accepted'):
        response=c.post('/api/quotes/'+quote['id']+'/status',
            headers=h,json={'status':state})
        assert response.status_code==200,response.text
    o=c.post('/api/orders/from-quote',headers=h,json={
        'quote_id':quote['id'],'due_date':'2099-12-30'})
    assert o.status_code==201,o.text
    return o.json(),quote


def get_context(c,h,oid):
    return c.get('/api/review/orders/'+oid+'/edit-context',headers=h)


def payload(context,qty=3,reason='검토 중 고객이 수량 변경 요청'):
    original=context['order']
    return {
        'fingerprint':context['fingerprint'],
        'updated':{'due_date':original['due_date'],'change_reason':reason,
            'items':[{'source_quote_item_id':x['source_quote_item_id'],
                      'name':x['name'],'quantity':qty,'unit_price':x['unit_price']}
                     for x in original['items']]}
    }


def change(c,h,oid,body):
    return c.post('/api/review/orders/'+oid+'/update',headers=h,json=body)


def approve(c,h,oid,fingerprint,confirm=True):
    return c.post('/api/review/orders/'+oid+'/acknowledge',headers=h,
          json={'fingerprint':fingerprint,'confirm':confirm})


def test_change_requires_review_and_blocks_fulfillment_until_ack(env):
    h=auth(env);order,quote=create_order(env,h)
    c=get_context(env,h,order['id'])
    assert c.status_code==200,c.text
    original=c.json()
    assert original['order']['review_state']=='clean'
    assert original['order']['items'][0]['source_quote_item_id']==quote['items'][0]['id']
    saved=change(env,h,order['id'],payload(original,qty=3))
    assert saved.status_code==200,saved.text
    result=saved.json()
    assert result['changed'] is True
    assert result['order']['review_state']=='pending'
    assert result['order']['money']['total']==3300
    assert result['order']['differences']
    assert result['fingerprint']!=original['fingerprint']
    processing=env.post('/api/orders/'+order['id']+'/status',headers=h,
                        json={'status':'processing'})
    assert processing.status_code==200,processing.text
    forbidden=env.post('/api/orders/'+order['id']+'/status',headers=h,
                       json={'status':'fulfilled'})
    assert forbidden.status_code==409
    before_ack=get_context(env,h,order['id']).json()
    assert before_ack['order']['status']=='processing'
    assert before_ack['order']['review_state']=='pending'
    confirmed=approve(env,h,order['id'],before_ack['fingerprint'])
    assert confirmed.status_code==200,confirmed.text
    assert confirmed.json()['order']['review_state']=='acknowledged'
    assert confirmed.json()['fingerprint']!=before_ack['fingerprint']
    fulfilled=env.post('/api/orders/'+order['id']+'/status',headers=h,
                       json={'status':'fulfilled'})
    assert fulfilled.status_code==200,fulfilled.text
    assert get_context(env,h,order['id']).status_code==409
    with main.conn() as db:
        edits=db.execute("SELECT detail FROM audit_logs WHERE entity_type='order' AND entity_id=? AND action='edit'",(order['id'],)).fetchall()
        confirms=db.execute("SELECT detail FROM audit_logs WHERE entity_type='order' AND entity_id=? AND action='acknowledge'",(order['id'],)).fetchall()
    assert len(edits)==1 and len(confirms)==1 and 'requires_review' in edits[0]['detail']


def test_pending_approval_requires_admin_and_is_stale_safe(env):
    owner=auth(env);order,_=create_order(env,owner)
    source=get_context(env,owner,order['id']).json()
    assert change(env,owner,order['id'],payload(source,qty=4)).status_code==200
    pending=get_context(env,owner,order['id']).json()
    with main.transaction() as db:
        org=db.execute("SELECT org_id FROM users WHERE email='demo@hanbit.example'").fetchone()['org_id']
        db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',(
            main.ident(),org,'review-member@example.invalid',
            main.hash_password('SyntheticUserPassword!'),'QA member','member',main.now()))
    member=auth(env,'review-member@example.invalid','SyntheticUserPassword!')
    assert approve(env,member,order['id'],pending['fingerprint']).status_code==403
    assert approve(env,owner,order['id'],source['fingerprint']).status_code==409
    assert approve(env,owner,order['id'],pending['fingerprint'],False).status_code==422
    ok=approve(env,owner,order['id'],pending['fingerprint'])
    assert ok.status_code==200,ok.text
    assert approve(env,owner,order['id'],pending['fingerprint']).status_code==409
    assert get_context(env,owner,order['id']).json()['order']['review_state']=='acknowledged'


def test_concurrent_edits_exactly_one_commits_and_stale_ack_is_rejected(env):
    owner=auth(env);order,_=create_order(env,owner)
    before=get_context(env,owner,order['id']).json()
    def write(n):
        with TestClient(owner_app,base_url='https://testserver') as c:
            return change(c,owner,order['id'],payload(before,qty=n)).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=sorted(pool.map(write,(3,5)))
    assert results==[200,409],results
    after=get_context(env,owner,order['id']).json()
    assert after['order']['review_state']=='pending'
    stale=approve(env,owner,order['id'],before['fingerprint'])
    assert stale.status_code==409
    assert approve(env,owner,order['id'],after['fingerprint']).status_code==200


def test_duplicate_quote_item_links_and_malformed_payload_rejected(env):
    owner=auth(env);order,_=create_order(env,owner)
    ctx=get_context(env,owner,order['id']).json()
    initial=payload(ctx,qty=3)
    duplicate={**initial,'updated':{**initial['updated'],'items':[
        initial['updated']['items'][0],initial['updated']['items'][0]]}}
    assert change(env,owner,order['id'],duplicate).status_code==400
    fake={**initial,'updated':{**initial['updated'],'items':[
        {**initial['updated']['items'][0],'source_quote_item_id':'a'*32}]}}
    assert change(env,owner,order['id'],fake).status_code==400
    bad={**initial,'updated':{**initial['updated'],'change_reason':'짧음'}}
    assert change(env,owner,order['id'],bad).status_code==422
    out={**initial,'updated':{**initial['updated'],'items':[
        {**initial['updated']['items'][0],'quantity':0}]}}
    assert change(env,owner,order['id'],out).status_code==422
    assert get_context(env,owner,order['id']).json()['fingerprint']==ctx['fingerprint']


def test_cross_tenant_csrf_and_origin_fail_closed(env):
    owner=auth(env);order,_=create_order(env,owner)
    foreign=auth(env,'demo@bada.example')
    ctx=get_context(env,owner,order['id']).json()
    assert get_context(env,foreign,order['id']).status_code==404
    assert change(env,foreign,order['id'],payload(ctx)).status_code==404
    assert approve(env,foreign,order['id'],ctx['fingerprint']).status_code==404
    path='/api/review/orders/'+order['id']+'/update'
    assert env.post(path,headers={'Cookie':owner['Cookie']},
                    json=payload(ctx)).status_code==403
    assert env.post(path,headers={**owner,'Origin':'https://attacker.invalid'},
                    json=payload(ctx)).status_code==403
    assert env.post(path,headers=owner,json={**payload(ctx),'owner':True}).status_code==422


def test_noop_preserves_fingerprint_and_invoice_prevents_mutation(env):
    owner=auth(env);order,_=create_order(env,owner)
    ctx=get_context(env,owner,order['id']).json()
    unchanged={**payload(ctx,qty=2)}
    resp=change(env,owner,order['id'],unchanged)
    assert resp.status_code==200,resp.text
    assert resp.json()['changed'] is False
    assert resp.json()['fingerprint']==ctx['fingerprint']
    assert resp.json()['order']['review_state']=='clean'
    # Mark fulfilled and invoice; previous CAS snapshot must never resurrect it.
    assert env.post('/api/orders/'+order['id']+'/status',headers=owner,
        json={'status':'processing'}).status_code==200
    assert env.post('/api/orders/'+order['id']+'/status',headers=owner,
        json={'status':'fulfilled'}).status_code==200
    invoice=env.post('/api/invoices/from-order',headers=owner,
        json={'order_id':order['id'],'due_date':'2099-12-31'})
    assert invoice.status_code==201,invoice.text
    assert change(env,owner,order['id'],payload(ctx,qty=3)).status_code==409


def test_base_business_app_has_no_order_review_routes(env):
    assert not any('/api/review/orders/' in getattr(x,'path','') for x in main.app.routes)
    paths={getattr(x,'path','') for x in owner_app.routes}
    assert '/api/review/orders/{order_id}/edit-context' in paths
    assert '/api/review/orders/{order_id}/update' in paths
    assert '/api/review/orders/{order_id}/acknowledge' in paths
