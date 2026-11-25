"""Adversarial tenant-scoped draft quotation CAS tests (review-only SQLite)."""
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
    monkeypatch.setattr(main,'DB_PATH',tmp_path/'quote-cas.db')
    with TestClient(owner_app,base_url='https://testserver') as client:
        yield client


def auth(client,email='demo@hanbit.example'):
    r=client.post('/api/login',json={'email':email,'password':'Demo!2026secure'})
    assert r.status_code==200,r.text
    token=r.cookies.get(main.SESSION_COOKIE)
    return {'Cookie':main.SESSION_COOKIE+'='+token,
            'X-CSRF-Token':r.json()['csrf_token']}


def create(env,h):
    customers=env.get('/api/customers',headers=h)
    assert customers.status_code==200 and customers.json()
    body={'customer_id':customers.json()[0]['id'],'title':'CAS Quote Original',
          'vat_mode':'taxable','items':[{'name':'Part A','quantity':3,'unit_price':1200},
                                        {'name':'Part B','quantity':1,'unit_price':100}]}
    q=env.post('/api/quotes',headers=h,json=body)
    assert q.status_code==201,q.text
    return q.json(),body


def context(client,h,id):
    return client.get('/api/review/quotes/'+id+'/edit-context',headers=h)


def update(client,h,id,sha,body):
    return client.post('/api/review/quotes/'+id+'/update',headers=h,
             json={'expected_sha256':sha,'updated':body})


def test_draft_update_recomputes_money_preserves_line_ids_and_audit(env):
    h=auth(env);quote,body=create(env,h)
    before=context(env,h,quote['id'])
    assert before.status_code==200,before.text
    fingerprint=before.json()['fingerprint']
    assert len(fingerprint)==64
    updated={**body,'title':'CAS Quote Updated',
             'items':[{'name':'New Item','quantity':4,'unit_price':700}]}
    changed=update(env,h,quote['id'],fingerprint,updated)
    assert changed.status_code==200,changed.text
    result=changed.json()
    assert result['changed'] is True
    assert result['quote']['title']=='CAS Quote Updated'
    assert result['quote']['money']['total']==3080
    assert result['fingerprint']!=fingerprint
    stored=env.get('/api/quotes/'+quote['id'],headers=h).json()
    assert stored['status']=='draft' and stored['doc_no']==quote['doc_no']
    assert stored['title']=='CAS Quote Updated'
    assert stored['money']['total']==3080
    assert len(stored['items'])==1
    with main.conn() as db:
        row=db.execute("SELECT detail FROM audit_logs WHERE action='edit' AND entity_type='quote' AND entity_id=?",
                       (quote['id'],)).fetchone()
    assert row is not None and 'review_cas' in row['detail']


def test_stale_update_rejected_and_noop_does_not_rewrite_lines(env):
    h=auth(env);quote,body=create(env,h)
    first=context(env,h,quote['id']).json()
    changed=update(env,h,quote['id'],first['fingerprint'],{**body,'title':'Winner'})
    assert changed.status_code==200
    late=update(env,h,quote['id'],first['fingerprint'],{**body,'title':'Loser'})
    assert late.status_code==409
    latest=context(env,h,quote['id']).json()
    assert latest['quote']['title']=='Winner'
    no_op=update(env,h,quote['id'],latest['fingerprint'],{**body,'title':'Winner'})
    assert no_op.status_code==200,no_op.text
    assert no_op.json()['changed'] is False
    assert no_op.json()['fingerprint']==latest['fingerprint']
    assert [x['id'] for x in no_op.json()['quote']['items']]==[
        x['id'] for x in latest['quote']['items']]


def test_two_parallel_writes_exactly_one_commits(env):
    h=auth(env);quote,body=create(env,h)
    old=context(env,h,quote['id']).json()
    def write(name):
        with TestClient(owner_app,base_url='https://testserver') as c:
            response=update(c,h,quote['id'],old['fingerprint'],{**body,'title':name})
            return response.status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes=sorted(pool.map(write,['Parallel A','Parallel B']))
    assert outcomes==[200,409],outcomes


def test_rejects_other_tenant_and_no_cross_tenant_disclosure(env):
    a=auth(env);quote,body=create(env,a)
    b=auth(env,'demo@bada.example')
    assert context(env,b,quote['id']).status_code==404
    assert update(env,b,quote['id'],'0'*64,body).status_code==404
    assert context(env,a,quote['id']).status_code==200


def test_sent_and_accepted_quotes_cannot_be_edited(env):
    h=auth(env);quote,body=create(env,h)
    before=context(env,h,quote['id']).json()
    sent=env.post('/api/quotes/'+quote['id']+'/status',headers=h,json={'status':'sent'})
    assert sent.status_code==200
    assert context(env,h,quote['id']).status_code==409
    assert update(env,h,quote['id'],before['fingerprint'],body).status_code==409
    assert env.get('/api/quotes/'+quote['id'],headers=h).json()['status']=='sent'


def test_csrf_origin_invalid_items_and_body_validation(env):
    h=auth(env);quote,body=create(env,h);old=context(env,h,quote['id']).json()
    url='/api/review/quotes/'+quote['id']+'/update'
    data={'expected_sha256':old['fingerprint'],'updated':body}
    assert env.post(url,headers={'Cookie':h['Cookie']},json=data).status_code==403
    assert env.post(url,headers={**h,'Origin':'https://hostile.invalid'},json=data).status_code==403
    assert update(env,h,quote['id'],old['fingerprint'],{**body,'items':[]}).status_code==422
    assert update(env,h,quote['id'],old['fingerprint'],{**body,'items':[{'name':'X','quantity':0,'unit_price':3}]}).status_code==422
    assert env.post(url,headers=h,json={**data,'set_role':'admin'}).status_code==422
    assert update(env,h,quote['id'],'not-a-valid-hash',body).status_code==422


def test_customer_from_other_company_is_rejected_atomically(env):
    h=auth(env);quote,body=create(env,h)
    foreign=auth(env,'demo@bada.example')
    theirs=env.get('/api/customers',headers=foreign).json()[0]['id']
    before=context(env,h,quote['id']).json()
    denied=update(env,h,quote['id'],before['fingerprint'],
                  {**body,'customer_id':theirs,'title':'Unsafe'})
    assert denied.status_code==404
    after=context(env,h,quote['id']).json()
    assert after['fingerprint']==before['fingerprint']


def test_baseline_core_app_has_no_review_quote_endpoint(env):
    assert not any('/api/review/quotes/' in getattr(r,'path','') for r in main.app.routes)
    assert any('/api/review/quotes/' in getattr(r,'path','') for r in owner_app.routes)
