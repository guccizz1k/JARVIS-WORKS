"""Real main.py integration tests: SQLite demo only, never external data."""
from tests.conftest import create_order
from app import main


def _fulfilled(api, payload):
    _,o=create_order(api,payload)
    assert api.post(f"/orders/{o['id']}/status",{'status':'processing'}).status_code==200
    assert api.post(f"/orders/{o['id']}/status",{'status':'fulfilled'}).status_code==200
    return o


def test_full_document_graph_idempotency_financial_integrity(api,quote_payload):
    o=_fulfilled(api,quote_payload)
    t=api.get('/automation/timing/active');assert t.status_code==200 and t.json() is None
    run=api.post('/automation/timing/start',{'workflow':'trade_statement','mode':'automated'}).json()
    doc=api.post('/automation/statements/from-order',{'order_id':o['id']})
    assert doc.status_code==201,doc.text
    doc=doc.json()
    assert doc['document']['money']['total']==o['money']['total']
    assert api.post(f"/automation/timing/{run['id']}/finish",{'completed':True,'statement_id':doc['id']}).status_code==200
    again=api.post('/automation/statements/from-order',{'order_id':o['id']})
    assert again.status_code==200 and again.json()['id']==doc['id']
    trace=api.get('/automation/transactions/'+o['id']).json()
    assert trace['order_money']['total']==doc['document']['money']['total']
    assert {e['type'] for e in trace['events']}=={'quote','order','trade_statement'}
    assert trace['remaining_balance'] is None
    assert api.get('/automation/timing/active').json() is None
    assert api.get('/automation/time-savings').json()['status']=='NOT_MEASURED'


def test_crash_recovery_cancel_and_immutability(api,quote_payload):
    run=api.post('/automation/timing/start',{'workflow':'trade_statement','mode':'manual'}).json()['id']
    assert api.get('/automation/timing/active').json()['id']==run
    assert api.post('/automation/timing/start',{'workflow':'trade_statement','mode':'automated'}).status_code==409
    assert api.post(f'/automation/timing/{run}/cancel',{}).json()['status']=='cancelled'
    assert api.get('/automation/timing/active').json() is None
    assert api.post(f'/automation/timing/{run}/cancel',{}).status_code==404
    assert api.get('/automation/time-savings').json()['samples']=={'manual':0,'automated':0}
    second=api.post('/automation/timing/start',{'workflow':'trade_statement','mode':'manual'}).json()['id']
    assert api.post(f'/automation/timing/{second}/finish',{'completed':True}).status_code==200
    assert api.post(f'/automation/timing/{second}/cancel',{}).status_code==409


def test_cross_company_rejected(api,client,quote_payload):
    o=_fulfilled(api,quote_payload)
    d=api.post('/automation/statements/from-order',{'order_id':o['id']}).json()
    login=client.post('/api/login',json={'email':'demo@bada.example','password':'Demo!2026secure'})
    assert login.status_code==200,login.text
    headers={'Cookie':main.SESSION_COOKIE+'='+login.cookies.get(main.SESSION_COOKIE),
             'X-CSRF-Token':login.json()['csrf_token']}
    assert client.get('/api/automation/statements/'+d['id'],headers=headers).status_code==404
    assert client.get('/api/automation/transactions/'+o['id'],headers=headers).status_code==404
    run=api.post('/automation/timing/start',{'workflow':'trade_statement','mode':'manual'}).json()['id']
    assert client.post('/api/automation/timing/'+run+'/cancel',headers=headers,json={}).status_code==404
    assert api.post('/automation/timing/'+run+'/cancel',{}).status_code==200
