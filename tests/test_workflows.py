import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

from .conftest import create_order, create_invoice


def test_health_and_authentication(client,api):
    assert client.get('/api/health').json()['status']=='ok'
    assert client.get('/').status_code==200
    assert client.get('/static/app.js').status_code==200
    assert client.get('/api/config').json()['demo_mode'] is True
    assert client.get('/api/customers',headers={'Cookie':'unknown=1'}).status_code==401
    assert client.post('/api/login',json={'email':'demo@hanbit.example','password':'wrong'}).status_code==401
    assert api.get('/me').json()['org_name']=='한빛테크'
    assert api.post('/logout',{}).status_code==200
    assert api.get('/customers').status_code==401


def test_customers_validation_uniqueness(api):
    body={'name':'초정밀 도매상','business_number':'1234567890','email':'person@business.kr',
          'phone':'010-0000-0000','contact_name':'김관리'}
    r=api.post('/customers',body)
    assert r.status_code==201,r.text
    assert r.json()['name']==body['name']
    assert api.post('/customers',body).status_code==409
    assert api.post('/customers',{**body,'name':'다른 업체','email':'not-an-email'}).status_code==422
    assert api.post('/customers',{**body,'unknown':'x'}).status_code==422
    assert len(api.get('/customers').json())==2


def test_money_rounded_and_exempt(api,quote_payload):
    q=api.post('/quotes',quote_payload);assert q.status_code==201,q.text
    assert q.json()['money']=={'subtotal':1309,'vat':131,'total':1440}
    q2=api.post('/quotes',{**quote_payload,'vat_mode':'exempt'}).json()
    assert q2['money']=={'subtotal':1309,'vat':0,'total':1309}
    q3=api.post('/quotes',{**quote_payload,'items':[{'name':'소액','quantity':1,'unit_price':5}]}).json()
    assert q3['money']=={'subtotal':5,'vat':1,'total':6}
    q4=api.post('/quotes',{**quote_payload,'items':[{'name':'소액','quantity':1,'unit_price':4}]}).json()
    assert q4['money']=={'subtotal':4,'vat':0,'total':4}
    assert q.json()['money']['total']==api.get(f"/quotes/{q.json()['id']}").json()['money']['total']


def test_money_limits_and_validation(api,quote_payload):
    q=api.post('/quotes',{**quote_payload,'items':[{'name':'최대','quantity':100000,'unit_price':1000000000} for _ in range(40)]})
    assert q.status_code==201,q.text
    assert q.json()['money']['subtotal']==4_000_000_000_000_000
    assert q.json()['money']['total']==4_400_000_000_000_000
    for bad in [
        [{'name':'a','quantity':0,'unit_price':100}],
        [{'name':'a','quantity':1.5,'unit_price':100}],
        [{'name':'a','quantity':1,'unit_price':-1}],
        [{'name':'a','quantity':1,'unit_price':1.5}],
        [{'name':'a','quantity':1,'unit_price':1000000001}],
        [{'name':'a','quantity':True,'unit_price':100}],
        []
    ]:
        r=api.post('/quotes',{**quote_payload,'items':bad})
        assert r.status_code==422,(bad,r.text)
    assert api.post('/quotes',{**quote_payload,'items':quote_payload['items']*30}).status_code==422


def test_quote_state_machine_and_immutable_accepted(api,quote_payload):
    q=api.post('/quotes',quote_payload).json();id=q['id']
    assert api.post('/orders/from-quote',{'quote_id':id,'due_date':'2099-12-30'}).status_code==409
    assert api.post(f'/quotes/{id}/status',{'status':'accepted'}).status_code==409
    upd=api.put(f'/quotes/{id}',{**quote_payload,'title':'수정본','items':[{'name':'A2','quantity':4,'unit_price':505}]})
    assert upd.status_code==200
    assert upd.json()['money']['total']==2222
    assert api.post(f'/quotes/{id}/status',{'status':'sent'}).status_code==200
    assert api.put(f'/quotes/{id}',quote_payload).status_code==409
    assert api.post(f'/quotes/{id}/status',{'status':'accepted'}).status_code==200
    assert api.post(f'/quotes/{id}/status',{'status':'rejected'}).status_code==409
    assert api.post('/orders/from-quote',{'quote_id':id,'due_date':'2099-12-30'}).status_code==201
    assert api.post('/orders/from-quote',{'quote_id':id,'due_date':'2099-12-30'}).status_code==409


def test_full_lifecycle_and_payments_exact(api,quote_payload):
    q,o,invoice=create_invoice(api,quote_payload)
    assert q['money']==invoice['money']==o['money']
    assert invoice['money']=={'subtotal':1309,'vat':131,'total':1440}
    assert invoice['balance']==1440
    payment={'amount':400,'paid_at':datetime.now(ZoneInfo('Asia/Seoul')).date().isoformat(),
             'reference':uuid.uuid4().hex,'note':'계좌 확인'}
    p=api.post(f"/invoices/{invoice['id']}/payments",payment)
    assert p.status_code==201,p.text
    assert p.json()['balance']==1040
    retry=api.post(f"/invoices/{invoice['id']}/payments",payment)
    assert retry.status_code==201 and retry.json()['balance']==1040
    assert api.post(f"/invoices/{invoice['id']}/payments",{**payment,'amount':401}).status_code==409
    assert api.post(f"/invoices/{invoice['id']}/payments",{**payment,'amount':1041,'reference':uuid.uuid4().hex}).status_code==409
    assert api.post(f"/invoices/{invoice['id']}/payments",{**payment,'amount':1040,'reference':uuid.uuid4().hex}).json()['balance']==0
    assert api.get(f"/invoices/{invoice['id']}").json()['payment_status']=='paid'
    assert api.post('/invoices/from-order',{'order_id':o['id'],'due_date':'2099-12-31'}).status_code==409
    assert api.put(f"/orders/{o['id']}",{'items':[],'change_reason':'변경 시도','due_date':'2099-12-30'}).status_code==422
    d=api.get('/dashboard').json();assert d['collected']==1440 and d['outstanding']==0


def test_detect_differences_approval_and_invoice_safety(api,quote_payload):
    q,o=create_order(api,quote_payload);oid=o['id']
    original=o['items'][0]
    change={'items':[{'name':x['name'],'quantity':x['quantity']+(1 if j==0 else 0),
                      'unit_price':x['unit_price'],'source_quote_item_id':x['source_quote_item_id']}
                      for j,x in enumerate(o['items'])],
            'change_reason':'고객의 요청으로 수량을 변경했습니다','due_date':'2099-12-30'}
    changed=api.put(f'/orders/{oid}',change)
    assert changed.status_code==200,changed.text
    assert changed.json()['review_state']=='pending'
    report=api.get(f'/reconciliation/{oid}').json()
    assert len(report['quote_to_order'])==1
    assert report['quote_to_order'][0]['field']=='quantity'
    assert report['safe_to_bill'] is False
    assert api.post(f'/orders/{oid}/status',{'status':'processing'}).status_code==200
    assert api.post(f'/orders/{oid}/status',{'status':'fulfilled'}).status_code==409
    assert api.post('/invoices/from-order',{'order_id':oid,'due_date':'2099-12-31'}).status_code==409
    assert api.post(f'/orders/{oid}/acknowledge',{}).status_code==200
    assert api.post(f'/orders/{oid}/status',{'status':'fulfilled'}).status_code==200
    invoice=api.post('/invoices/from-order',{'order_id':oid,'due_date':'2099-12-31'})
    assert invoice.status_code==201,invoice.text
    report=api.get(f'/reconciliation/{oid}').json()
    assert report['quote_to_order'] and report['order_to_invoice']==[]
    assert api.put(f'/orders/{oid}',change).status_code==409
    log=api.get('/audit').json()
    assert any(x['action']=='acknowledge' for x in log)
    assert any(x['action']=='edit' and '고객의 요청' in x['detail'] for x in log)


def test_invalid_reference_prevents_cross_origin_injection(api,quote_payload):
    q,o=create_order(api,quote_payload)
    body={'items':[{'name':'거짓 원본','quantity':1,'unit_price':5,'source_quote_item_id':'foreign-or-random'}],
          'change_reason':'다른 문서에서 품목 조작','due_date':'2099-12-30'}
    assert api.put(f"/orders/{o['id']}",body).status_code==400
    original=o['items'][0]
    body['items']=[{'name':original['name'],'quantity':1,'unit_price':5,'source_quote_item_id':original['source_quote_item_id']}]*2
    assert api.put(f"/orders/{o['id']}",body).status_code==400
    assert api.get(f"/orders/{o['id']}").json()['review_state']=='clean'


def test_tenant_isolation(client,api,quote_payload):
    q,o,invoice=create_invoice(api,quote_payload)
    a_customer=api.get('/customers').json()[0]['id']
    auth_a=api.auth.copy()
    assert api.login('demo@bada.example').status_code==200
    assert api.get('/me').json()['org_name']=='바다유통'
    assert len(api.get('/customers').json())==1
    assert api.get('/dashboard').json()['invoices']==0
    for path in [f'/quotes/{q["id"]}',f'/orders/{o["id"]}',f'/invoices/{invoice["id"]}',f'/reconciliation/{o["id"]}']:
        assert api.get(path).status_code==404,path
    assert api.post('/quotes',{**quote_payload,'customer_id':a_customer}).status_code==404
    assert api.post('/orders/from-quote',{'quote_id':q['id'],'due_date':'2099-12-30'}).status_code==404
    assert api.post('/invoices/from-order',{'order_id':o['id'],'due_date':'2099-12-30'}).status_code==404
    assert api.post(f"/invoices/{invoice['id']}/payments",{'amount':1,'paid_at':'2026-10-18','reference':'cross-tenant-attempt'}).status_code==404
    assert api.get('/audit').json()==[]
    api.auth=auth_a
    assert api.get('/dashboard').json()['invoices']==1


def test_order_status_restrictions_and_due_dates(api,quote_payload):
    q,o=create_order(api,quote_payload)
    oid=o['id']
    assert api.post(f'/orders/{oid}/status',{'status':'fulfilled'}).status_code==409
    assert api.post('/invoices/from-order',{'order_id':oid,'due_date':'2099-12-31'}).status_code==409
    assert api.post('/orders/from-quote',{'quote_id':q['id'],'due_date':'2001-01-01'}).status_code==409
    assert api.post(f'/orders/{oid}/status',{'status':'processing'}).status_code==200
    assert api.post(f'/orders/{oid}/status',{'status':'cancelled'}).status_code==200
    assert api.post(f'/orders/{oid}/status',{'status':'processing'}).status_code==409
    assert api.post('/invoices/from-order',{'order_id':oid,'due_date':'2099-12-31'}).status_code==409


def test_unauthorized_or_rejected_payment(api,quote_payload):
    _,_,inv=create_invoice(api,quote_payload)
    path=f"/invoices/{inv['id']}/payments"
    payment={'amount':1,'paid_at':'2099-12-30','reference':uuid.uuid4().hex}
    assert api.post(path,payment).status_code==400
    assert api.post(path,{**payment,'paid_at':'2026-10-18','amount':0}).status_code==422
    assert api.post(path,{**payment,'paid_at':'2026-10-18','amount':-1}).status_code==422
    assert api.post(path,{**payment,'paid_at':'2026-10-18','amount':1.1}).status_code==422
    assert api.get(f"/invoices/{inv['id']}").json()['paid']==0


def test_customer_update_preserves_links_and_logs(api,quote_payload):
    customer_id=quote_payload['customer_id']
    quote=api.post('/quotes',quote_payload).json()
    changed={'name':'미래부품 신규 상호','business_number':'9876543210',
             'contact_name':'담당자2','email':'office@new.example','phone':'02-0000-1234'}
    r=api.put(f'/customers/{customer_id}',changed)
    assert r.status_code==200,r.text
    assert r.json()['name']==changed['name']
    assert api.get(f'/quotes/{quote["id"]}').json()['customer_id']==customer_id
    assert next(x for x in api.get('/quotes').json() if x['id']==quote['id'])['customer_name']=='미래부품'
    assert api.put(f'/customers/{customer_id}',{**changed,'email':'wrong-at'}).status_code==422
    assert api.put(f'/customers/{customer_id}',{**changed,'name':'미래부품'}).status_code==200
    assert api.put('/customers/someone-else',changed).status_code==404
    assert any(x['entity_id']==customer_id and x['action']=='edit' for x in api.get('/audit').json())


def test_payment_reversal_audit_and_reference_safety(api,quote_payload):
    q,o,invoice=create_invoice(api,quote_payload)
    date_string=datetime.now(ZoneInfo('Asia/Seoul')).date().isoformat()
    p={'amount':500,'paid_at':date_string,'reference':uuid.uuid4().hex,'note':'실수 입금'}
    recorded=api.post(f"/invoices/{invoice['id']}/payments",p)
    assert recorded.status_code==201
    assert recorded.json()['balance']==940
    payid=recorded.json()['payments'][0]['id']
    path=f"/invoices/{invoice['id']}/payments/{payid}/reverse"
    reversed_record=api.post(path,{})
    assert reversed_record.status_code==200,reversed_record.text
    assert reversed_record.json()['balance']==1440
    assert reversed_record.json()['paid']==0
    assert reversed_record.json()['payments'][0]['reversed_at'] is not None
    assert api.post(path,{}).status_code==409
    assert api.post(f"/invoices/{invoice['id']}/payments",p).status_code==409
    assert any(x['entity_id']==payid and x['action']=='reverse' for x in api.get('/audit').json())
    assert api.get('/dashboard').json()['outstanding']==1440
    corrected={**p,'reference':uuid.uuid4().hex,'amount':1440,'note':'확인된 실제 입금'}
    assert api.post(f"/invoices/{invoice['id']}/payments",corrected).json()['balance']==0
    assert len(api.get(f"/invoices/{invoice['id']}").json()['payments'])==2


def test_cross_tenant_customer_edit_and_payment_reversal(client,api,quote_payload):
    q,o,invoice=create_invoice(api,quote_payload)
    pay={'amount':100,'paid_at':datetime.now(ZoneInfo('Asia/Seoul')).date().isoformat(),
         'reference':uuid.uuid4().hex}
    payment_id=api.post(f"/invoices/{invoice['id']}/payments",pay).json()['payments'][0]['id']
    aid=quote_payload['customer_id']
    assert api.login('demo@bada.example').status_code==200
    assert api.put(f'/customers/{aid}',{'name':'도용 시도'}).status_code==404
    assert api.post(f"/invoices/{invoice['id']}/payments/{payment_id}/reverse",{}).status_code==404
    assert api.get('/audit').json()==[]


def test_login_throttle_is_persisted_and_recovers_on_correct_password(client):
    email='demo@bada.example'
    wrong={'email':email,'password':'incorrect'}
    for _ in range(5):
        assert client.post('/api/login',json=wrong).status_code==401
    assert client.post('/api/login',json=wrong).status_code==429
    assert client.post('/api/login',json={'email':email,'password':'Demo!2026secure'}).status_code==429
    from app.main import transaction
    from datetime import timedelta
    with transaction() as c:
        past=(datetime.now(ZoneInfo('Asia/Seoul'))-timedelta(minutes=16)).isoformat()
        c.execute('UPDATE login_failures SET first_failed_at=? WHERE email=?',(past,email))
    assert client.post('/api/login',json={'email':email,'password':'Demo!2026secure'}).status_code==200
    assert client.get('/api/health').headers['cache-control']=='no-store'
    assert client.get('/api/health').headers['x-frame-options']=='DENY'


def test_concurrent_payment_does_not_overcollect(client,api,quote_payload):
    import concurrent.futures
    _,_,invoice=create_invoice(api,quote_payload)
    headers=api.auth.copy()
    path=f"/api/invoices/{invoice['id']}/payments"
    def submit(i):
        with __import__('fastapi').testclient.TestClient(client.app,base_url='https://testserver') as other:
            return other.post(path,headers=headers,json={
                'amount':1000,'paid_at':datetime.now(ZoneInfo('Asia/Seoul')).date().isoformat(),
                'reference':str(uuid.uuid4()),'note':str(i)}).status_code
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(submit,[1,2]))
    assert sorted(results)==[201,409],results
    assert api.get(f"/invoices/{invoice['id']}").json()['paid']==1000


def test_historical_customer_snapshot_and_edit_audit(api,quote_payload):
    q=api.post('/quotes',quote_payload).json()
    c=api.get('/customers').json()[0]
    r=api.put(f"/customers/{c['id']}",{'name':'미래부품 상호변경','business_number':'',
           'contact_name':'새 담당','email':'new@example.kr','phone':''})
    assert r.status_code==200,r.text
    assert api.get(f"/quotes/{q['id']}").json()['customer_name_snapshot']==c['name']
    assert any(x['customer_name']==c['name'] for x in api.get('/quotes').json() if x['id']==q['id'])
    assert api.post(f"/quotes/{q['id']}/status",{'status':'sent'}).status_code==200
    assert api.post(f"/quotes/{q['id']}/status",{'status':'accepted'}).status_code==200
    order=api.post('/orders/from-quote',{'quote_id':q['id'],'due_date':'2099-12-30'}).json()
    assert order['customer_name_snapshot']==c['name']
    log=api.get('/audit').json()
    assert any(x['entity_type']=='customer' and 'changed_fields' in x['detail'] and 'email' in x['detail'] and 'new@example.kr' not in x['detail'] for x in log)


def test_payment_history_and_cross_tenant_isolation(api,quote_payload):
    _,_,i=create_invoice(api,quote_payload)
    payload={'amount':100,'paid_at':datetime.now(ZoneInfo('Asia/Seoul')).date().isoformat(),
             'reference':uuid.uuid4().hex,'note':'영수 확인'}
    assert api.post(f"/invoices/{i['id']}/payments",payload).status_code==201
    history=api.get(f"/invoices/{i['id']}/payments").json()
    assert len(history)==1 and history[0]['note']=='영수 확인'
    api.login('demo@bada.example')
    assert api.get(f"/invoices/{i['id']}/payments").status_code==404


def test_reconciliation_adding_and_removing_items(api,quote_payload):
    q,o=create_order(api,quote_payload)
    source=o['items'][0]
    changed={'items':[{'source_quote_item_id':source['source_quote_item_id'], 'name':'부품 A',
                       'quantity':3,'unit_price':101},
                      {'source_quote_item_id':None,'name':'추가 서비스','quantity':1,'unit_price':45}],
             'due_date':'2099-12-30','change_reason':'추가 서비스와 품목 조정'}
    r=api.put(f"/orders/{o['id']}",changed)
    assert r.status_code==200,r.text
    diff=api.get(f"/reconciliation/{o['id']}").json()['quote_to_order']
    assert {x['field'] for x in diff}=={'missing','extra'}
    log=api.get('/audit').json()
    edits=[x for x in log if x['action']=='edit' and x['entity_type']=='order']
    assert len(edits)==1 and '추가 서비스' in edits[0]['detail']


def test_production_bootstrap_without_demo(tmp_path,monkeypatch):
    import app.main as backend
    from fastapi.testclient import TestClient
    monkeypatch.setattr(backend,'DB_PATH',tmp_path/'production-sandbox.db')
    monkeypatch.delenv('DEMO_SEED',raising=False)
    monkeypatch.setenv('BOOTSTRAP_EMAIL','admin@sample.company')
    monkeypatch.setenv('BOOTSTRAP_PASSWORD','StrongBootstrap!2026')
    monkeypatch.setenv('BOOTSTRAP_ORG','시험용 기업')
    with TestClient(backend.app,base_url='https://testserver') as c:
        assert c.get('/api/config').json()['demo_mode'] is False
        r=c.post('/api/login',json={'email':'admin@sample.company','password':'StrongBootstrap!2026'})
        assert r.status_code==200,r.text
        assert 'token' not in r.json()
        assert r.cookies.get(backend.SESSION_COOKIE)
        assert c.get('/api/customers').json()==[]
        assert c.get('/api/health').headers['x-frame-options']=='DENY'


def test_legacy_schema_migration_preserves_existing_documents(tmp_path,monkeypatch):
    import sqlite3
    import app.main as backend
    db=tmp_path/'legacy.db'
    legacy=backend.SCHEMA.replace('  customer_name_snapshot TEXT NOT NULL,\n','').replace('  reversed_at TEXT, reversed_by TEXT REFERENCES users(id),\n','')
    with sqlite3.connect(db) as c:
        c.executescript(legacy)
        c.execute('INSERT INTO organizations VALUES(?,?,?)',('org','사내 테스트',backend.now()))
        c.execute('INSERT INTO customers VALUES(?,?,?,?,?,?,?,?)',('cust','org','과거 고객','','','','',backend.now()))
        c.execute('INSERT INTO quotes VALUES(?,?,?,?,?,?,?,?,?)',('quo','org','cust','Q-LEGACY','마이그레이션 견적','draft','taxable',backend.now(),backend.now()))
        c.execute('INSERT INTO quote_items VALUES(?,?,?,?,?,?)',('item','quo','기존 품목',2,100,0))
    monkeypatch.setattr(backend,'DB_PATH',db)
    monkeypatch.delenv('DEMO_SEED',raising=False)
    backend.init_db()
    with backend.conn() as c:
        row=c.execute("SELECT * FROM quotes WHERE id='quo'").fetchone()
        assert row['customer_name_snapshot']=='과거 고객'
        assert backend.detail_doc(c,'quote',dict(row))['money']['total']==220
        assert {r['name'] for r in c.execute('PRAGMA table_info(payments)')} >= {'reversed_at','reversed_by'}
    backend.init_db()  # safe to rerun


def test_consistent_sqlite_backup(tmp_path,api,monkeypatch):
    from importlib.util import spec_from_file_location, module_from_spec
    from pathlib import Path
    import app.main as backend
    destination=tmp_path/'archive'
    monkeypatch.setenv('JARVIS_DB_PATH',str(backend.DB_PATH))
    monkeypatch.setenv('JARVIS_BACKUP_DIR',str(destination))
    target=Path(__file__).resolve().parents[1]/'scripts'/'backup_db.py'
    spec=spec_from_file_location('backup_db_test',target)
    module=module_from_spec(spec)
    spec.loader.exec_module(module)
    from cryptography.fernet import Fernet
    monkeypatch.setenv('JW_BACKUP_KEY',Fernet.generate_key().decode())
    backup_path=module.backup()
    assert backup_path.is_file() and backup_path.suffix=='.jwbackup'
    from scripts.secure_backup import verify_backup
    import sqlite3
    with sqlite3.connect(':memory:') as b:
        b.deserialize(verify_backup(backup_path))
        assert b.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        assert b.execute('SELECT count(*) FROM organizations').fetchone()[0]==2
