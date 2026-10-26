"""V6.9 integration gates on the same API and SQLite harness as V6.8."""
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from app import main
from tests.conftest import create_invoice


def setup_invoice(api,quote_payload):
    _,_,invoice=create_invoice(api,quote_payload)
    return invoice


def proposal(api,invoice,kind,seq=1,**kw):
    data=dict(kind=kind,request_key='v69_request_%04d'%seq,
              reason='원본 청구 품목 및 조정 사유를 담당자가 확인했습니다',original_checked=True,
              **kw)
    return api.post('/invoices/'+invoice['id']+'/adjustments',data)


def status(api,invoice):
    r=api.get('/invoices/'+invoice['id']+'/adjustments')
    assert r.status_code==200,r.text
    return r.json()


def decide(api,invoice,aid,approve=True,digest=None):
    s=status(api,invoice)
    return api.post('/invoices/'+invoice['id']+'/adjustments/'+aid+'/decision',
                    dict(approve=approve,expected_digest=digest or s['expected_digest'],
                         original_checked=True,note='원본 증빙 및 수량 금액을 확인했습니다'))


def test_return_discount_freight_totals_and_partial_payment(api,quote_payload):
    inv=setup_invoice(api,quote_payload)
    base=api.get('/invoices/'+inv['id']).json()
    assert base['money']['total']==1440
    line=base['items'][0]
    r=proposal(api,inv,'return',1,item_id=line['id'],quantity=1)
    assert r.status_code==201,r.text
    assert status(api,inv)['settlement']['adjusted_total']==1440 # pending no effect
    assert decide(api,inv,r.json()['id']).status_code==200
    assert status(api,inv)['settlement']['adjusted_total']==1329 # 1309-101=1208 plus 121 VAT
    assert proposal(api,inv,'discount',2,amount=100).status_code==201
    adj=status(api,inv)['adjustments'][-1]
    assert decide(api,inv,adj['id']).status_code==200
    assert status(api,inv)['settlement']['adjusted_total']==1219
    assert proposal(api,inv,'freight',3,amount=60).status_code==201
    adj=status(api,inv)['adjustments'][-1]
    assert decide(api,inv,adj['id']).status_code==200
    after=api.get('/invoices/'+inv['id']).json()
    assert after['settlement']['adjusted_total']==1285 # 1168 + 117
    assert after['money']['total']==1440 # original legally distinct
    assert after['balance']==1285
    assert after['settlement']['statutory_credit_note_issued'] is False
    pay=api.post('/invoices/'+inv['id']+'/payments',
                 dict(reference='v69_payment_0001',amount=500,paid_at='2026-10-21',note='1차 입금'))
    assert pay.status_code==201,pay.text
    assert pay.json()['balance']==785
    assert api.post('/invoices/'+inv['id']+'/payments',
        dict(reference='v69_payment_0002',amount=786,paid_at='2026-10-21',note='초과')).status_code==409
    assert api.get('/dashboard').json()['outstanding']>=785


def test_double_return_limits_and_stale_approval(api,quote_payload):
    inv=setup_invoice(api,quote_payload)
    item=inv['items'][0]
    a=proposal(api,inv,'return',11,item_id=item['id'],quantity=2)
    b=proposal(api,inv,'return',12,item_id=item['id'],quantity=2)
    assert a.status_code==201 and b.status_code==201
    stale=status(api,inv)['expected_digest']
    assert decide(api,inv,a.json()['id']).status_code==200
    assert decide(api,inv,b.json()['id'],digest=stale).status_code==409
    assert decide(api,inv,b.json()['id']).status_code==409
    assert status(api,inv)['settlement']['approved_adjustments']==1


def test_reject_does_not_change_receivable_or_mutate_original(api,quote_payload):
    inv=setup_invoice(api,quote_payload)
    amt=inv['money']['total']
    r=proposal(api,inv,'discount',21,amount=99)
    assert decide(api,inv,r.json()['id'],False).status_code==200
    assert api.get('/invoices/'+inv['id']).json()['balance']==amt
    assert decide(api,inv,r.json()['id'],True).status_code==409
    with main.conn() as c:
        with pytest.raises(sqlite3.DatabaseError):
            c.execute('UPDATE invoice_adjustments_v69 SET amount=2 WHERE id=?',(r.json()['id'],))
        with pytest.raises(sqlite3.DatabaseError):
            c.execute('DELETE FROM invoice_adjustment_decisions_v69 WHERE adjustment_id=?',(r.json()['id'],))


def test_cannot_credit_below_existing_receipt_or_negative_subtotal(api,quote_payload):
    inv=setup_invoice(api,quote_payload)
    assert api.post('/invoices/'+inv['id']+'/payments',
                    dict(reference='v69_payment_0003',amount=1000,paid_at='2026-10-21',note='선결제')).status_code==201
    a=proposal(api,inv,'discount',31,amount=600)
    assert decide(api,inv,a.json()['id']).status_code==409
    assert status(api,inv)['settlement']['adjusted_total']==1440
    b=proposal(api,inv,'discount',32,amount=2000)
    assert decide(api,inv,b.json()['id']).status_code==409


def test_tenant_scope_input_validation_idempotency(api,quote_payload):
    inv=setup_invoice(api,quote_payload)
    p=proposal(api,inv,'freight',41,amount=150)
    assert p.status_code==201
    assert proposal(api,inv,'freight',41,amount=150).json()['reused'] is True
    assert proposal(api,inv,'freight',41,amount=151).status_code==409
    assert proposal(api,inv,'return',42,item_id='not-a-real-item',quantity=1).status_code==422
    assert proposal(api,inv,'discount',43,amount=True).status_code==422
    assert proposal(api,inv,'discount',44,amount=5,quantity=1).status_code==422
    assert api.post('/invoices/'+inv['id']+'/adjustments',dict(kind='discount',request_key='declined_0000001',amount=5,reason='검토가 완료되지 않았습니다',original_checked=False)).status_code==422
    who=api.get('/me').json()['org_id']
    with main.conn() as c:
        other=c.execute('SELECT id FROM organizations WHERE id!=?',(who,)).fetchone()['id']
        with pytest.raises(sqlite3.IntegrityError):
            c.execute('''INSERT INTO invoice_adjustments_v69
              (id,org_id,invoice_id,request_key,kind,item_id,quantity,amount,reason,created_by,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
              ('v69_invalid',other,inv['id'],'fake_key_123456','discount','',0,100,'fake',
              api.get('/me').json()['id'],main.now()))
    assert api.login('demo@bada.example').status_code==200
    assert status_not_found(api,inv)
    assert proposal(api,inv,'discount',46,amount=10).status_code==404


def status_not_found(api,inv):
    return api.get('/invoices/'+inv['id']+'/adjustments').status_code==404


def test_max_pending_and_reversal_rebalances(api,quote_payload):
    inv=setup_invoice(api,quote_payload)
    for i in range(20):assert proposal(api,inv,'freight',100+i,amount=1).status_code==201
    assert proposal(api,inv,'freight',150,amount=1).status_code==409
    p=status(api,inv)['adjustments'][0]
    assert decide(api,inv,p['id'],False).status_code==200
    assert proposal(api,inv,'freight',151,amount=1).status_code==201
    receipt=api.post('/invoices/'+inv['id']+'/payments',
        dict(reference='v69_payment_0004',amount=100,paid_at='2026-10-21',note='입금')).json()
    pid=next(p['id'] for p in receipt['payments'] if p['reversed_at'] is None)
    assert api.post('/invoices/'+inv['id']+'/payments/'+pid+'/reverse',{}).status_code==200
    assert status(api,inv)['settlement']['paid']==0
