"""V6.2 synthetic-only FastAPI integration and malicious-input coverage."""
from __future__ import annotations

import io
import sqlite3

from openpyxl import load_workbook
from tests.conftest import create_order, create_invoice
from app import main


def fulfilled(api,payload):
    q,o=create_order(api,payload)
    assert api.post('/orders/'+o['id']+'/status',{'status':'processing'}).status_code==200
    assert api.post('/orders/'+o['id']+'/status',{'status':'fulfilled'}).status_code==200
    return q,o


def test_sales_draft_only_accepted_quote(api, quote_payload):
    quote=api.post('/quotes',quote_payload).json()
    body={'kind':'sales_order_draft','source_id':quote['id']}
    assert api.post('/automation/drafts/from-source',body).status_code==409
    assert api.post('/quotes/'+quote['id']+'/status',{'status':'sent'}).status_code==200
    assert api.post('/automation/drafts/from-source',body).status_code==409
    assert api.post('/quotes/'+quote['id']+'/status',{'status':'accepted'}).status_code==200
    doc=api.post('/automation/drafts/from-source',body)
    assert doc.status_code==201,doc.text
    doc=doc.json()
    assert doc['kind']=='sales_order_draft'
    assert doc['document']['money']['total']==quote['money']['total']
    assert doc['document']['source_no']==quote['doc_no']
    again=api.post('/automation/drafts/from-source',body)
    assert again.status_code==200 and again.json()['id']==doc['id']
    with main.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM orders WHERE quote_id=?',(quote['id'],)).fetchone()[0]==0
        assert c.execute('SELECT COUNT(*) FROM automation_document_drafts_v62').fetchone()[0]==1


def test_delivery_note_snapshot_idempotence_and_trace(api,quote_payload):
    quote,order=fulfilled(api,quote_payload)
    body={'source_id':order['id'],'kind':'delivery_note_draft'}
    response=api.post('/automation/drafts/from-source',body)
    assert response.status_code==201,response.text
    doc=response.json()
    assert doc['document']['money']==order['money']
    assert len(doc['document']['items'])==2
    assert api.post('/automation/drafts/from-source',body).json()['id']==doc['id']
    assert api.get('/automation/drafts/'+doc['id']).json()['document']==doc['document']
    with main.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM invoices WHERE order_id=?',(order['id'],)).fetchone()[0]==0
        assert c.execute('SELECT COUNT(*) FROM audit_logs WHERE entity_id=?',(doc['id'],)).fetchone()[0]==1
        try:
            c.execute('UPDATE automation_document_drafts_v62 SET document_no=? WHERE id=?',('HIJACK',doc['id']))
            assert False,'Update unexpectedly allowed'
        except sqlite3.IntegrityError:
            pass
        try:
            c.execute('DELETE FROM automation_document_drafts_v62 WHERE id=?',(doc['id'],))
            assert False,'Delete unexpectedly allowed'
        except sqlite3.IntegrityError:
            pass


def test_payment_request_snapshot_only_unpaid(api,quote_payload):
    _,order,invoice=create_invoice(api,quote_payload)
    d=api.post('/automation/drafts/from-source',{'kind':'payment_request_draft','source_id':invoice['id']})
    assert d.status_code==201,d.text
    assert d.json()['document']['balance_at_creation']==invoice['money']['total']
    assert d.json()['document']['document_status']=='internal_review_draft_only'
    assert api.post('/invoices/'+invoice['id']+'/payments',{'amount':invoice['money']['total'],'paid_at':'2026-10-22','note':'test','reference':'settled0001'}).status_code==201
    previous=api.get('/automation/drafts/'+d.json()['id']).json()
    assert previous['document']['balance_at_creation']==invoice['money']['total']
    assert previous['created_at']==d.json()['created_at']
    assert previous['stale'] is True and previous['current_balance']==0
    # An obsolete notice can still be read for audit but cannot be reissued/exported.
    assert api.post('/automation/drafts/from-source',{'kind':'payment_request_draft','source_id':invoice['id']}).status_code==409
    assert api.get('/automation/drafts/'+d.json()['id']+'/xlsx').status_code==409
    with main.conn() as c:
        assert c.execute('SELECT count(*) FROM payments WHERE invoice_id=?',(invoice['id'],)).fetchone()[0]==1


def test_batch_atomic_failure_and_reuse(api,quote_payload):
    _,good=fulfilled(api,quote_payload)
    _,bad=create_order(api,quote_payload)
    payload={'kind':'delivery_note_draft','source_ids':[good['id'],bad['id']]}
    assert api.post('/automation/drafts/batch',payload).status_code==409
    with main.conn() as c:
        assert c.execute('SELECT count(*) FROM automation_document_drafts_v62').fetchone()[0]==0
    assert api.post('/orders/'+bad['id']+'/status',{'status':'processing'}).status_code==200
    assert api.post('/orders/'+bad['id']+'/status',{'status':'fulfilled'}).status_code==200
    result=api.post('/automation/drafts/batch',payload)
    assert result.status_code==201,result.text
    assert result.json()['count']==2 and result.json()['created']==2
    assert api.post('/automation/drafts/batch',payload).json()['reused']==2
    assert api.post('/automation/drafts/batch',{'kind':'delivery_note_draft','source_ids':[good['id'],good['id']]}).status_code==400
    assert api.post('/automation/drafts/batch',{'kind':'delivery_note_draft','source_ids':[]}).status_code==422
    assert api.post('/automation/drafts/batch',{'kind':'delivery_note_draft','source_ids':['x']*21}).status_code==422
    assert api.post('/automation/drafts/from-source',{'kind':'bogus','source_id':good['id']}).status_code==422


def test_cross_tenant_source_draft_and_export_rejected(api,client,quote_payload):
    quote,order=fulfilled(api,quote_payload)
    d=api.post('/automation/drafts/from-source',{'kind':'delivery_note_draft','source_id':order['id']}).json()
    login=client.post('/api/login',json={'email':'demo@bada.example','password':'Demo!2026secure'})
    assert login.status_code==200
    headers={'Cookie':main.SESSION_COOKIE+'='+login.cookies.get(main.SESSION_COOKIE),
             'X-CSRF-Token':login.json()['csrf_token']}
    for path in ['/api/automation/drafts/'+d['id'], '/api/automation/drafts/'+d['id']+'/xlsx']:
        assert client.get(path,headers=headers).status_code==404
    assert client.post('/api/automation/drafts/from-source',headers=headers,json={'kind':'delivery_note_draft','source_id':order['id']}).status_code==404
    assert client.post('/api/automation/drafts/batch',headers=headers,json={'kind':'delivery_note_draft','source_ids':[order['id']]}).status_code==404
    with main.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM automation_document_drafts_v62').fetchone()[0]==1


def test_excel_export_safe_types_and_formula_injection(api,quote_payload):
    quote_payload['items'][0]['name']='=HYPERLINK("https://example.invalid","evil")'
    quote_payload['items'][1]['name']=' +SUM(1,2)'
    _,order=fulfilled(api,quote_payload)
    d=api.post('/automation/drafts/from-source',{'kind':'delivery_note_draft','source_id':order['id']}).json()
    response=api.get('/automation/drafts/'+d['id']+'/xlsx')
    assert response.status_code==200
    assert 'no-store' in response.headers['cache-control']
    assert response.content.startswith(b'PK')
    workbook=load_workbook(io.BytesIO(response.content),read_only=True,data_only=False)
    sheet=workbook.active
    assert sheet['A8'].value.startswith("'=")
    assert sheet['A9'].value.startswith("'+")
    assert sheet['A8'].data_type=='s'
    assert sheet['A9'].data_type=='s'
    assert sheet['D8'].value==303
    assert sheet['D9'].value==1006
    assert any(row[0]=='합계' and row[3]==order['money']['total'] for row in sheet.values)
    assert response.headers['content-disposition'].endswith('.xlsx"')


def test_tenant_db_guard_direct_insert(api,quote_payload):
    quote,order=fulfilled(api,quote_payload)
    with main.conn() as c:
        org=c.execute('SELECT id FROM organizations WHERE name=?',('한빛상사',)).fetchone()
        if org is None:
            org=c.execute('SELECT org_id FROM orders WHERE id=?',(order['id'],)).fetchone()
            orgid=org[0]
        else: orgid=org[0]
        other=c.execute('SELECT id FROM organizations WHERE id<>? LIMIT 1',(orgid,)).fetchone()[0]
        user=c.execute('SELECT id FROM users WHERE org_id=? LIMIT 1',(orgid,)).fetchone()[0]
        try:
            c.execute('''INSERT INTO automation_document_drafts_v62(id,org_id,created_by,kind,source_type,source_id,document_no,payload_json,created_at)
                VALUES(?,?,?,?,?,?,?,?,?)''',('fake',other,user,'delivery_note_draft','order',order['id'],'fake','{}','2026-10-22'))
            assert False,'DB tenant guard bypassed'
        except sqlite3.IntegrityError:
            pass


def test_simultaneous_repeat_is_idempotent(api,quote_payload):
    from concurrent.futures import ThreadPoolExecutor
    _,order=fulfilled(api,quote_payload)
    body={'kind':'delivery_note_draft','source_id':order['id']}
    def request(_):
        return api.post('/automation/drafts/from-source',body)
    with ThreadPoolExecutor(max_workers=6) as pool:
        replies=list(pool.map(request,range(12)))
    assert all(r.status_code in (200,201) for r in replies),[r.text for r in replies if r.status_code not in (200,201)]
    assert sum(r.status_code==201 for r in replies)==1
    assert len({r.json()['id'] for r in replies})==1
    with main.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM automation_document_drafts_v62').fetchone()[0]==1
        assert c.execute('SELECT COUNT(*) FROM audit_logs WHERE entity_type=?',('automation_document_draft',)).fetchone()[0]==1


def test_dashboard_document_summary_is_tenant_scoped(api,client,quote_payload):
    _,order=fulfilled(api,quote_payload)
    empty=api.get('/automation/drafts/summary')
    assert empty.status_code==200 and empty.json()['total']==0
    doc=api.post('/automation/drafts/from-source',{'kind':'delivery_note_draft','source_id':order['id']}).json()
    summary=api.get('/automation/drafts/summary')
    assert summary.status_code==200
    assert summary.json()['total']==1
    assert summary.json()['by_kind']['delivery_note_draft']==1
    assert summary.json()['recent'][0]['id']==doc['id']
    other=client.post('/api/login',json={'email':'demo@bada.example','password':'Demo!2026secure'})
    headers={'Cookie':main.SESSION_COOKIE+'='+other.cookies.get(main.SESSION_COOKIE)}
    response=client.get('/api/automation/drafts/summary',headers=headers)
    assert response.status_code==200 and response.json()['total']==0 and response.json()['recent']==[]
