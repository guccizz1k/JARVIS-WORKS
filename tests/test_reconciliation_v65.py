"""V6.5 conservative evidence reconciliation, entirely synthetic data."""
import io
import json
import sqlite3
import pytest
from openpyxl import Workbook
from app import main


def spreadsheet(kind, customer, amount, ref):
    wb=Workbook(); w=wb.active
    for row in [('문서종류',kind),('거래처',customer),('거래일','2026-10-21'),('총금액',amount),('문서번호',ref)]: w.append(row)
    out=io.BytesIO();wb.save(out);return out.getvalue()


def create_sale(api, quote_payload, *, vendor=None, amount=None, ref=None, kind='매출전표', record_kind='sales'):
    q=api.post('/quotes',quote_payload)
    assert q.status_code==201,q.text
    quote=q.json()
    detail=api.get('/quotes/'+quote['id']).json()
    actual_customer=detail['customer_name_snapshot']
    actual_amount=detail['money']['total']
    src=spreadsheet(kind,vendor if vendor is not None else actual_customer,
                    amount if amount is not None else actual_amount,
                    ref if ref is not None else detail['doc_no'])
    preview=api.c.post('/api/evidence/preview',files={'file':('doc.xlsx',src)},headers=api.auth)
    assert preview.status_code==201,preview.text
    preview=preview.json()
    payload={'preview_digest':preview['digest'],'record_type':record_kind,
        'document_kind':'sales_slip' if kind=='매출전표' else 'trade_statement',
        'counterparty':vendor if vendor is not None else actual_customer,
        'document_date':'2026-10-21','gross_amount':amount if amount is not None else actual_amount,
        'reference_number':ref if ref is not None else detail['doc_no'],'original_checked':True}
    record=api.post('/evidence/preview/'+preview['id']+'/confirm',payload)
    assert record.status_code==201,record.text
    return detail,record.json()['id']


def candidates(api, rid):
    r=api.get('/evidence/records/'+rid+'/candidates')
    assert r.status_code==200,r.text
    return r.json()


def link(api, rid, d, *, reason=''):
    body={'source_type':d['source_type'],'source_id':d['source_id'],
          'comparison_digest':d['comparison_digest'],
          'original_and_differences_checked':True, 'discrepancy_reason':reason}
    return api.post('/evidence/records/'+rid+'/reconcile-link',body)


def test_exact_reconciliation_and_idempotent_link(api,quote_payload):
    before=api.get('/dashboard').json()
    q,rid=create_sale(api,quote_payload)
    d=next(x for x in candidates(api,rid)['candidates'] if x['source_id']==q['id'])
    assert d['identity_basis']=='document_number'
    assert d['recommendation']=='exact_fields_match' and d['issues']==[]
    assert d['expected_amount']==q['money']['total']
    posted=link(api,rid,d); assert posted.status_code==201,posted.text
    assert posted.json()['accounting_changed'] is False
    again=link(api,rid,d);assert again.status_code==201 and again.json()['reused']
    reconciliation=api.get('/evidence/records/'+rid+'/reconciliation').json()
    assert reconciliation['linked'] and not reconciliation['source_changed']
    dashboard=api.get('/dashboard').json()
    assert dashboard['invoices']==before['invoices'] and dashboard['outstanding']==before['outstanding']
    with main.conn() as c:
        assert c.execute('SELECT count(*) FROM payments').fetchone()[0]==0
        assert c.execute('SELECT count(*) FROM evidence_links_v65').fetchone()[0]==1
        assert c.execute("SELECT count(*) FROM audit_logs WHERE action='link'").fetchone()[0]==1


def test_wrong_amount_triggers_difference_and_explicit_reason(api,quote_payload):
    q,rid=create_sale(api,quote_payload,amount=998877)
    d=next(x for x in candidates(api,rid)['candidates'] if x['source_id']==q['id'])
    assert 'gross_amount' in [issue['field'] for issue in d['issues']]
    assert link(api,rid,d).status_code==422
    assert link(api,rid,d,reason='단순히 일치하는 것처럼 기록').status_code==201
    row=api.get('/evidence/reconciliation/queue').json()
    assert row['linked_with_issues']==1 and row['items'][0]['issues_at_link']


def test_company_mismatch_requires_review_even_if_reference_same(api,quote_payload):
    q,rid=create_sale(api,quote_payload,vendor='위조 거래처',ref=None)
    d=next(x for x in candidates(api,rid)['candidates'] if x['source_id']==q['id'])
    assert d['identity_basis']=='document_number'
    assert 'counterparty' in [i['field'] for i in d['issues']]
    assert link(api,rid,d,reason='원본 거래처명 차이는 담당자 확인 필요').status_code==201


def test_no_guess_based_on_amount_and_unrelated_vendor(api,quote_payload):
    q,rid=create_sale(api,quote_payload,vendor='거래 관계 없는 업체',ref='NOT-THE-INTERNAL-DOC-NUMBER')
    assert candidates(api,rid)['candidates']==[]
    fake={'source_type':'quote','source_id':q['id'],'comparison_digest':'0'*64}
    assert link(api,rid,fake).status_code==409
    assert api.get('/evidence/reconciliation/queue').json()['unlinked']==1


def test_stale_digest_after_source_mutation_is_blocked(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    d=next(x for x in candidates(api,rid)['candidates'] if x['source_id']==q['id'])
    with main.transaction() as c:
        c.execute('UPDATE quotes SET status=? WHERE id=?',('sent',q['id']))
    assert link(api,rid,d).status_code==409
    assert api.get('/evidence/records/'+rid+'/reconciliation').json()['linked'] is False


def test_link_immutability_and_stale_source_detection(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    d=next(x for x in candidates(api,rid)['candidates'] if x['source_id']==q['id'])
    assert link(api,rid,d).status_code==201
    with main.transaction() as c:
        with pytest.raises(sqlite3.IntegrityError):
            c.execute("UPDATE evidence_links_v65 SET discrepancy_reason='hack' WHERE record_id=?",(rid,))
        with pytest.raises(sqlite3.IntegrityError):
            c.execute('DELETE FROM evidence_links_v65 WHERE record_id=?',(rid,))
        c.execute('UPDATE quotes SET status=? WHERE id=?',('sent',q['id']))
    r=api.get('/evidence/records/'+rid+'/reconciliation')
    assert r.status_code==200 and r.json()['source_changed']


def test_source_org_isolation_at_api_and_trigger(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    org=api.get('/me').json()['org_id']
    with main.conn() as c:
        alt=c.execute('SELECT id FROM organizations WHERE id!=?',(org,)).fetchone()['id']
        foreign=c.execute('SELECT * FROM quotes WHERE org_id=? LIMIT 1',(alt,)).fetchone()
    if foreign is None:
        # Create separate tenant's quote through the regular authenticated API.
        login=api.c.post('/api/login',json={'email':'demo@bada.example','password':'Demo!2026secure'})
        assert login.status_code==200
        h={'Cookie':main.SESSION_COOKIE+'='+login.cookies.get(main.SESSION_COOKIE),'X-CSRF-Token':login.json()['csrf_token']}
        customers=api.c.get('/api/customers',headers=h).json()
        r=api.c.post('/api/quotes',headers=h,json={'customer_id':customers[0]['id'],'title':'다른 회사 견적',
          'vat_mode':'taxable','items':[{'name':'해외용', 'quantity':1,'unit_price':1000}]})
        assert r.status_code==201,r.text
        foreign_id=r.json()['id']
        assert api.login().status_code==200
    else:foreign_id=foreign['id']
    fake={'source_type':'quote','source_id':foreign_id,'comparison_digest':'0'*64}
    assert link(api,rid,fake).status_code==404
    assert api.get('/evidence/records/'+rid+'/candidates').status_code==200
    with main.conn() as c:
        user=api.get('/me').json()
        with pytest.raises(sqlite3.IntegrityError):
            c.execute('''INSERT INTO evidence_links_v65(id,org_id,record_id,source_type,source_id,
                comparison_json,comparison_digest,discrepancy_reason,reviewed_by,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?)''',
                ('fake-link',org,rid,'quote',foreign_id,'{}','0'*64,'',user['id'],main.now()))


def test_csrf_confirm_and_user_approval_guard(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    d=next(x for x in candidates(api,rid)['candidates'] if x['source_id']==q['id'])
    body={'source_type':d['source_type'],'source_id':d['source_id'],
          'comparison_digest':d['comparison_digest'],'original_and_differences_checked':True}
    r=api.c.post('/api/evidence/records/'+rid+'/reconcile-link',json=body,
                 headers={'Cookie':api.auth['Cookie']})
    assert r.status_code==403
    assert api.post('/evidence/records/'+rid+'/reconcile-link',
                    {**body,'original_and_differences_checked':False}).status_code==422
    assert link(api,rid,d).status_code==201


def test_inventory_and_purchases_are_not_attached_to_sales(api,quote_payload):
    q=api.post('/quotes',quote_payload).json()
    for kind,record_kind in [('영수증','expense'),('매입전표','purchase')]:
        doc=api.get('/quotes/'+q['id']).json()
        raw=spreadsheet(kind,doc['customer_name_snapshot'],doc['money']['total'],doc['doc_no'])
        preview=api.c.post('/api/evidence/preview',files={'file':(kind+'.xlsx',raw)},headers=api.auth).json()
        p={'preview_digest':preview['digest'],'record_type':record_kind,
           'document_kind':'receipt' if kind=='영수증' else 'purchase_slip',
           'counterparty':doc['customer_name_snapshot'],'document_date':'2026-10-21',
           'gross_amount':doc['money']['total'],'reference_number':doc['doc_no'],'original_checked':True}
        record=api.post('/evidence/preview/'+preview['id']+'/confirm',p)
        assert record.status_code==201,record.text
        rid=record.json()['id']
        assert not candidates(api,rid)['supported']
        assert link(api,rid,{'source_type':'quote','source_id':q['id'],
                            'comparison_digest':'0'*64}).status_code==422
    res=api.get('/evidence/reconciliation/queue').json()
    assert sum(x['status']=='unsupported_source_direction' for x in res['items'])==2


def test_member_limited_to_own_uploads(api,quote_payload):
    # All fixtures are admin by default; other organization cannot access the evidence.
    q,rid=create_sale(api,quote_payload)
    login=api.c.post('/api/login',json={'email':'demo@bada.example','password':'Demo!2026secure'})
    assert login.status_code==200
    cookie=login.cookies.get(main.SESSION_COOKIE)
    h={'Cookie':main.SESSION_COOKIE+'='+cookie,'X-CSRF-Token':login.json()['csrf_token']}
    assert api.c.get('/api/evidence/records/'+rid+'/candidates',headers=h).status_code==404
    assert api.c.get('/api/evidence/records/'+rid+'/reconciliation',headers=h).status_code==404
    assert api.c.get('/api/evidence/reconciliation/queue',headers=h).json()['items']==[]
