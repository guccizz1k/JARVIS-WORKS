"""V6.6 multi-line conservative comparison, only synthetic test documents."""
import sqlite3
import pytest
from app import main
from tests.test_reconciliation_v65 import create_sale, candidates, link


def sample_lines():
    return [dict(name='부품 A',quantity=3,unit_price=101),
            dict(name='부품 B',quantity=2,unit_price=503)]


def confirm(api,rid,lines,checked=True):
    return api.post('/evidence/records/'+rid+'/line-items',
                    {'original_checked':checked,'lines':lines})


def source_candidate(api,rid,source_id):
    return next(x for x in candidates(api,rid)['candidates'] if x['source_id']==source_id)


def test_multi_line_full_match_and_immutable_snapshot(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    res=confirm(api,rid,sample_lines()); assert res.status_code==201,res.text
    assert not res.json()['reused']
    data=source_candidate(api,rid,q['id'])
    assert data['recommendation']=='exact_fields_match' and data['issues']==[]
    assert data['line_comparison']['matched_line_count']==2
    assert data['line_comparison']['full_source_coverage']
    assert data['line_comparison']['evidence_subtotal']==1309
    get=api.get('/evidence/records/'+rid+'/line-items');assert get.status_code==200 and len(get.json()['lines'])==2
    assert confirm(api,rid,sample_lines()).json()['reused'] is True
    assert link(api,rid,data).status_code==201
    assert confirm(api,rid,[dict(name='변경',quantity=1,unit_price=100)]).status_code==409
    r=api.get('/evidence/records/'+rid+'/reconciliation').json()
    assert not r['source_changed'] and r['comparison_at_link']['line_comparison']['full_source_coverage']
    with main.conn() as c:
        row=c.execute('SELECT * FROM evidence_lines_v66 WHERE record_id=? LIMIT 1',(rid,)).fetchone()
        with pytest.raises(sqlite3.IntegrityError):
            c.execute('UPDATE evidence_lines_v66 SET quantity=99 WHERE id=?',(row['id'],))
        with pytest.raises(sqlite3.IntegrityError):
            c.execute('DELETE FROM evidence_lines_v66 WHERE id=?',(row['id'],))


def test_partial_delivery_and_missing_line_requires_reason(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    assert confirm(api,rid,[dict(name='부품 A',quantity=1,unit_price=101)]).status_code==201
    d=source_candidate(api,rid,q['id'])
    issues={i['field'] for i in d['issues']}
    assert 'partial_quantity' in issues and 'missing_source_line' in issues
    assert d['line_comparison']['full_source_coverage'] is False
    assert link(api,rid,d).status_code==422
    assert link(api,rid,d,reason='일부 물품만 먼저 납품되어 수량이 다름').status_code==201
    assert api.get('/evidence/reconciliation/queue').json()['linked_with_issues']==1


def test_excess_quantity_price_mismatch_and_unrecognized_item(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    lines=[dict(name='부품 A',quantity=20,unit_price=102),dict(name='외부 부품',quantity=2,unit_price=503)]
    assert confirm(api,rid,lines).status_code==201
    d=source_candidate(api,rid,q['id'])
    issues={i['field'] for i in d['issues']}
    assert {'excess_quantity','line_unit_price','unmatched_line','missing_source_line'}<=issues


def test_duplicate_source_name_requires_manual_review(api,quote_payload):
    quote_payload['items']=[dict(name='같은 품목',quantity=2,unit_price=100),
                            dict(name='같은 품목',quantity=1,unit_price=100)]
    q,rid=create_sale(api,quote_payload)
    assert confirm(api,rid,[dict(name='같은 품목',quantity=3,unit_price=100)]).status_code==201
    d=source_candidate(api,rid,q['id'])
    assert 'ambiguous_line' in {i['field'] for i in d['issues']}
    assert d['recommendation']=='manual_review_required'


def test_document_code_unverifiable_not_claimed_as_matched(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    lines=sample_lines();lines[0]['product_code']='SKU-100'
    assert confirm(api,rid,lines).status_code==201
    d=source_candidate(api,rid,q['id'])
    assert 'product_code_unverifiable' in {i['field'] for i in d['issues']}
    assert d['line_comparison']['lines'][0]['product_code_checked'] is False


def test_missing_approval_and_invalid_lines(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    assert confirm(api,rid,sample_lines(),False).status_code==422
    assert confirm(api,rid,[]).status_code==422
    assert confirm(api,rid,[dict(name='A',quantity=True,unit_price=0)]).status_code==422
    assert confirm(api,rid,[dict(name='A',quantity=-2,unit_price=0)]).status_code==422
    assert confirm(api,rid,[dict(name='A',quantity=1,unit_price=10,unexpected='a')]).status_code==422
    assert confirm(api,rid,[dict(name='A\nB',quantity=1,unit_price=0)]).status_code==422
    assert confirm(api,rid,[dict(name='A',quantity=1,unit_price=0)]*41).status_code==422
    assert api.get('/evidence/records/'+rid+'/line-items').json()['confirmed'] is False


def test_source_digest_becomes_stale_after_lines_are_added(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    old=source_candidate(api,rid,q['id'])
    assert confirm(api,rid,sample_lines()).status_code==201
    assert link(api,rid,old).status_code==409
    fresh=source_candidate(api,rid,q['id'])
    assert link(api,rid,fresh).status_code==201


def test_legacy_v65_comparison_digest_is_not_rewritten(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    old=source_candidate(api,rid,q['id'])
    assert 'line_comparison' not in old
    assert link(api,rid,old).status_code==201
    assert api.get('/evidence/records/'+rid+'/reconciliation').json()['source_changed'] is False
    assert confirm(api,rid,sample_lines()).status_code==409


def test_purchase_evidence_cannot_gain_sales_lines(api,quote_payload):
    import io
    from openpyxl import Workbook
    from tests.test_reconciliation_v65 import spreadsheet
    raw=spreadsheet('매입전표','부품판매사',1000,'INVOICE-987')
    p=api.c.post('/api/evidence/preview',files={'file':('purchase.xlsx',raw)},headers=api.auth).json()
    res=api.post('/evidence/preview/'+p['id']+'/confirm',{
        'preview_digest':p['digest'],'record_type':'purchase','document_kind':'purchase_slip',
        'counterparty':'부품판매사','document_date':'2026-10-21',
        'gross_amount':1000,'reference_number':'INVOICE-987','original_checked':True})
    assert res.status_code==201,res.text
    assert confirm(api,res.json()['id'],sample_lines()).status_code==422


def test_tenant_restrictions_and_db_triggers(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    org=api.get('/me').json()['org_id']
    who=api.get('/me').json()['id']
    with main.conn() as c:
        other=c.execute('SELECT id FROM organizations WHERE id!=?',(org,)).fetchone()['id']
        with pytest.raises(sqlite3.IntegrityError):
            c.execute('''INSERT INTO evidence_lines_v66
                (id,org_id,record_id,position,name,product_code,quantity,unit_price,reviewed_by,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)''',
                ('badline',other,rid,0,'A','',1,100,who,main.now()))
    # Log in as tenant B. User B can neither read nor confirm tenant A's lines.
    assert api.login('demo@bada.example').status_code==200
    assert api.get('/evidence/records/'+rid+'/line-items').status_code==404
    assert confirm(api,rid,sample_lines()).status_code==404


def test_no_implicit_payments_inventory_or_invoice_changes(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    before=api.get('/dashboard').json()
    assert confirm(api,rid,sample_lines()).status_code==201
    after=api.get('/dashboard').json()
    assert before['outstanding']==after['outstanding']
    assert before['collected']==after['collected']
    assert before['invoices']==after['invoices']
    with main.conn() as c:
        assert c.execute('SELECT count(*) FROM payments').fetchone()[0]==0
        assert c.execute('SELECT count(*) FROM evidence_lines_v66').fetchone()[0]==2


def test_empty_optional_product_code_allowed(api,quote_payload):
    q,rid=create_sale(api,quote_payload)
    result=confirm(api,rid,[dict(name='부품 A',product_code='',quantity=3,unit_price=101)])
    assert result.status_code==201,result.text
