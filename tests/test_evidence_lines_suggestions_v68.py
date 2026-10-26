"""XLSX explicit item-table candidate extraction (never automatic approval)."""
import io
from openpyxl import Workbook
from app.evidence_v64_worker import extract


def raw_workbook(lines, headings=('품목명','수량','단가','금액')):
    wb=Workbook();ws=wb.active
    for k,v in [('문서종류','매출전표'),('거래처','미래부품'),('거래일','2026-10-21'),('총금액',1100),('문서번호','CASE-0001')]:
        ws.append([k,v])
    ws.append(list(headings))
    for x in lines:ws.append(x)
    b=io.BytesIO();wb.save(b);return b.getvalue()


def test_two_lines_extract_with_explicit_warning():
    raw=raw_workbook([['부품 A',2,100,200],['부품 B',3,200,600],['합계','','',800]])
    result=extract('slip.xlsx',raw)
    assert len(result['suggested_lines'])==2
    assert result['suggested_lines'][0]=={'name':'부품 A','product_code':'','quantity':2,'unit_price':100}
    assert result['suggested_lines_source']=='xlsx_table_unverified'
    assert any('자동 확정되지' in x for x in result['warnings'])


def test_conflicting_row_amount_disables_all_suggestions():
    result=extract('slip.xlsx',raw_workbook([['A',2,101,202],['B',1,200,199]]))
    assert result['suggested_lines']==[]
    assert any('일치하지' in x for x in result['warnings'])


def test_bad_quantity_price_or_overlong_table_is_discarded():
    for rows in [[['A','unknown',101,202]],[['A',1,-100,-100]],
                 [[f'item-{i}',1,10,10] for i in range(41)]]:
        result=extract('slip.xlsx',raw_workbook(rows))
        assert result['suggested_lines']==[]


def test_ambiguous_header_does_not_guess():
    b=raw_workbook([['A',1,100,100]],headings=('품목','품목명','수량','단가'))
    result=extract('slip.xlsx',b)
    assert result['suggested_lines']==[]


def test_preview_exposes_candidates_but_record_requires_explicit_approval(api):
    raw=raw_workbook([['A',1,100,100]])
    r=api.c.post('/api/evidence/preview',files={'file':('slip.xlsx',raw)},headers=api.auth)
    assert r.status_code==201,r.text
    doc=r.json()['document']
    assert doc['suggested_lines']==[{'name':'A','product_code':'','quantity':1,'unit_price':100}]
    assert api.get('/evidence/records').json()==[]
    assert api.get('/evidence/reconciliation/queue').json()['items']==[]
    confirmed=api.post('/evidence/preview/'+r.json()['id']+'/confirm',{
        'preview_digest':r.json()['digest'],'record_type':'sales','document_kind':'sales_slip',
        'counterparty':'미래부품','document_date':'2026-10-21',
        'gross_amount':1100,'reference_number':'CASE-0001','original_checked':True})
    assert confirmed.status_code==201,confirmed.text
    rid=confirmed.json()['id']
    hints=api.get('/evidence/records/'+rid+'/line-suggestions')
    assert hints.status_code==200,hints.text
    assert hints.json()['lines']==doc['suggested_lines'] and not hints.json()['automatic_approval']
    assert api.get('/evidence/records/'+rid+'/line-items').json()['confirmed'] is False

