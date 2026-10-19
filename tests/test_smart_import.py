"""Deterministic document-import contract tests. Never feed real customer records."""
import io
from datetime import date
from concurrent.futures import ThreadPoolExecutor
from openpyxl import Workbook
import pytest
from app.import_engine import extract, DocumentError
from app import main as backend

REVIEW_ROWS=[('산업용 부품 A',12,125000,1500000),('밸브 B',2,25000,50000)]
META=[('문서종류','발주서'),('거래처','신규산업'),('사업자번호','555-77-33333'),('수주일','2026-10-16'),
      ('납기일','2026-11-01'),('과세구분','과세'),('제목','시범 발주'),
      ('공급가액',1550000),('부가세',155000),('총금액',1705000)]

def make_xlsx(changes=None, items=None):
    changes=changes or {}
    wb=Workbook();ws=wb.active
    for i,(k,v) in enumerate(META,1):ws.cell(i,1,k);ws.cell(i,2,changes.get(k,v))
    ws.append(['품목명','수량','단가','금액'])
    for row in (items or REVIEW_ROWS):ws.append(row)
    stream=io.BytesIO();wb.save(stream);return stream.getvalue()

def post_file(api,content,filename='purchase.xlsx'):
    return api.c.post('/api/imports/preview',files={'file':(filename,content)},headers=api.auth)

def approve(api,preview,**kw):
    payload={'preview_digest':preview['digest'],'confirmed_customer':preview['document']['company'],
             'confirmed_order_date':preview['document']['ordered_at'],
             'confirmed_total':preview['document']['money']['total'],'approve':True}
    payload.update(kw)
    return api.post('/imports/'+preview['id']+'/confirm',payload)

def test_extract_xlsx_exact():
    doc=extract('test.xlsx',make_xlsx())
    assert doc['company']=='신규산업'
    assert doc['ordered_at']=='2026-10-16'
    assert doc['due_date']=='2026-11-01'
    assert doc['ordered_quantity']==14
    assert doc['money']=={'subtotal':1550000,'vat':155000,'total':1705000}

@pytest.mark.parametrize('changes,keyword',[({'총금액':1705999},'합계'),({'부가세':150000},'합계'),({'납기일':'2026-10-15'},'납기일'),({'수주일':'2026-02-30'},'수주일'),({'거래처':''},'필수'),({'과세구분':'미정'},'과세')])
def test_invalid_metadata_block(changes,keyword):
    with pytest.raises(DocumentError,match=keyword):extract('invalid.xlsx',make_xlsx(changes))

def test_bad_row_quantity_or_money_rejected():
    for row in [('부품',13,125000,1500000),('부품',12,125000,1500001),('부품',0,1,0),('부품',1,'1.5',2)]:
        with pytest.raises(DocumentError):extract('bad.xlsx',make_xlsx(items=[row]))

def test_formula_blocked():
    wb=Workbook();ws=wb.active
    for i,(k,v) in enumerate(META,1):ws.cell(i,1,k);ws.cell(i,2,v)
    ws.append(['품목명','수량','단가','금액']);ws.append(('부품',3,100,'=B11*C11'))
    stream=io.BytesIO();wb.save(stream)
    with pytest.raises(DocumentError,match='계산식'):extract('form.xlsx',stream.getvalue())

def test_multiple_sheets_blocked():
    wb=Workbook();wb.create_sheet('extra');buf=io.BytesIO();wb.save(buf)
    with pytest.raises(DocumentError,match='여러 개'):extract('multi.xlsx',buf.getvalue())

def test_pdf_header_and_table():
    # A real, selectable-text PDF with a ruled product table; image-only PDF is rejected.
    from reportlab.pdfgen import canvas
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    pdfmetrics.registerFont(TTFont('NanumJWSample','/usr/share/fonts/truetype/nanum/NanumGothic.ttf'))
    buffer=io.BytesIO();c=canvas.Canvas(buffer,pagesize=(595,842));c.setFont('NanumJWSample',11)
    for i,(k,v) in enumerate(META):c.drawString(40,800-i*22,f'{k}: {v}')
    start=555;widths=[40,270,350,430,540];
    for x in widths:c.line(x,start,x,start-75)
    for y in [start,start-25,start-50,start-75]:c.line(40,y,540,y)
    for row_idx,row in enumerate([('품목명','수량','단가','금액'),('산업용 부품 A','12','125000','1500000'),('밸브 B','2','25000','50000')]):
        for j,value in enumerate(row):c.drawString(widths[j]+5,start-18-row_idx*25,str(value))
    c.save();data=buffer.getvalue()
    result=extract('order.pdf',data)
    assert result['ordered_quantity']==14 and result['money']['total']==1705000


def test_scanned_pdf_fails():
    with pytest.raises(DocumentError):extract('empty.pdf',b'%PDF-not-valid')

def test_preview_does_not_mutate_records_and_confirmation_is_atomic(api):
    before_customers=len(api.get('/customers').json());before_orders=len(api.get('/orders').json());before_quotes=len(api.get('/quotes').json())
    p=post_file(api,make_xlsx());assert p.status_code==201,p.text;p=p.json()
    assert p['customer_status']=='new'
    assert len(api.get('/customers').json())==before_customers
    assert len(api.get('/orders').json())==before_orders
    assert len(api.get('/quotes').json())==before_quotes
    wrong=approve(api,p,confirmed_total=1705001)
    assert wrong.status_code==409
    assert len(api.get('/orders').json())==before_orders
    done=approve(api,p);assert done.status_code==201,done.text
    o=done.json()['order']
    assert o['order_date']=='2026-10-16'
    assert o['due_date']=='2026-11-01'
    assert o['money']['total']==1705000
    assert o['review_state']=='clean'
    assert [x['quantity'] for x in o['items']]==[12,2]
    assert len(api.get('/customers').json())==before_customers+1
    assert len(api.get('/orders').json())==before_orders+1
    assert len(api.get('/quotes').json())==before_quotes+1
    assert approve(api,p).status_code==409
    assert post_file(api,make_xlsx()).status_code==409

def test_aggregate_by_company_and_order_date(api):
    p=post_file(api,make_xlsx()).json();approve(api,p)
    a=api.get('/order-analytics').json()
    assert a['totals']=={'order_count':1,'ordered_quantity':14,'subtotal':1550000,'vat':155000,'total':1705000}
    assert a['companies'][0]['company']=='신규산업'
    b=api.get('/order-analytics?start_date=2026-10-17&end_date=2026-11-01').json()
    assert b['totals']['order_count']==0
    assert api.get('/order-analytics?start_date=2026-11-01&end_date=2026-10-01').status_code==400

def test_cross_company_cannot_see_or_approve(api,client):
    p=post_file(api,make_xlsx()).json()
    other=client.post('/api/login',json={'email':'demo@bada.example','password':'Demo!2026secure'}).json()
    from fastapi.testclient import TestClient
    # Headers with the other company's session must not read or confirm the first company's staging record.
    othercookie=client.cookies.get(backend.SESSION_COOKIE)
    headers={'Cookie':backend.SESSION_COOKIE+'='+othercookie,'X-CSRF-Token':other['csrf_token']}
    assert client.get('/api/imports/'+p['id'],headers=headers).status_code==404
    payload={'preview_digest':p['digest'],'confirmed_customer':p['document']['company'],
             'confirmed_order_date':p['document']['ordered_at'],
             'confirmed_total':p['document']['money']['total'],'approve':True}
    assert client.post('/api/imports/'+p['id']+'/confirm',headers=headers,json=payload).status_code==404
    assert api.get('/orders').status_code==200

def test_security_rejects_without_csrf(api):
    response=api.c.post('/api/imports/preview',files={'file':('order.xlsx',make_xlsx())},
                        headers={'Cookie':api.auth['Cookie']})
    assert response.status_code==403

def test_invalid_document_never_saved(api):
    before=api.get('/orders').json()
    bad=post_file(api,make_xlsx({'총금액':123}))
    assert bad.status_code==422
    assert api.get('/orders').json()==before

def test_wrong_company_number_conflict_blocks(api):
    original=api.post('/customers',{'name':'신규산업','business_number':'different','contact_name':'','phone':'','email':''})
    assert original.status_code==201
    result=post_file(api,make_xlsx())
    assert result.status_code==409

def test_import_customer_reuse_existing(api):
    assert api.post('/customers',{'name':'신규산업','business_number':'555-77-33333','contact_name':'','phone':'','email':''}).status_code==201
    before=len(api.get('/customers').json())
    p=post_file(api,make_xlsx()).json()
    assert p['customer_status']=='existing'
    assert approve(api,p).status_code==201
    assert len(api.get('/customers').json())==before

def test_invalid_type_content_and_size(api):
    assert post_file(api,b'<html>fake</html>','bad.pdf').status_code==422
    assert post_file(api,b'not xlsx','order.xlsx').status_code==422
    assert post_file(api,b'A'* (5*1024*1024+1)).status_code==422
    assert post_file(api,b'hello','order.xls').status_code==422


def test_reject_wrong_document_kind():
    with pytest.raises(DocumentError,match='발주서'):
        extract('wrong.xlsx',make_xlsx({'문서종류':'세금계산서'}))

def test_reject_customer_with_missing_tax_id(api):
    assert api.post('/customers',{'name':'신규산업','business_number':'','contact_name':'','phone':'','email':''}).status_code==201
    assert post_file(api,make_xlsx()).status_code==409


def make_extended_xlsx(extra=None, include_units=True):
    """Synthetic extended purchase order; no customer production data."""
    wb=Workbook();ws=wb.active
    attrs=META + list((extra or {'발주번호':'PO-2026-0041', '프로젝트명':'테스트 설비', '납품장소':'가상 창고',
                                   '담당자':'시험 담당', '결제조건':'검수 후 30일', '비고':'긴급 처리 아님', '통화':'KRW'}).items())
    for i,(k,v) in enumerate(attrs,1):ws.cell(i,1,k);ws.cell(i,2,v)
    if include_units:
        ws.append(['품목명','품목코드','규격','수량','단위','단가','금액'])
        ws.append(['산업용 부품 A','SKU-A','10mm',12,'개',125000,1500000])
        ws.append(['밸브 B','SKU-B','20mm',2,'박스',25000,50000])
    else:
        ws.append(['품목명','수량','단가','금액']);ws.append(['산업용 부품 A',12,125000,1500000]);ws.append(['밸브 B',2,25000,50000])
    buf=io.BytesIO();wb.save(buf);return buf.getvalue()


def test_extended_fields_and_quantity_units_are_extracted():
    d=extract('extended.xlsx',make_extended_xlsx())
    assert d['additional_fields']=={'reference_number':'PO-2026-0041','project_name':'테스트 설비',
      'delivery_address':'가상 창고','buyer_contact':'시험 담당','payment_terms':'검수 후 30일','remarks':'긴급 처리 아님'}
    assert d['quantity_by_unit']=={'개':12,'박스':2}
    assert d['items'][0]['sku']=='SKU-A' and d['items'][1]['spec']=='20mm'
    assert d['money']['total']==1705000


def test_extended_fields_survive_confirmation_and_are_aggregated(api):
    p=post_file(api,make_extended_xlsx()).json()
    assert p['document']['quantity_by_unit']=={'개':12,'박스':2}
    result=approve(api,p)
    assert result.status_code==201,result.text
    order=result.json()['order']
    assert order['import_source']['additional_fields']['project_name']=='테스트 설비'
    assert order['import_source']['source_items'][0]['sku']=='SKU-A'
    api_data=api.get('/orders/'+order['id']).json()
    assert api_data['import_source']['quantity_by_unit']=={'개':12,'박스':2}
    stats=api.get('/order-analytics').json()
    assert stats['quantity_by_unit']=={'개':12,'박스':2}
    assert stats['by_date'][0]['date']=='2026-10-16'
    assert sum(x['subtotal'] for x in stats['by_item'])==1550000
    assert stats['totals']['total']==1705000


def test_unknown_source_field_fails_closed():
    with pytest.raises(DocumentError,match='지원하지 않는 추가 항목'):
        extract('unknown.xlsx',make_extended_xlsx(extra={'보증기간':'3년'}))


def test_foreign_currency_is_not_assumed_krw():
    with pytest.raises(DocumentError,match='원화'):
        extract('usd.xlsx',make_extended_xlsx(extra={'통화':'USD'}))


def test_missing_unit_is_not_fabricated_as_ea():
    d=extract('no_units.xlsx',make_extended_xlsx(include_units=False))
    assert d['quantity_by_unit']=={'단위 미기재':14}
    assert all(not x['unit'] for x in d['items'])


def test_unknown_line_after_total_is_blocked():
    wb=Workbook();ws=wb.active
    for i,(k,v) in enumerate(META,1):ws.cell(i,1,k);ws.cell(i,2,v)
    ws.append(['품목명','수량','단가','금액']);ws.append(['산업용 부품 A',12,125000,1500000]);ws.append(['밸브 B',2,25000,50000]);ws.append(['합계',None,None,1550000]);ws.append(['추가 부품',1,0,0])
    buf=io.BytesIO();wb.save(buf)
    with pytest.raises(DocumentError,match='합계 행 뒤'):
        extract('trailing.xlsx',buf.getvalue())


def test_hidden_data_rows_are_not_ignored():
    wb=Workbook();ws=wb.active
    for i,(k,v) in enumerate(META,1):ws.cell(i,1,k);ws.cell(i,2,v)
    ws.append(['품목명','수량','단가','금액']);ws.append(['산업용 부품 A',12,125000,1500000]);ws.append(['밸브 B',2,25000,50000]);ws.row_dimensions[ws.max_row].hidden=True
    buf=io.BytesIO();wb.save(buf)
    with pytest.raises(DocumentError,match='숨겨진 행'):
        extract('hidden.xlsx',buf.getvalue())


def test_blank_row_between_items_is_rejected():
    wb=Workbook();ws=wb.active
    for i,(k,v) in enumerate(META,1):ws.cell(i,1,k);ws.cell(i,2,v)
    ws.append(['품목명','수량','단가','금액']);ws.append(['산업용 부품 A',12,125000,1500000]);ws.append([None,None,None,None]);ws.append(['밸브 B',2,25000,50000])
    buf=io.BytesIO();wb.save(buf)
    with pytest.raises(DocumentError,match='빈 행'):
        extract('row_gap.xlsx',buf.getvalue())


def test_cancelled_import_is_excluded_from_analytics(api):
    p=post_file(api,make_extended_xlsx()).json();done=approve(api,p)
    assert done.status_code==201
    order=done.json()['order']
    cancelled=api.post('/orders/'+order['id']+'/status',{'status':'cancelled'})
    assert cancelled.status_code==200,cancelled.text
    stats=api.get('/order-analytics').json()
    assert stats['totals']['order_count']==0 and stats['quantity_by_unit']=={}


def test_mismatching_confirmation_does_not_save_extra_fields(api):
    p=post_file(api,make_extended_xlsx()).json()
    failed=approve(api,p,confirmed_customer='다른회사')
    assert failed.status_code==409
    assert all(o.get('source_import_id')!=p['id'] for o in api.get('/orders').json())
    assert approve(api,p).status_code==201


def test_invalid_comma_as_decimal_does_not_become_wrong_quantity():
    # A malformed 1,5 must NEVER silently become quantity=15.
    with pytest.raises(DocumentError, match='쉼표'):
        extract('bad_grouping.xlsx',make_xlsx(items=[('부품', '1,5', 100, 1500)]))


def test_valid_thousands_separator_yields_same_exact_krw():
    doc=extract('grouping.xlsx',make_xlsx(changes={'공급가액':'1,550,000','부가세':'155,000','총금액':'1,705,000'},
                                         items=[('부품 A','12','125,000','1,500,000'),('부품 B','2','25,000','50,000')]))
    assert doc['money']['total']==1705000


def test_extra_row_named_like_metadata_is_still_an_item():
    # Item name '거래처' must not be silently skipped by the parser.
    doc=extract('named_like_meta.xlsx',make_xlsx(changes={'공급가액':0,'부가세':0,'총금액':0}, items=[('거래처',1,0,0)]))
    assert len(doc['items'])==1 and doc['items'][0]['name']=='거래처'


def test_shipped_pdf_and_xlsx_samples_identical():
    from pathlib import Path
    folder=Path(__file__).resolve().parents[1]/'samples'
    a=extract('sample.xlsx',(folder/'SAMPLE-ORDER-IMPORT.xlsx').read_bytes())
    b=extract('sample.pdf',(folder/'SAMPLE-ORDER-IMPORT.pdf').read_bytes())
    for field in ('company','business_number','ordered_at','due_date','vat_mode','currency','items','money','quantity_by_unit','additional_fields'):
        assert a[field]==b[field],field


def test_200_randomized_integer_money_calculations_and_tamper_block():
    """For accepted template values, all arithmetic must be exact, not floating point."""
    import random
    from app.import_engine import verify
    rng=random.Random(20261018)
    for _ in range(200):
        qty=rng.randint(1,100000)
        price=rng.randint(0,1000000000)
        subtotal=qty*price
        vat=(subtotal+5)//10
        row={'name':'가상 품목','quantity':qty,'unit_price':price,'line_total':subtotal}
        metadata={'document_kind':'발주서','company':'가상 회사','ordered_at':'2026-10-18','due_date':'2026-11-01',
                  'vat_mode':'과세','subtotal':subtotal,'vat':vat,'total':subtotal+vat}
        d=verify(metadata,[row]);assert d['money']=={'subtotal':subtotal,'vat':vat,'total':subtotal+vat}
        altered=metadata.copy();altered['total']+=1
        with pytest.raises(DocumentError):verify(altered,[row])
