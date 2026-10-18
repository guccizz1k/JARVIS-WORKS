"""v1.4 missing metadata only; all source financial figures remain server-verified."""
from __future__ import annotations
import io
import pytest
from openpyxl import Workbook
from app.import_engine import extract, supplement_review, DocumentError
from tests.test_smart_import import make_xlsx, META, post_file, approve
from app import main as backend


def patch(api, preview, **fields):
    return api.c.patch('/api/imports/'+preview['id']+'/supplement',json={
        'preview_digest':preview['digest'], 'fields':fields},headers=api.auth)


def test_missing_company_creates_preview_not_order(api):
    before_orders=len(api.get('/orders').json())
    p=post_file(api,make_xlsx({'거래처':''}))
    assert p.status_code==201,p.text
    p=p.json()
    assert p['document']['missing_fields']==['company']
    assert p['ready_to_confirm'] is False
    assert len(api.get('/orders').json())==before_orders
    assert approve(api,p).status_code in (409,422)
    resp=patch(api,p,company='신규산업');assert resp.status_code==200,resp.text
    updated=resp.json()
    assert updated['document']['missing_fields']==[]
    assert updated['document']['user_filled_fields']==['company']
    assert updated['ready_to_confirm'] is True
    assert updated['digest']!=p['digest']
    assert approve(api,p).status_code in (409,422)
    assert len(api.get('/orders').json())==before_orders
    assert approve(api,updated).status_code==201
    assert len(api.get('/orders').json())==before_orders+1


def test_dates_can_be_filled_separately_and_rechecked(api):
    p=post_file(api,make_xlsx({'수주일':'','납기일':''})).json()
    assert set(p['document']['missing_fields'])=={'ordered_at','due_date'}
    response=patch(api,p,ordered_at='2026-10-16')
    assert response.status_code==200,response.text
    r=response.json(); assert r['document']['missing_fields']==['due_date']
    assert approve(api,r).status_code in (409,422)
    invalid=patch(api,r,due_date='2026-10-10'); assert invalid.status_code==422
    r2=patch(api,r,due_date='2026-11-01')
    assert r2.status_code==200,r2.text
    final=r2.json()
    assert final['document']['money']['total']==1705000
    assert approve(api,final).status_code==201
    a=api.get('/order-analytics?start_date=2026-10-16&end_date=2026-10-16').json()
    assert a['totals']['order_count']==1
    assert a['totals']['total']==1705000


def test_extracted_values_not_editable(api):
    p=post_file(api,make_xlsx()).json()
    for field,v in [('company','다른기업'),('ordered_at','2026-10-15'),('due_date','2026-12-01')]:
        assert patch(api,p,**{field:v}).status_code==422
    assert patch(api,p,vat_mode='exempt').status_code==422
    assert patch(api,p,quantity='999999').status_code==422
    assert approve(api,p).status_code==201


def test_supplement_cannot_modify_money_or_items_indirectly(api):
    p=post_file(api,make_xlsx({'거래처':''})).json()
    result=patch(api,p,company='신규산업').json()
    assert result['document']['items']==p['document']['items']
    assert result['document']['money']==p['document']['money']
    assert result['document']['ordered_quantity']==p['document']['ordered_quantity']


def test_stale_digest_rejected(api):
    p=post_file(api,make_xlsx({'거래처':''})).json()
    result=patch(api,p,company='신규산업').json()
    assert patch(api,p,company='다른산업').status_code==409
    assert api.post('/imports/'+p['id']+'/confirm', {'preview_digest':p['digest'],'confirmed_customer':'신규산업','confirmed_order_date':'2026-10-16','confirmed_total':1705000,'approve':True}).status_code==409
    assert approve(api,result).status_code==201
    assert patch(api,result,company='다른산업').status_code==409


def test_source_missing_fields_required_at_confirmation(api):
    p=post_file(api,make_xlsx({'거래처':'','수주일':''})).json()
    r=patch(api,p,company='보완기업').json()
    assert approve(api,r).status_code in (409,422)
    assert patch(api,r,ordered_at='날짜미상').status_code==422
    assert len(api.get('/orders').json())==0


def test_incomplete_data_rejected_if_money_wrong(api):
    r=post_file(api,make_xlsx({'거래처':'','총금액':100}));assert r.status_code==422
    assert not api.get('/orders').json()


def test_incomplete_data_rejected_if_wrong_document_kind(api):
    r=post_file(api,make_xlsx({'문서종류':'견적서','거래처':''}));assert r.status_code==422


def test_unknown_excel_mapping_rejected(api):
    wb=Workbook();ws=wb.active
    for i,(k,v) in enumerate(META,1):ws.cell(i,1,k);ws.cell(i,2,v)
    ws['A10']='미확인 계약 특약';ws['B10']='수수료 10%'
    ws.append(['품목명','수량','단가','금액'])
    ws.append(['부품',1,100,100])
    b=io.BytesIO();wb.save(b)
    assert post_file(api,b.getvalue()).status_code==422


def test_additional_aliases_work_without_guessing():
    wb=Workbook();ws=wb.active
    alias={'거래처':'발주회사','수주일':'발주일자','납기일':'납기예정일'}
    for i,(k,v) in enumerate(META,1):ws.cell(i,1,alias.get(k,k));ws.cell(i,2,v)
    ws.append(['제품','요청수량','주문단가','공급금액'])
    for name,qty,price,sub in [('산업용 부품 A',12,125000,1500000),('밸브 B',2,25000,50000)]:
        ws.append([name,qty,price,sub])
    b=io.BytesIO();wb.save(b)
    r=extract('alternate.xlsx',b.getvalue())
    assert r['company']=='신규산업' and r['ordered_at']=='2026-10-16'
    assert r['money']['total']==1705000


def test_company_wrong_number_still_blocked(api):
    p=post_file(api,make_xlsx({'거래처':''})).json()
    r=patch(api,p,company='미래부품')
    assert r.status_code==409


def test_no_csrf_cannot_patch(api):
    p=post_file(api,make_xlsx({'거래처':''})).json()
    r=api.c.patch('/api/imports/'+p['id']+'/supplement',json={
        'preview_digest':p['digest'],'fields':{'company':'신규산업'}},headers={'Cookie':api.auth['Cookie']})
    assert r.status_code==403


def test_preview_other_company_forbidden(api,client):
    p=post_file(api,make_xlsx({'거래처':''})).json()
    other=client.post('/api/login',json={'email':'demo@bada.example','password':'Demo!2026secure'}).json()
    cookie=client.cookies.get(backend.SESSION_COOKIE)
    headers={'Cookie':backend.SESSION_COOKIE+'='+cookie,'X-CSRF-Token':other['csrf_token']}
    r=client.patch('/api/imports/'+p['id']+'/supplement',headers=headers,json={
        'preview_digest':p['digest'],'fields':{'company':'신규산업'}})
    assert r.status_code==404


def test_strict_direct_import_still_rejects_missing():
    with pytest.raises(DocumentError):extract('test.xlsx',make_xlsx({'거래처':''}))


def test_invalid_calendar_day_cannot_be_supplemented(api):
    p=post_file(api,make_xlsx({'납기일':''})).json()
    assert patch(api,p,due_date='2026-02-29').status_code==422


def test_source_extracted_zero_amount_remains_valid():
    result=extract('zero.xlsx',make_xlsx({'공급가액':0,'부가세':0,'총금액':0}, items=[('무료샘플',1,0,0)]),allow_missing=True)
    assert result['money']=={'subtotal':0,'vat':0,'total':0}


def make_reference_document(reference='PO-SAME-001', title='시범 발주'):
    from openpyxl import load_workbook
    wb=load_workbook(io.BytesIO(make_xlsx({'제목':title})))
    ws=wb.active
    ws.insert_rows(10)
    ws['A10']='발주번호';ws['B10']=reference
    out=io.BytesIO();wb.save(out);return out.getvalue()


def test_duplicate_external_po_different_file_is_blocked(api):
    p=post_file(api,make_reference_document()).json()
    assert approve(api,p).status_code==201
    alternate=post_file(api,make_reference_document(title='제목 변경 후 재업로드'))
    assert alternate.status_code==201,alternate.text
    assert approve(api,alternate.json()).status_code==409
    assert len(api.get('/orders').json())==1
    assert api.get('/order-analytics').json()['totals']['order_count']==1


def test_different_po_references_can_be_entered(api):
    p=post_file(api,make_reference_document('PO-001')).json()
    assert approve(api,p).status_code==201
    other=post_file(api,make_reference_document('PO-002')).json()
    assert approve(api,other).status_code==201
    assert api.get('/order-analytics').json()['totals']['order_count']==2


def test_unknown_item_column_cannot_be_silently_discarded():
    wb=Workbook();ws=wb.active
    for k,v in META:ws.append([k,v])
    ws.append(['품목명','수량','단가','금액','할인율'])
    ws.append(['산업용 부품 A',12,125000,1500000,'5%'])
    out=io.BytesIO();wb.save(out)
    with pytest.raises(DocumentError,match='품목 열'):
        extract('unsafe.xlsx',out.getvalue(),allow_missing=True)


def test_same_item_sku_with_different_source_name_is_not_aggregated_as_one(api):
    from openpyxl import load_workbook
    data=make_xlsx()
    wb=load_workbook(io.BytesIO(data));ws=wb.active
    ws.cell(11,5,'품목코드');ws.cell(12,5,'COMMON');ws.cell(13,5,'COMMON')
    out=io.BytesIO();wb.save(out)
    p=post_file(api,out.getvalue()).json()
    assert approve(api,p).status_code==201
    stats=api.get('/order-analytics').json()
    assert len(stats['by_item'])==2
    assert sum(i['ordered_quantity'] for i in stats['by_item'])==14


def test_missing_dates_in_pdf_are_review_only():
    from reportlab.pdfgen import canvas
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    pdfmetrics.registerFont(TTFont('JWCheckPdf','/usr/share/fonts/truetype/nanum/NanumGothic.ttf'))
    b=io.BytesIO();c=canvas.Canvas(b,pagesize=(595,842));c.setFont('JWCheckPdf',11)
    src=[(k,v) for k,v in META if k!='납기일']
    for i,(k,v) in enumerate(src):c.drawString(40,800-i*22,f'{k}: {v}')
    start=555;widths=[40,270,350,430,540]
    for x in widths:c.line(x,start,x,start-75)
    for y in [start,start-25,start-50,start-75]:c.line(40,y,540,y)
    for i,row in enumerate([('품목명','수량','단가','금액'),('산업용 부품 A','12','125000','1500000'),('밸브 B','2','25000','50000')]):
        for j,v in enumerate(row):c.drawString(widths[j]+5,start-18-i*25,str(v))
    c.save()
    r=extract('missing_due.pdf',b.getvalue(),allow_missing=True)
    assert r['missing_fields']==['due_date']
    fixed=supplement_review(r,{'due_date':'2026-11-01'})
    assert fixed['due_date']=='2026-11-01'
    assert fixed['money']['total']==1705000
