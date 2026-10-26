"""Quotations are independent evidence; no artificial order or payment approval."""
import io
from openpyxl import Workbook
import pytest
from app.import_engine import extract, DocumentError
from tests.test_smart_import import make_xlsx as make_order
from app import main as backend

ITEMS=[('유압 펌프',3,45000,135000),('조립 부품',2,12500,25000)]
FIELDS=[('문서종류','견적서'),('거래처','신규견적사'),('사업자번호','222-33-44444'),
        ('견적일','2026-10-18'),('견적번호','QT-123'),('과세구분','과세'),
        ('제목','시험용 외부 견적'),('공급가액',160000),('부가세',16000),('총금액',176000)]

def qxlsx(changes=None, *, items=None):
    wb=Workbook();ws=wb.active;changes=changes or {}
    for i,(k,v) in enumerate(FIELDS,1):ws.cell(i,1,k);ws.cell(i,2,changes.get(k,v))
    ws.append(['품목명','수량','단가','금액'])
    for x in items or ITEMS: ws.append(x)
    buf=io.BytesIO();wb.save(buf);return buf.getvalue()

def post_file(api,body=None):
    return api.c.post('/api/imports/preview',files={'file':('quote.xlsx',body if body is not None else qxlsx())},headers=api.auth)

def confirm(api,p,**changes):
    data={'preview_digest':p['digest'],'confirmed_customer':p['document']['company'],
          'confirmed_quote_date':p['document']['quote_date'],
          'confirmed_total':p['document']['money']['total'],'approve':True}
    data.update(changes)
    return api.post('/imports/'+p['id']+'/confirm',data)

def test_quote_extract_exact_fields_and_date():
    doc=extract('quote.xlsx',qxlsx())
    assert doc['record_type']=='quote' and doc['quote_date']=='2026-10-18'
    assert doc['ordered_at'] is None and doc['due_date'] is None
    assert doc['additional_fields']['reference_number']=='QT-123'
    assert doc['money']=={'subtotal':160000,'vat':16000,'total':176000}

def test_quote_never_auto_creates_order_or_accepted_quote(api):
    before={key:len(api.get('/'+key).json()) for key in ('customers','quotes','orders','invoices')}
    p=post_file(api);assert p.status_code==201,p.text;p=p.json()
    assert p['ready_to_confirm'] and p['document']['record_type']=='quote'
    for key in before:assert len(api.get('/'+key).json())==before[key],key
    wrong=confirm(api,p,confirmed_total=176001);assert wrong.status_code==409
    good=confirm(api,p);assert good.status_code==201,good.text
    data=good.json();assert data['record_type']=='quote' and data['quote']['status']=='draft'
    assert data['quote']['quote_date']=='2026-10-18'
    assert data['quote']['money']['total']==176000
    assert data['quote']['source_import_id']==p['id']
    assert len(api.get('/quotes').json())==before['quotes']+1
    assert len(api.get('/customers').json())==before['customers']+1
    assert len(api.get('/orders').json())==before['orders']
    assert len(api.get('/invoices').json())==before['invoices']
    assert api.get('/dashboard').json()['collected']==0
    assert confirm(api,p).status_code==409
    assert post_file(api).status_code==409

def test_quote_duplicate_reference_changed_bytes_fails(api):
    p=post_file(api).json();assert confirm(api,p).status_code==201
    modified=qxlsx({'제목':'별도 내용이나 같은 견적번호'})
    p2=post_file(api,modified);assert p2.status_code==201,p2.text
    assert confirm(api,p2.json()).status_code==409
    assert len(api.get('/quotes').json())==2  # one demo quote + first imported quote

def test_bad_quote_tax_math_and_unknown_type_block(api):
    for bad in [qxlsx({'총금액':177000}),qxlsx({'과세구분':'불명'}),
                qxlsx({'견적일':'2026-02-30'}),qxlsx({'문서종류':'청구서'})]:
        assert post_file(api,bad).status_code==422
    assert len(api.get('/quotes').json())==1

def test_quote_missing_company_and_date_requires_supplement(api):
    p=post_file(api,qxlsx({'거래처':'','견적일':''}));assert p.status_code==201,p.text
    p=p.json();assert sorted(p['document']['missing_fields'])==['company','quote_date']
    assert confirm(api,p,confirmed_customer='신규견적사',confirmed_quote_date='2026-10-18').status_code==409
    r=api.c.patch('/api/imports/'+p['id']+'/supplement',json={'preview_digest':p['digest'],
                       'fields':{'company':'신규견적사','quote_date':'2026-10-18'}},headers=api.auth)
    assert r.status_code==200,r.text
    ready=r.json();assert ready['ready_to_confirm']
    assert confirm(api,p,confirmed_customer='신규견적사',confirmed_quote_date='2026-10-18').status_code==409
    assert confirm(api,ready).status_code==201

def test_quote_never_silent_override_source_amount(api):
    p=post_file(api,qxlsx({'거래처':''})).json()
    response=api.c.patch('/api/imports/'+p['id']+'/supplement',json={
        'preview_digest':p['digest'],'fields':{'company':'보완기업','subtotal':'1'}},headers=api.auth)
    assert response.status_code==422

def test_quote_wrong_date_not_accepted(api):
    p=post_file(api).json()
    assert confirm(api,p,confirmed_quote_date='2026-10-19').status_code==409
    assert confirm(api,p,confirmed_order_date='2026-10-18',confirmed_quote_date=None).status_code==409

def test_quote_cross_tenant_no_preview_or_confirm(api,client):
    p=post_file(api).json()
    login=client.post('/api/login',json={'email':'demo@bada.example','password':'Demo!2026secure'});assert login.status_code==200
    other={'X-CSRF-Token':login.json()['csrf_token'],'Cookie':backend.SESSION_COOKIE+'='+login.cookies.get(backend.SESSION_COOKIE)}
    assert client.get('/api/imports/'+p['id'],headers=other).status_code==404
    assert client.post('/api/imports/'+p['id']+'/confirm',headers=other,json={'preview_digest':p['digest'],
        'confirmed_customer':'신규견적사','confirmed_quote_date':'2026-10-18',
        'confirmed_total':176000,'approve':True}).status_code==404

def test_quote_no_csrf(api):
    assert api.c.post('/api/imports/preview',files={'file':('quote.xlsx',qxlsx())},
        headers={'Cookie':api.auth['Cookie']}).status_code==403

def test_existing_order_import_still_works(api):
    r=post_file(api,make_order());assert r.status_code==201,r.text
    p=r.json();assert p['document']['record_type']=='order'
    conf=api.post('/imports/'+p['id']+'/confirm',{
        'preview_digest':p['digest'],'confirmed_customer':p['document']['company'],
        'confirmed_order_date':p['document']['ordered_at'],
        'confirmed_total':p['document']['money']['total'],'approve':True})
    assert conf.status_code==201,conf.text
    assert conf.json()['order']['status']=='received'

def test_quote_pdf_selectable_text_identical_to_excel():
    from reportlab.pdfgen import canvas
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from pathlib import Path
    font=Path('/usr/share/fonts/truetype/nanum/NanumGothic.ttf')
    if not font.exists():pytest.skip('Korean font for fixture unavailable')
    pdfmetrics.registerFont(TTFont('JwQuote',str(font)))
    buf=io.BytesIO();c=canvas.Canvas(buf,pagesize=(595,842));c.setFont('JwQuote',11)
    for i,(k,v) in enumerate(FIELDS):c.drawString(40,800-i*22,f'{k}: {v}')
    widths=[40,270,350,430,540];start=555
    for x in widths:c.line(x,start,x,start-75)
    for y in [start,start-25,start-50,start-75]:c.line(40,y,540,y)
    for ri,row in enumerate([('품목명','수량','단가','금액'),*ITEMS]):
        for j,v in enumerate(row):c.drawString(widths[j]+5,start-18-ri*25,str(v))
    c.save()
    pdf=extract('quote.pdf',buf.getvalue());xlsx=extract('quote.xlsx',qxlsx())
    assert pdf['record_type']==xlsx['record_type']=='quote'
    assert pdf['items']==xlsx['items'] and pdf['money']==xlsx['money']
    assert pdf['quote_date']==xlsx['quote_date']

@pytest.mark.parametrize('fields',[
    {'문서종류':'견적서','수주일':'2026-10-16','견적일':'2026-10-18'},
    {'문서종류':'발주서','견적일':'2026-10-18'},
    {'견적일':'2026-10-18','견적유효일':'2026-10-17'},
])
def test_conflicting_dates_and_invalid_validity_block(fields):
    base=dict(FIELDS)
    base.update(fields)
    from openpyxl import Workbook
    wb=Workbook();ws=wb.active
    for idx,(key,val) in enumerate(base.items(),1):ws.cell(idx,1,key);ws.cell(idx,2,val)
    ws.append(['품목명','수량','단가','금액'])
    for item in ITEMS:ws.append(item)
    buf=io.BytesIO();wb.save(buf)
    with pytest.raises(DocumentError):extract('quote.xlsx',buf.getvalue())


def test_validity_and_extra_fields_preserved():
    wb=Workbook();ws=wb.active
    data=[*FIELDS,('견적유효일','2026-11-17'),('프로젝트명','창고 정비'),('결제조건','납품후 30일')]
    for idx,(key,val) in enumerate(data,1):ws.cell(idx,1,key);ws.cell(idx,2,val)
    ws.append(['품목명','수량','단가','금액'])
    for item in ITEMS:ws.append(item)
    buf=io.BytesIO();wb.save(buf)
    doc=extract('quotation.xlsx',buf.getvalue())
    assert doc['additional_fields']['valid_until']=='2026-11-17'
    assert doc['additional_fields']['project_name']=='창고 정비'


def test_legacy_quote_insert_and_upgrade(tmp_path,monkeypatch):
    """A previous 10-column quote table must survive V1.6 without rewriting rows."""
    import sqlite3
    db=tmp_path/'legacy.db'
    conn=sqlite3.connect(db)
    # Create V1.5 schema manually (before new fields exist).
    conn.executescript(backend.SCHEMA)
    conn.execute('INSERT INTO organizations VALUES(?,?,?)',('org','옛회사',backend.now()))
    conn.execute('INSERT INTO customers VALUES(?,?,?,?,?,?,?,?)',('cust','org','옛고객','','','','',backend.now()))
    conn.execute('INSERT INTO quotes VALUES(?,?,?,?,?,?,?,?,?,?)',
                 ('quote','org','cust','옛고객','Q-OLD','이전 견적','draft','taxable',backend.now(),backend.now()))
    conn.commit();conn.close()
    monkeypatch.setattr(backend,'DB_PATH',db)
    monkeypatch.delenv('DEMO_SEED',raising=False)
    backend.init_db();backend.init_db()
    with backend.conn() as c:
        row=c.execute('SELECT * FROM quotes WHERE id=?',('quote',)).fetchone()
        assert row['title']=='이전 견적' and row['quote_date'] is None
        assert row['source_import_id'] is None
        assert 'quote_id' in {x['name'] for x in c.execute('PRAGMA table_info(import_previews)')}

def test_quote_delivery_date_preserved_as_source_fact():
    from openpyxl import Workbook
    wb=Workbook();ws=wb.active
    for idx,(k,v) in enumerate([*FIELDS,('납기일','2026-12-01')],1):
        ws.cell(idx,1,k);ws.cell(idx,2,v)
    ws.append(['품목명','수량','단가','금액'])
    for item in ITEMS:ws.append(item)
    buf=io.BytesIO();wb.save(buf)
    doc=extract('quote.xlsx',buf.getvalue())
    assert doc['additional_fields']['expected_delivery_date']=='2026-12-01'
    assert doc['due_date'] is None  # Never turn a quotation lead time into a purchase-order due date.

def test_no_reference_similar_quote_changed_title_still_blocks(api):
    def build(title):
        wb=Workbook();ws=wb.active
        for idx,(k,v) in enumerate([(k,(title if k=='제목' else v)) for k,v in FIELDS if k!='견적번호'],1):
            ws.cell(idx,1,k);ws.cell(idx,2,v)
        ws.append(['품목명','수량','단가','금액'])
        for x in ITEMS:ws.append(x)
        buf=io.BytesIO();wb.save(buf);return buf.getvalue()
    first=post_file(api,build('별도 견적명')).json()
    assert confirm(api,first).status_code==201
    second=post_file(api,build('변경된 견적명')).json()
    assert confirm(api,second).status_code==409
    assert len(api.get('/quotes').json())==2

def test_quote_optional_delivery_date_survives_missing_company_supplement(api):
    wb=Workbook();ws=wb.active
    for idx,(k,v) in enumerate([*[(k,('' if k=='거래처' else v)) for k,v in FIELDS],('납기일','2026-12-01')],1):
        ws.cell(idx,1,k);ws.cell(idx,2,v)
    ws.append(['품목명','수량','단가','금액'])
    for item in ITEMS:ws.append(item)
    buf=io.BytesIO();wb.save(buf)
    p=post_file(api,buf.getvalue()).json()
    assert p['document']['additional_fields']['expected_delivery_date']=='2026-12-01'
    supplement=api.c.patch('/api/imports/'+p['id']+'/supplement',json={'preview_digest':p['digest'],'fields':{'company':'보완고객'}},headers=api.auth)
    assert supplement.status_code==200,supplement.text
    doc=supplement.json()['document']
    assert doc['additional_fields']['expected_delivery_date']=='2026-12-01'
    assert confirm(api,supplement.json()).status_code==201

def test_quote_pdf_upload_to_backend_confirmation(api):
    from reportlab.pdfgen import canvas
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from pathlib import Path
    font=Path('/usr/share/fonts/truetype/nanum/NanumGothic.ttf')
    if not font.exists():pytest.skip('Fixture font unavailable')
    pdfmetrics.registerFont(TTFont('QuoteServerFixture',str(font)))
    buf=io.BytesIO();c=canvas.Canvas(buf,pagesize=(595,842));c.setFont('QuoteServerFixture',11)
    for idx,(k,v) in enumerate(FIELDS):c.drawString(40,800-idx*22,f'{k}: {v}')
    bounds=[40,270,350,430,540];y=555
    for x in bounds:c.line(x,y,x,y-75)
    for yrow in [y,y-25,y-50,y-75]:c.line(40,yrow,540,yrow)
    for ri,row in enumerate([('품목명','수량','단가','금액'),*ITEMS]):
        for j,v in enumerate(row):c.drawString(bounds[j]+5,y-18-ri*25,str(v))
    c.save()
    result=api.c.post('/api/imports/preview',files={'file':('external_quote.pdf',buf.getvalue(),'application/pdf')},headers=api.auth)
    assert result.status_code==201,result.text
    doc=result.json()
    assert doc['document']['record_type']=='quote'
    assert not api.get('/orders').json()
    confirmed=confirm(api,doc)
    assert confirmed.status_code==201,confirmed.text
    assert confirmed.json()['quote']['status']=='draft'
    assert not api.get('/orders').json()
