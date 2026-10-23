"""V6.4 synthetic documents only, isolated tenants; no production records."""
from __future__ import annotations
import io
from PIL import Image,ImageDraw,ImageFont
from openpyxl import Workbook
import fitz
from app import main

FONT='/usr/share/fonts/truetype/nanum/NanumGothic.ttf'

def xlsx(kind='영수증',company='한국상사',gross=11000, reference='R20260001',date='2026-10-21',additional=None):
 wb=Workbook();w=wb.active
 data=[('문서종류',kind),('거래처',company),('거래일',date),('총금액',gross),('문서번호',reference)]
 if additional:data+=additional
 for x in data:w.append(x)
 buffer=io.BytesIO();wb.save(buffer);return buffer.getvalue()

def png(kind='영수증'):
 im=Image.new('RGB',(1300,550),'white');pen=ImageDraw.Draw(im)
 f=ImageFont.truetype(FONT,46)
 for idx,line in enumerate([f'문서종류: {kind}','거래처: 한국상사','거래일: 2026-10-21','총금액: 11000','문서번호: R20260002']):pen.text((50,30+idx*95),line,fill='black',font=f)
 b=io.BytesIO();im.save(b,format='PNG');return b.getvalue()

def scanpdf():
 doc=fitz.open();page=doc.new_page(width=700,height=350)
 page.insert_image(fitz.Rect(5,5,695,345),stream=png())
 b=doc.tobytes();doc.close();return b

def stage(api,filename,data):
 return api.c.post('/api/evidence/preview',files={'file':(filename,data)},headers=api.auth)

def approve(api,preview,*,type='expense',kind='receipt',amount=11000,reference='R20260001',**kwargs):
 fields={'preview_digest':preview['digest'],'record_type':type,'document_kind':kind,
  'counterparty':'한국상사','document_date':'2026-10-21','gross_amount':amount,
  'reference_number':reference,'sku':'','quantity':None,'unit':'','original_checked':True}
 fields.update(kwargs)
 return api.post('/evidence/preview/'+preview['id']+'/confirm',fields)

def test_receipt_stage_and_expense_approval_does_not_issue_invoice(api):
 baseline=api.get('/dashboard').json()
 res=stage(api,'expense.xlsx',xlsx());assert res.status_code==201,res.text
 p=res.json();assert p['document']['document_kind']=='receipt' and p['original_file_stored'] is False
 assert p['document']['fields']['gross_amount']==11000
 assert api.get('/evidence/dashboard').json()['pending_review']==1
 assert api.get('/dashboard').json()['invoices']==baseline['invoices']
 r=approve(api,p);assert r.status_code==201,r.text
 assert r.json()['accounting_posted'] is False
 d=api.get('/dashboard').json();assert d['evidence']['by_type']['expense']['amount']==11000
 assert d['invoices']==baseline['invoices'] and d['outstanding']==baseline['outstanding']
 assert api.get('/evidence/dashboard').json()['pending_review']==0
 assert len(api.get('/evidence/records').json())==1
 assert approve(api,p).status_code==409
 assert stage(api,'same.xlsx',xlsx()).status_code==409

def test_four_evidence_kinds_and_inventory_snapshot(api):
 scenarios=[('매출전표','sales','sales_slip',11000),('매입전표','purchase','purchase_slip',11000),('재고표','inventory_snapshot','inventory_sheet',None),('거래명세표','purchase','trade_statement',11000)]
 for index,(document,kind,source,total) in enumerate(scenarios):
  more=[('품목코드','A-001'),('재고수량',37)] if kind=='inventory_snapshot' else []
  raw=xlsx(document,reference=f'v64-{index}',additional=more)
  p=stage(api,f'd{index}.xlsx',raw)
  assert p.status_code==201,p.text
  p=p.json()
  r=approve(api,p,type=kind,kind=source,amount=total,reference=f'v64-{index}',
            sku='A-001' if kind=='inventory_snapshot' else '',
            quantity=37 if kind=='inventory_snapshot' else None)
  assert r.status_code==201,r.text
 s=api.get('/evidence/dashboard').json()
 assert s['by_type']['sales']['count']==1
 assert s['by_type']['purchase']['count']==2
 assert s['by_type']['inventory_snapshot']['count']==1
 assert s['by_type']['inventory_snapshot']['amount']==0
 assert api.get('/dashboard').json()['orders']==0

def test_receipt_scan_png_and_pdf_ocr(api):
 for name,data in [('scan.png',png()),('scanned.pdf',scanpdf())]:
  p=stage(api,name,data)
  assert p.status_code==201,p.text
  doc=p.json()['document']
  assert doc['method']=='ocr',doc
  assert 'OCR' in ' '.join(doc['warnings'])
  assert doc['ocr_text_excerpt']
  assert '문서종류' in doc['ocr_text_excerpt'] or '영수증' in doc['ocr_text_excerpt']
  assert api.get('/evidence/dashboard').json()['total_confirmed']==0

def test_invalid_and_oversized_are_fail_closed(api):
 assert stage(api,'file.jpg',b'not jpg').status_code==422
 assert stage(api,'file.pdf',b'%PDF invalid').status_code==422
 assert stage(api,'x.zip',b'PK').status_code==422
 assert stage(api,'empty.png',b'').status_code==413
 assert stage(api,'big.png',b'0'*(5*1024*1024+1)).status_code==413
 assert api.get('/evidence/dashboard').json()['pending_review']==0

def test_tenant_cross_access_and_role_isolation(api):
 first=stage(api,'a.xlsx',xlsx()).json()
 login=api.c.post('/api/login',json={'email':'demo@bada.example','password':'Demo!2026secure'})
 assert login.status_code==200
 cookie=api.c.cookies.get(main.SESSION_COOKIE)
 h={'Cookie':main.SESSION_COOKIE+'='+cookie,'X-CSRF-Token':login.json()['csrf_token']}
 assert api.c.get('/api/evidence/preview/'+first['id'],headers=h).status_code==404
 assert api.c.get('/api/evidence/dashboard',headers=h).json()['pending_review']==0
 assert api.c.post('/api/evidence/preview/'+first['id']+'/confirm',json={
  'preview_digest':first['digest'],'record_type':'expense','document_kind':'receipt',
  'counterparty':'한국상사','document_date':'2026-10-21','gross_amount':11000,
  'original_checked':True},headers=h).status_code==404
 assert api.c.post('/api/evidence/preview',files={'file':('same.xlsx',xlsx())},headers=h).status_code==201

def test_csrf_and_signature_and_approval_required(api):
 p=stage(api,'a.xlsx',xlsx()).json()
 no_csrf={'Cookie':api.auth['Cookie']}
 r=api.c.post('/api/evidence/preview/'+p['id']+'/confirm',json={
  'preview_digest':p['digest'],'record_type':'expense','document_kind':'receipt',
  'counterparty':'한국상사','document_date':'2026-10-21','gross_amount':11000,
  'original_checked':True},headers=no_csrf)
 assert r.status_code==403
 assert approve(api,p,preview_digest='0'*64).status_code==409
 assert approve(api,p,original_checked=False).status_code==422
 assert api.get('/evidence/dashboard').json()['pending_review']==1

def test_inventory_restrictions_and_mismatch(api):
 p=stage(api,'stock.xlsx',xlsx('재고표',additional=[('품목코드','SKU-2'),('재고수량',37)])).json()
 assert approve(api,p,type='sales',kind='inventory_sheet').status_code==422
 assert approve(api,p,type='inventory_snapshot',kind='inventory_sheet',amount=11000,sku='SKU-2',quantity=37).status_code==422
 assert approve(api,p,type='inventory_snapshot',kind='inventory_sheet',amount=None,sku='',quantity=37).status_code==422
 assert approve(api,p,type='inventory_snapshot',kind='receipt',amount=11000).status_code==409
 assert api.get('/evidence/dashboard').json()['total_confirmed']==0

def test_pdf_text_and_no_formulas_allowed(api):
 pdf=fitz.open();pg=pdf.new_page();pg.insert_text((30,70),'RECEIPT 2026-10-21 11000 DOCUMENT REFERENCE S-2026-1001');b=pdf.tobytes();pdf.close()
 p=stage(api,'text.pdf',b)
 assert p.status_code==201,p.text
 assert p.json()['document']['method']=='pdf_text'
 b=xlsx();from openpyxl import load_workbook
 wb=load_workbook(io.BytesIO(b));wb.active['B4']='=SUM(1,2)';out=io.BytesIO();wb.save(out)
 assert stage(api,'formula.xlsx',out.getvalue()).status_code==422

def test_human_correction_in_audit_no_foreign_payment(api):
 p=stage(api,'source.xlsx',xlsx()).json()
 r=approve(api,p,amount=15000,counterparty='원본 재확인한 상호')
 assert r.status_code==201,r.text
 assert set(r.json()['corrected_fields'])=={'gross_amount','counterparty'}
 with main.conn() as c:
  assert c.execute("SELECT count(*) FROM payments").fetchone()[0]==0
  assert c.execute("SELECT count(*) FROM audit_logs WHERE action='evidence_confirm'").fetchone()[0]==1

def test_sqlite_tenant_relation_guard_is_database_enforced(api):
 import sqlite3
 p=stage(api,'record.xlsx',xlsx()).json()
 with main.conn() as c:
  other=c.execute("SELECT id FROM organizations WHERE id!=? LIMIT 1",(api.get('/me').json()['org_id'],)).fetchone()
  assert other
  with __import__('pytest').raises(sqlite3.IntegrityError):
   c.execute('UPDATE evidence_previews_v64 SET org_id=? WHERE id=?',(other['id'],p['id']))
 r=approve(api,p);assert r.status_code==201,r.text
 with main.conn() as c:
  with __import__('pytest').raises(sqlite3.IntegrityError):
   c.execute('UPDATE evidence_records_v64 SET org_id=? WHERE id=?',(other['id'],r.json()['id']))

def test_duplicate_reference_confirm_blocked_even_after_file_content_changes(api):
 first=stage(api,'one.xlsx',xlsx()).json()
 assert approve(api,first).status_code==201
 # Modified vendor/date could denote a different transaction, whereas same source
 # kind, vendor and reference must be unique even after metadata/file changes.
 second=stage(api,'two.xlsx',xlsx(gross=12000,reference='R20260001'))
 assert second.status_code==409,second.text


def test_pending_duplicate_rejected_before_ocr(api,monkeypatch):
 from app import evidence_v64
 payload=xlsx()
 first=stage(api,'once.xlsx',payload)
 assert first.status_code==201,first.text
 def forbidden(*a,**k):raise AssertionError('OCR must not be called on a duplicate')
 monkeypatch.setattr(evidence_v64,'protected_parse',forbidden)
 second=stage(api,'twice.xlsx',payload)
 assert second.status_code==409,second.text
 assert api.get('/evidence/dashboard').json()['pending_review']==1

def test_org_pending_queue_cap_is_checked_before_ocr(api,monkeypatch):
 from app import evidence_v64
 user=api.get('/me').json()
 with main.transaction() as c:
  for i in range(100):
   c.execute("""INSERT INTO evidence_previews_v64
       (id,org_id,uploaded_by,file_sha256,filename,proposed_json,digest,status,created_at)
       VALUES(?,?,?,?,?,?,?,?,?)""",
       (f'cap-{i}',user['org_id'],user['id'],f'{i:064x}',f'{i}.xlsx','{}','0'*64,'pending',main.now()))
 def forbidden(*a,**k):raise AssertionError('OCR must not be called when queue is full')
 monkeypatch.setattr(evidence_v64,'protected_parse',forbidden)
 result=stage(api,'new.xlsx',xlsx())
 assert result.status_code==429,result.text
 assert api.get('/evidence/dashboard').json()['pending_review']==100
