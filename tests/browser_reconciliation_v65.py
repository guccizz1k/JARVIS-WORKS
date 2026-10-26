"""Playwright PC/mobile test for V6.5, using real authenticated FastAPI TestClient."""
from __future__ import annotations
import io,os,tempfile
from pathlib import Path
from openpyxl import Workbook
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
from app import main
ROOT=Path(__file__).resolve().parents[1]

def make_doc(customer,ref,total):
 wb=Workbook();w=wb.active
 for r in [('문서종류','매출전표'),('거래처',customer),('거래일','2026-10-21'),('총금액',total),('문서번호',ref)]:w.append(r)
 b=io.BytesIO();wb.save(b);return b.getvalue()

def run():
 with tempfile.TemporaryDirectory() as td:
  os.environ['DEMO_SEED']='1'
  original=main.DB_PATH;main.DB_PATH=Path(td)/'test.db'
  try:
   with TestClient(main.app,base_url='https://testserver') as c:
    login=c.post('/api/login',json={'email':'demo@hanbit.example','password':'Demo!2026secure'});assert login.status_code==200
    head={'Cookie':main.SESSION_COOKIE+'='+login.cookies.get(main.SESSION_COOKIE),'X-CSRF-Token':login.json()['csrf_token']}
    customer=c.get('/api/customers',headers=head).json()[0]
    payload={'customer_id':customer['id'],'title':'V65 정품', 'vat_mode':'taxable',
             'items':[{'name':'부품A','quantity':2,'unit_price':5000}]}
    q=c.post('/api/quotes',json=payload,headers=head);assert q.status_code==201,q.text
    d=c.get('/api/quotes/'+q.json()['id'],headers=head).json()
    upload=c.post('/api/evidence/preview',headers=head,files={'file':('sales.xlsx',make_doc(d['customer_name_snapshot'],d['doc_no'],d['money']['total']))})
    assert upload.status_code==201,upload.text
    p=upload.json()
    done=c.post('/api/evidence/preview/'+p['id']+'/confirm',headers=head,json={
     'preview_digest':p['digest'],'record_type':'sales','document_kind':'sales_slip',
     'counterparty':d['customer_name_snapshot'],'document_date':'2026-10-21',
     'gross_amount':d['money']['total'],'reference_number':d['doc_no'],
     'original_checked':True});assert done.status_code==201,done.text
    rid=done.json()['id']
    with sync_playwright() as pw:
     for width,height in ((1440,900),(390,844)):
      browser=pw.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox'])
      page=browser.new_page(viewport={'width':width,'height':height})
      errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
      def backend(source,data):
       h={**data.get('headers',{}),'Cookie':head['Cookie']}
       method=data.get('method','GET');path=data['path']
       if method not in ('GET','HEAD') and path!='/api/login':h['X-CSRF-Token']=head['X-CSRF-Token']
       b=data.get('body');res=c.request(method,path,headers=h,content=b.encode() if isinstance(b,str) else b)
       return {'status':res.status_code,'body':res.text,'content_type':res.headers.get('content-type','application/json')}
      page.expose_binding('__v65_backend',backend)
      html=(ROOT/'app/static/index.html').read_text()
      scripts=['evidence_v64.js','evidence_v65.js','app.js','automation_v61.js','automation_v62.js']
      for n in scripts:html=html.replace(f'<script src="/static/{n}" defer></script>','')
      page.set_content(html)
      page.add_style_tag(content=(ROOT/'app/static/style.css').read_text())
      page.evaluate('''() => {window.fetch=async function(path,opts={}){
       const resp=await window.__v65_backend({path,method:opts.method||'GET',headers:opts.headers||{},body:opts.body||null});
       return new Response(resp.body,{status:resp.status,headers:{'Content-Type':resp.content_type}})
      }}''')
      for n in scripts:page.add_script_tag(content=(ROOT/'app/static'/n).read_text())
      if width==1440:
       page.locator('button[data-v65-check]').wait_for(timeout=15000)
       page.locator('button[data-v65-check]').click()
       page.locator('button[data-v65-select]').first.wait_for(timeout=15000)
       page.locator('button[data-v65-select]').first.click()
       page.locator('#jw-v65-link-form').wait_for()
       page.locator('#jw-v65-link-form [name=ack]').check()
       page.locator('#jw-v65-link-form button[type=submit]').click()
      page.locator('button[data-v65-detail]').wait_for(timeout=15000)
      page.locator('button[data-v65-detail]').click()
      page.get_by_text('거래 대조 기록',exact=True).wait_for(timeout=15000)
      page.locator('[data-action=close]').click()
      assert not errors,errors
      if width==390:assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth+2'),'mobile horizontal overflow'
      proof=ROOT/'proof';proof.mkdir(exist_ok=True)
      page.screenshot(path=str(proof/f'v65_reconciliation_{width}px.png'),full_page=True,animations='disabled')
      browser.close()
   print('V6.5 PC + mobile Chromium E2E PASS (1440/390)')
  finally:main.DB_PATH=original

if __name__=='__main__':run()
