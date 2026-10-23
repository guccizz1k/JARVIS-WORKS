"""V6.8 PC/mobile Chromium: approved Excel candidates -> immutable lines -> exception history."""
from __future__ import annotations
import io,os,tempfile
from pathlib import Path
from openpyxl import Workbook
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
from app import main
ROOT=Path(__file__).resolve().parents[1]


def make_doc(customer,ref,total):
    w=Workbook();s=w.active
    for row in [('문서종류','매출전표'),('거래처',customer),('거래일','2026-10-21'),('총금액',total),('문서번호',ref)]:s.append(row)
    s.append(['품목명','수량','단가','금액'])
    s.append(['부품 A',3,101,303]);s.append(['부품 B',2,503,1006])
    s.append(['합계',None,None,1309]);out=io.BytesIO();w.save(out);return out.getvalue()


def run():
 with tempfile.TemporaryDirectory() as td:
  os.environ['DEMO_SEED']='1'
  old=main.DB_PATH;main.DB_PATH=Path(td)/'test.db'
  try:
   with TestClient(main.app,base_url='https://testserver') as c:
    login=c.post('/api/login',json={'email':'demo@hanbit.example','password':'Demo!2026secure'})
    assert login.status_code==200,login.text
    auth={'Cookie':main.SESSION_COOKIE+'='+login.cookies.get(main.SESSION_COOKIE),
          'X-CSRF-Token':login.json()['csrf_token']}
    customer=c.get('/api/customers',headers=auth).json()[0]
    q=c.post('/api/quotes',headers=auth,json={'customer_id':customer['id'],
        'title':'V68 다품목','vat_mode':'taxable','items':[
            {'name':'부품 A','quantity':3,'unit_price':101},
            {'name':'부품 B','quantity':2,'unit_price':503}]})
    assert q.status_code==201,q.text
    quote=c.get('/api/quotes/'+q.json()['id'],headers=auth).json()
    raw=make_doc(quote['customer_name_snapshot'],quote['doc_no'],quote['money']['total'])
    p=c.post('/api/evidence/preview',headers=auth,files={'file':('sales.xlsx',raw)})
    assert p.status_code==201,p.text
    p=p.json();assert len(p['document']['suggested_lines'])==2
    confirmed=c.post('/api/evidence/preview/'+p['id']+'/confirm',headers=auth,json={
        'preview_digest':p['digest'],'record_type':'sales','document_kind':'sales_slip',
        'counterparty':quote['customer_name_snapshot'],'document_date':'2026-10-21',
        'gross_amount':quote['money']['total'],'reference_number':quote['doc_no'],
        'original_checked':True})
    assert confirmed.status_code==201,confirmed.text
    rid=confirmed.json()['id']
    with sync_playwright() as pw:
     for width,height in ((1440,900),(390,844)):
      browser=pw.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox'])
      page=browser.new_page(viewport={'width':width,'height':height})
      errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
      def backend(source,data):
       h={**data.get('headers',{}),'Cookie':auth['Cookie']}
       method=data.get('method','GET');path=data['path']
       if method not in ('GET','HEAD') and path!='/api/login':h['X-CSRF-Token']=auth['X-CSRF-Token']
       body=data.get('body');response=c.request(method,path,headers=h,
          content=body.encode() if isinstance(body,str) else body)
       return {'status':response.status_code,'body':response.text,
               'content_type':response.headers.get('content-type','application/json')}
      page.expose_binding('__v68_backend',backend)
      html=(ROOT/'app/static/index.html').read_text()
      scripts=['evidence_v64.js','evidence_v65.js','evidence_v68.js','app.js','automation_v61.js','automation_v62.js']
      for name in scripts:html=html.replace(f'<script src="/static/{name}" defer></script>','')
      page.set_content(html)
      page.add_style_tag(content=(ROOT/'app/static/style.css').read_text())
      page.evaluate('''() => {window.fetch=async function(path,opts={}){
       const res=await window.__v68_backend({path,method:opts.method||'GET',headers:opts.headers||{},body:opts.body||null});
       return new Response(res.body,{status:res.status,headers:{'Content-Type':res.content_type}})
      }}''')
      for name in scripts:page.add_script_tag(content=(ROOT/'app/static'/name).read_text())
      button=page.locator('button[data-v68-lines]').first
      if width==1440:
       button.wait_for(timeout=16000);button.click()
       page.locator('#jw-v68-lines-form').wait_for()
       assert page.locator('.jw-v68-line').count()==2
       assert page.locator('.jw-v68-line').first.locator('[name=name]').input_value()=='부품 A'
       page.locator('#jw-v68-lines-form [name=original_checked]').check()
       page.locator('#jw-v68-lines-form button[type=submit]').click()
       page.locator('button[data-v65-check]').first.wait_for(timeout=15000)
       import time
       for _ in range(30):
        if c.get('/api/evidence/records/'+rid+'/line-items',headers=auth).json()['confirmed']:break
        time.sleep(0.3)
       assert c.get('/api/evidence/records/'+rid+'/line-items',headers=auth).json()['confirmed'],page.locator('body').inner_text()[-1000:]
      else:
       button.wait_for(timeout=16000);button.click()
       page.get_by_text('확정된 품목 대조 내역',exact=True).wait_for(timeout=15000)
       page.locator('[data-action=close]').click()
      history=page.locator('button[data-v68-review]').first
      history.wait_for(timeout=15000);history.click()
      page.locator('#jw-v68-review-form').wait_for()
      if width==1440:
       page.locator('#jw-v68-review-form [name=note]').fill('원본 문서와 거래 품목을 모두 확인했습니다')
       page.locator('#jw-v68-review-form [name=original_checked]').check()
       page.locator('#jw-v68-review-form button[type=submit]').click()
      else:
       page.locator('[data-action=close]').click()
      assert not errors,errors
      if width==390:
       assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth+3'),'mobile overflow'
      proof=ROOT/'proof';proof.mkdir(exist_ok=True)
      page.screenshot(path=str(proof/f'v68_document_workflow_{width}px.png'),
                      full_page=True,animations='disabled')
      browser.close()
   print('V6.8 PC/mobile Chromium line approval & review E2E PASS')
  finally:main.DB_PATH=old

if __name__=='__main__':run()
