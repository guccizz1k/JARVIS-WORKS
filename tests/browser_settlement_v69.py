"""Local Chromium E2E: V6.9 adjustment review in both 1440px & 390px layouts."""
from __future__ import annotations
import os,tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
from app import main
ROOT=Path(__file__).resolve().parents[1]

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
    def call(method,path,body):
     r=c.request(method,path,headers=auth,json=body)
     assert r.status_code in (200,201),r.text
     return r.json()
    q=call('POST','/api/quotes',{'customer_id':customer['id'],
       'title':'V69 정산 검증','vat_mode':'taxable','items':[
       {'name':'부품 A','quantity':3,'unit_price':101},
       {'name':'부품 B','quantity':2,'unit_price':503}]})
    call('POST','/api/quotes/'+q['id']+'/status',{'status':'sent'})
    call('POST','/api/quotes/'+q['id']+'/status',{'status':'accepted'})
    o=call('POST','/api/orders/from-quote',{'quote_id':q['id'],'due_date':'2099-12-30'})
    call('POST','/api/orders/'+o['id']+'/status',{'status':'processing'})
    call('POST','/api/orders/'+o['id']+'/status',{'status':'fulfilled'})
    inv=call('POST','/api/invoices/from-order',{'order_id':o['id'],'due_date':'2099-12-31'})
    with sync_playwright() as pw:
     browser=pw.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox'])
     try:
      for width,height in ((1440,900),(390,844)):
       page=browser.new_page(viewport={'width':width,'height':height})
       errors=[];page.on('pageerror',lambda x:errors.append(str(x)))
       def backend(source,data):
        headers={**data.get('headers',{}),'Cookie':auth['Cookie']}
        method=data.get('method','GET');path=data['path']
        if method not in ('GET','HEAD') and path!='/api/login':headers['X-CSRF-Token']=auth['X-CSRF-Token']
        body=data.get('body')
        response=c.request(method,path,headers=headers,
           content=body.encode() if isinstance(body,str) else body)
        return {'status':response.status_code,'body':response.text,
                'content_type':response.headers.get('content-type','application/json')}
       page.expose_binding('__v69_backend',backend)
       html=(ROOT/'app/static/index.html').read_text()
       scripts=['evidence_v64.js','evidence_v65.js','evidence_v68.js','app.js',
                'settlement_v69.js','automation_v61.js','automation_v62.js']
       for name in scripts:html=html.replace(f'<script src="/static/{name}" defer></script>','')
       page.set_content(html)
       page.add_style_tag(content=(ROOT/'app/static/style.css').read_text())
       page.evaluate('''() => {window.fetch=async function(path,opts={}){
        const res=await window.__v69_backend({path,method:opts.method||'GET',headers:opts.headers||{},body:opts.body||null});
        return new Response(res.body,{status:res.status,headers:{'Content-Type':res.content_type}})
       }}''')
       for name in scripts:page.add_script_tag(content=(ROOT/'app/static'/name).read_text())
       page.locator('#app-shell:not(.hidden)').wait_for(timeout=20000)
       if width==390:page.locator('#toggle-menu').click()
       page.locator('button[data-page="invoices"]').click()
       page.locator('button[data-action="view-invoice"]').first.wait_for(timeout=15000)
       page.locator('button[data-action="view-invoice"]').first.click()
       page.locator('[data-v69-open]').wait_for()
       page.locator('[data-v69-open]').click()
       page.locator('#jw-v69-form').wait_for()
       assert '수정세금계산서' in page.locator('#modal-root').inner_text()
       if width==1440:
        form=page.locator('#jw-v69-form')
        form.locator('[name=kind]').select_option('discount')
        form.locator('[name=amount]').fill('100')
        form.locator('[name=reason]').fill('실제 청구 원본의 할인 내역을 모두 대조했습니다')
        form.locator('[name=original_checked]').check()
        form.locator('button[type=submit]').click()
        page.locator('[data-v69-decide]').first.wait_for(timeout=15000)
        page.on('dialog',lambda d:d.accept('할인액 100원 및 원본 품목을 재확인했습니다'))
        page.locator('[data-v69-decide][data-approve=yes]').click()
        page.get_by_text('승인 조정 후 합계',exact=True).wait_for(timeout=15000)
        assert c.get('/api/invoices/'+inv['id'],headers=auth).json()['balance']==1330
       else:
        assert page.locator('#jw-v69-form').count()==1
       assert not errors,errors
       if width==390:assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth+3'),'mobile overflow'
       proof=ROOT/'proof';proof.mkdir(exist_ok=True)
       page.screenshot(path=str(proof/f'v69_settlement_{width}px.png'),
                       full_page=True,animations='disabled')
       page.close()
     finally:browser.close()
   print('V6.9 PC/mobile Chromium adjustment review PASS')
  finally:main.DB_PATH=old

if __name__=='__main__':run()
