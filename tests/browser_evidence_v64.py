"""Desktop/mobile Chromium simulation using authenticated FastAPI TestClient; not Safari or real browser HTTP."""
from __future__ import annotations
import os
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
from tests.test_evidence_v64 import xlsx
from app import main
ROOT=Path(__file__).resolve().parents[1]

def run():
 with tempfile.TemporaryDirectory() as temp:
  os.environ['DEMO_SEED']='1'
  saved=main.DB_PATH
  main.DB_PATH=Path(temp)/'works.db'
  try:
   with TestClient(main.app,base_url='https://testserver') as client:
    login=client.post('/api/login',json={'email':'demo@hanbit.example','password':'Demo!2026secure'})
    assert login.status_code==200,login.text
    head={'Cookie':main.SESSION_COOKIE+'='+login.cookies.get(main.SESSION_COOKIE),
          'X-CSRF-Token':login.json()['csrf_token']}
    with sync_playwright() as p:
     for width,height in ((1440,900),(390,844)):
      browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
      page=browser.new_page(viewport={'width':width,'height':height})
      errors=[]
      page.on('pageerror',lambda e:errors.append(str(e)))
      def backend(source,data):
       if data.get('kind')=='form':
        uploads=[(x['field'],(x['filename'],bytes(x['bytes']))) for x in data['files']]
        res=client.request(data.get('method','POST'),data['path'],files=uploads,headers=head)
       else:
        h={**data.get('headers',{}),'Cookie':head['Cookie']}
        method=data.get('method','GET')
        if method not in ('GET','HEAD') and data['path']!='/api/login':h['X-CSRF-Token']=head['X-CSRF-Token']
        body=data.get('body')
        res=client.request(method,data['path'],headers=h,content=body.encode() if isinstance(body,str) else body)
       return {'status':res.status_code,'body':res.text,'content_type':res.headers.get('content-type','application/json')}
      page.expose_binding('__test_backend',backend)
      html=(ROOT/'app/static/index.html').read_text()
      for n in ('evidence_v64.js','app.js','automation_v61.js','automation_v62.js'):
       html=html.replace(f'<script src="/static/{n}" defer></script>','')
      page.set_content(html)
      page.add_style_tag(content=(ROOT/'app/static/style.css').read_text())
      page.evaluate('''window.fetch=async function(path,opts={}){
       let data={path,method:opts.method||'GET',headers:opts.headers||{},body:opts.body||null};
       if(opts.body instanceof FormData){data.kind='form';data.files=[];for(const [field,f] of opts.body.entries()){
        if(f instanceof File)data.files.push({field,filename:f.name,bytes:Array.from(new Uint8Array(await f.arrayBuffer()))});}
        data.body=null;}
       const resp=await window.__test_backend(data);
       return new Response(resp.body,{status:resp.status,headers:{'Content-Type':resp.content_type}});
      };void 0;''')
      for n in ('evidence_v64.js','app.js','automation_v61.js','automation_v62.js'):
       page.add_script_tag(content=(ROOT/'app/static'/n).read_text())
      page.locator('#evidence-v64-file input[type=file]').wait_for(timeout=20000)
      page.locator('#evidence-v64-file input[type=file]').set_input_files([{
        'name':f'receipt-{width}.xlsx','mimeType':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'buffer':xlsx(reference=f'R-v64-{width}')
      }])
      page.locator('#evidence-v64-file button[type=submit]').click()
      page.locator('#evidence-v64-confirm').wait_for(timeout=15000)
      assert page.locator('#evidence-v64-confirm [name=counterparty]').input_value()=='한국상사'
      page.locator('#evidence-v64-confirm [name=original_checked]').check()
      page.locator('#evidence-v64-confirm button[type=submit]').click()
      page.locator('#evidence-v64-confirm').wait_for(state='detached',timeout=15000)
      d=client.get('/api/evidence/dashboard',headers=head).json()
      assert d['by_type']['expense']['amount']>=11000,d
      if width<600:page.locator('#toggle-menu').click()
      page.locator('[data-page=dashboard]').click()
      page.get_by_text('검토 완료 증빙 기록').wait_for(timeout=15000)
      assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth+2'),width
      assert not errors,errors
      proof=ROOT/'proof';proof.mkdir(exist_ok=True)
      page.screenshot(path=str(proof/f'v64_evidence_{width}px.png'),full_page=True,animations='disabled')
      browser.close()
    print('V6.4 browser UI PASS desktop 1440 / mobile 390, real XLSX upload, approval and summary')
  finally:main.DB_PATH=saved

if __name__=='__main__':run()
