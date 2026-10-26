"""Chromium UI simulation tied to authenticated FastAPI TestClient, with real file bytes.
Not a real Safari or browser-over-network test. Synthetic data only.
"""
from __future__ import annotations
import os
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
from tests.test_smart_import import make_xlsx
from tests.test_quote_import import qxlsx
from app import main
ROOT=Path(__file__).resolve().parents[1]

def run():
    with tempfile.TemporaryDirectory() as temp:
        os.environ['DEMO_SEED']='1'
        original=main.DB_PATH
        main.DB_PATH=Path(temp)/'works.db'
        try:
            with TestClient(main.app,base_url='https://testserver') as api:
                login=api.post('/api/login',json={'email':'demo@hanbit.example','password':'Demo!2026secure'})
                assert login.status_code==200,login.text
                head={'Cookie':main.SESSION_COOKIE+'='+login.cookies.get(main.SESSION_COOKIE),
                      'X-CSRF-Token':login.json()['csrf_token']}
                with sync_playwright() as p:
                    for width,height in ((1440,900),(390,844)):
                        browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
                        page=browser.new_page(viewport={'width':width,'height':height},device_scale_factor=1)
                        errors=[]
                        page.on('pageerror',lambda exc:errors.append(str(exc)))
                        def backend(source,payload):
                            method=payload.get('method','GET')
                            if payload.get('kind')=='form':
                                files=[('files',(f['filename'],bytes(f['bytes']))) for f in payload['files']]
                                res=api.post(payload['path'],files=files,headers=head)
                            else:
                                h={**payload.get('headers',{}),'Cookie':head['Cookie']}
                                if method not in ('GET','HEAD') and payload['path']!='/api/login':
                                    h['X-CSRF-Token']=head['X-CSRF-Token']
                                body=payload.get('body')
                                res=api.request(method,payload['path'],headers=h,
                                                content=body.encode() if isinstance(body,str) else body)
                            return {'status':res.status_code,'body':res.text,
                                    'content_type':res.headers.get('content-type','application/json')}
                        page.expose_binding('__test_backend',backend)
                        html=(ROOT/'app/static/index.html').read_text()
                        for name in ('app.js','automation_v61.js','automation_v62.js'):
                            html=html.replace(f'<script src="/static/{name}" defer></script>','')
                        page.set_content(html)
                        page.add_style_tag(content=(ROOT/'app/static/style.css').read_text())
                        page.evaluate('''window.fetch=async function(path,opts={}){
                            let payload={path,method:opts.method||'GET',headers:opts.headers||{},body:opts.body||null};
                            if(opts.body instanceof FormData){
                                payload.kind='form';payload.files=[];
                                for(const [name,v] of opts.body.entries()){
                                    if(v instanceof File)payload.files.push({name,filename:v.name,bytes:Array.from(new Uint8Array(await v.arrayBuffer()))});
                                }
                                payload.body=null;
                            }
                            const r=await window.__test_backend(payload);
                            return new Response(r.body,{status:r.status,headers:{'Content-Type':r.content_type}});
                        };void 0;''')
                        for name in ('app.js','automation_v61.js','automation_v62.js'):
                            page.add_script_tag(content=(ROOT/'app/static'/name).read_text())
                        page.locator('#import-batch-form input[name=files]').wait_for(timeout=15000)
                        page.locator('#import-batch-form input[name=files]').set_input_files([
                            {'name':'order.xlsx','mimeType':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','buffer':make_xlsx()},
                            {'name':'quote.xlsx','mimeType':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','buffer':qxlsx()},
                        ])
                        page.locator('#import-batch-form button[type=submit]').click()
                        page.get_by_text('일괄 분석 결과 · 2건').wait_for(timeout=30000)
                        assert page.locator('[data-action=import-batch-open]').count()==2
                        page.locator('[data-action=import-batch-open]').last.click()
                        page.get_by_text('신규견적사').first.wait_for(timeout=15000)
                        assert page.locator('#import-approval').count()==1
                        assert not errors,errors
                        assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth+2'),width
                        proof=ROOT/'proof';proof.mkdir(exist_ok=True)
                        page.screenshot(path=str(proof/f'v63_import_batch_{width}px.png'),full_page=True,animations='disabled')
                        browser.close()
                print('V6.3 Chromium UI + TestClient PASS desktop 1440 / mobile 390: binary upload & independent review')
        finally:main.DB_PATH=original

if __name__=='__main__':run()
