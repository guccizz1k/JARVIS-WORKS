"""Real desktop Chromium UI test for incomplete XLSX → user supplement → review → confirmation."""
from __future__ import annotations
import base64,json,os,shutil
from pathlib import Path
from tempfile import TemporaryDirectory
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
from app import main as backend
from tests.test_smart_import import make_xlsx

ROOT=Path(__file__).resolve().parents[1]
os.environ['DEMO_SEED']='1'
with TemporaryDirectory() as temp:
    backend.DB_PATH=Path(temp)/'supplement.db'
    with TestClient(backend.app,base_url='https://testserver') as client,sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,executable_path=(os.environ.get('CHROMIUM_PATH') or shutil.which('chromium') or pw.chromium.executable_path),args=['--no-sandbox'])
        page=browser.new_page(viewport={'width':1440,'height':900})
        page.set_default_timeout(15000)
        errors=[];page.on('pageerror',lambda err:errors.append(str(err)))
        html=(ROOT/'app/static/index.html').read_text().replace('<link rel="stylesheet" href="/static/style.css">','<style>'+(ROOT/'app/static/style.css').read_text()+'</style>').replace('<script src="/static/app.js" defer></script>','')
        def bridge(path,opt):
            opts=opt or {};method=opts.get('method','GET');headers=opts.get('headers',{})
            if 'file_b64' in opts:
                res=client.request(method,path,headers=headers,files={'file':(opts['file_name'],base64.b64decode(opts['file_b64']))})
            else:
                res=client.request(method,path,headers=headers,json=json.loads(opts['body']) if opts.get('body') else None)
            try:data=res.json()
            except ValueError:data={'detail':res.text}
            return {'status':res.status_code,'data':data}
        page.expose_function('py_api_request',bridge)
        page.set_content(html)
        page.evaluate('''() => {window.fetch=async(url,options={})=>{
         const opts={method:options.method||'GET',headers:options.headers||{}};
         if(options.body instanceof FormData){let file=options.body.get('file');let arr=new Uint8Array(await file.arrayBuffer());let chunks=[];for(let i=0;i<arr.length;i+=3000)chunks.push(String.fromCharCode(...arr.slice(i,i+3000)));opts.file_b64=btoa(chunks.join(''));opts.file_name=file.name}
         else if(options.body)opts.body=options.body;
         const r=await window.py_api_request(url,opts);return {ok:r.status>=200&&r.status<300,status:r.status,json:async()=>r.data};
        }}''')
        page.add_script_tag(content=(ROOT/'app/static/app.js').read_text())
        page.get_by_role('button',name='한빛테크').click()
        page.locator('#login-form [type=submit]').click()
        page.get_by_role('heading',name='문서 업로드 · 자동 처리').wait_for()
        page.locator('nav [data-page=imports]').click()
        page.locator('#import-file').set_input_files({'name':'incomplete.xlsx','mimeType':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','buffer':make_xlsx({'거래처':'','납기일':''})})
        page.get_by_role('button',name='파일 분석 및 검증').click()
        page.get_by_role('heading',name='추출 결과 검토 — 자동 발주 전 최종 확인').wait_for()
        assert page.locator('form#import-supplement-form').count()==1
        assert page.locator('[data-action=confirm-import]').count()==0
        assert not client.get('/api/orders').json()
        page.locator('#import-supplement-form [name=company]').fill('신규산업')
        page.locator('#import-supplement-form [name=due_date]').fill('2026-11-01')
        path=Path(os.environ.get('SCREENSHOT_DIR',str(ROOT/'previews')));path.mkdir(parents=True,exist_ok=True)
        page.screenshot(path=str(path/'v14_missing_field_review.png'),full_page=True)
        page.locator('#import-supplement-form [type=submit]').click()
        page.locator('[data-action=confirm-import]').wait_for()
        assert not client.get('/api/orders').json()
        assert '1,705,000원' in page.locator('.import-review').inner_text()
        page.screenshot(path=str(path/'v14_completed_document_review.png'),full_page=True)
        page.locator('#import-approval').check()
        page.once('dialog',lambda d:d.accept())
        page.locator('[data-action=confirm-import]').click()
        page.get_by_role('heading',name='발주 생성 완료').wait_for()
        assert len(client.get('/api/orders').json())==1
        assert client.get('/api/order-analytics').json()['totals']['total']==1705000
        assert not errors,errors
        print('BROWSER V1.4 PASS: incomplete preview → no order → field supplement → approval → exactly one order & correct aggregate')
        browser.close()
