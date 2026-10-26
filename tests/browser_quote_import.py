"""Real Chromium document UI simulation: quotation xlsx and explicit human confirmation."""
import base64
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import shutil
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
from app import main as backend
from tests.test_quote_import import qxlsx

ROOT=Path(__file__).resolve().parents[1]
os.environ['DEMO_SEED']='1'
with TemporaryDirectory() as tmp:
    backend.DB_PATH=Path(tmp)/'quote-browser.db'
    with TestClient(backend.app,base_url='https://testserver') as client, sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,executable_path=os.environ.get('CHROMIUM_PATH') or shutil.which('chromium') or pw.chromium.executable_path,args=['--no-sandbox'])
        page=browser.new_page(viewport={'width':1440,'height':900})
        page.set_default_timeout(13000)
        errors=[];page.on('pageerror',lambda err: errors.append(str(err)))
        html=(ROOT/'app/static/index.html').read_text().replace('<link rel="stylesheet" href="/static/style.css">','<style>'+(ROOT/'app/static/style.css').read_text()+'</style>').replace('<script src="/static/app.js" defer></script>','')
        def bridge(path,opts):
            opts=opts or {};method=opts.get('method','GET');headers=opts.get('headers',{})
            if 'file_b64' in opts:
                res=client.request(method,path,headers=headers,files={'file':(opts['file_name'],base64.b64decode(opts['file_b64']),'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')})
            else:
                payload=json.loads(opts['body']) if opts.get('body') else None
                res=client.request(method,path,headers=headers,json=payload)
            try:data=res.json()
            except ValueError:data={'detail':res.text}
            return {'status':res.status_code,'data':data}
        page.expose_function('py_api_request',bridge)
        page.set_content(html)
        page.evaluate('''() => {window.fetch=async(url,options={})=>{
          const opts={method:options.method||'GET',headers:options.headers||{}};
          if(options.body instanceof FormData){const file=options.body.get('file');let arr=new Uint8Array(await file.arrayBuffer());let chunks=[];for(let i=0;i<arr.length;i+=3000)chunks.push(String.fromCharCode(...arr.slice(i,i+3000)));opts.file_b64=btoa(chunks.join(''));opts.file_name=file.name;}
          else if(options.body){opts.body=options.body;}
          let r=await window.py_api_request(url,opts);return {ok:r.status>=200&&r.status<300,status:r.status,json:async()=>r.data};
        }}''')
        page.add_script_tag(content=(ROOT/'app/static/app.js').read_text())
        page.get_by_role('button',name='한빛테크').click()
        page.locator('#login-form [type=submit]').click()
        page.get_by_role('heading',name='문서 업로드 · 자동 처리').wait_for()
        before_quotes=len(client.get('/api/quotes').json())
        before_orders=len(client.get('/api/orders').json())
        before_customers=len(client.get('/api/customers').json())
        page.locator('#import-file').set_input_files({'name':'external_quote.xlsx','mimeType':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','buffer':qxlsx()})
        page.get_by_role('button',name='파일 분석 및 검증').click()
        page.get_by_role('heading',name='추출 결과 검토 — 승인 전 최종 확인').wait_for()
        t=page.locator('.import-review').inner_text()
        assert '견적일' in t and '2026-10-18' in t and '176,000원' in t and 'QT-123' in t,t
        assert '납기일' not in t and '수주일' not in t
        assert len(client.get('/api/quotes').json())==before_quotes
        assert len(client.get('/api/orders').json())==before_orders
        save=Path(os.environ.get('SCREENSHOT_DIR',str(ROOT/'previews')));save.mkdir(parents=True,exist_ok=True)
        page.screenshot(path=str(save/'v16_quote_review_desktop.png'),full_page=True)
        page.locator('#import-approval').check()
        page.once('dialog',lambda dialog:dialog.accept())
        page.get_by_role('button',name='확인 후 견적 초안 생성').click()
        page.get_by_role('heading',name='견적 초안 등록 완료').wait_for()
        modal=page.locator('#modal-root').inner_text()
        assert '초안 (승인 아님)' in modal
        assert '176,000원' in modal
        assert len(client.get('/api/quotes').json())==before_quotes+1
        assert len(client.get('/api/customers').json())==before_customers+1
        assert len(client.get('/api/orders').json())==before_orders
        page.screenshot(path=str(save/'v16_quote_confirmed_desktop.png'),full_page=True)
        page.get_by_role('button',name='견적서 상세 보기').click()
        page.get_by_role('heading',name='견적서 상세').wait_for()
        assert not errors,errors
        print('BROWSER QUOTE IMPORT PASS: xlsx -> preview no records -> approval -> draft quote only')
        browser.close()
