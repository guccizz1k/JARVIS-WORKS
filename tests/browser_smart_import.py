"""PC browser integration for XLSX upload + explicit confirmation using real FastAPI TestClient.
Network-independent test: bridges browser FormData bytes to TestClient in process.
"""
import base64
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import shutil
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
from app import main as backend
from tests.test_smart_import import make_extended_xlsx

ROOT=Path(__file__).resolve().parents[1]
os.environ['DEMO_SEED']='1'

with TemporaryDirectory() as tmp:
    backend.DB_PATH=Path(tmp)/'browser_import.db'
    with TestClient(backend.app,base_url='https://testserver') as client, sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,executable_path=(os.environ.get('CHROMIUM_PATH') or shutil.which('chromium') or pw.chromium.executable_path),args=['--no-sandbox'])
        page=browser.new_page(viewport={'width':1440,'height':900})
        page.set_default_timeout(14000)
        errors=[]
        page.on('pageerror',lambda err: errors.append(str(err)))
        html=(ROOT/'app/static/index.html').read_text().replace('<link rel="stylesheet" href="/static/style.css">','<style>'+(ROOT/'app/static/style.css').read_text()+'</style>').replace('<script src="/static/app.js" defer></script>','')
        def bridge(path,opt):
            opts=opt or {}
            method=opts.get('method','GET')
            headers=opts.get('headers',{})
            if 'file_b64' in opts:
                raw=base64.b64decode(opts['file_b64'])
                res=client.request(method,path,headers=headers,files={'file':(opts['file_name'],raw,'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')})
            else:
                payload=json.loads(opts['body']) if opts.get('body') else None
                res=client.request(method,path,headers=headers,json=payload)
            try: data=res.json()
            except ValueError: data={'detail':res.text}
            return {'status':res.status_code,'data':data}
        page.expose_function('py_api_request',bridge)
        page.set_content(html)
        page.evaluate('''() => {window.fetch=async(url,options={})=>{
          const opts={method:options.method||'GET',headers:options.headers||{}};
          if(options.body instanceof FormData){
            const file=options.body.get('file');let arr=new Uint8Array(await file.arrayBuffer());
            let chunks=[];for(let i=0;i<arr.length;i+=3000)chunks.push(String.fromCharCode(...arr.slice(i,i+3000)));
            opts.file_b64=btoa(chunks.join(''));opts.file_name=file.name;
          }else if(options.body){opts.body=options.body;}
          let r=await window.py_api_request(url,opts);
          return {ok:r.status>=200&&r.status<300,status:r.status,json:async()=>r.data};
        }}''')
        page.add_script_tag(content=(ROOT/'app/static/app.js').read_text())
        page.get_by_role('button',name='한빛테크').click()
        page.locator('#login-form [type=submit]').click()
        page.get_by_role('heading',name='문서 업로드 · 자동 처리').wait_for()
        Path(os.environ.get('SCREENSHOT_DIR',str(ROOT/'previews'))).mkdir(parents=True,exist_ok=True)
        page.screenshot(path=str(Path(os.environ.get('SCREENSHOT_DIR',str(ROOT/'previews')))/'v15_automation_home_desktop.png'),full_page=True)
        before=client.get('/api/orders').json()
        page.locator('nav [data-page=imports]').click()
        page.get_by_role('heading',name='문서 업로드 · 자동 처리').wait_for()
        page.locator('#import-file').set_input_files({'name':'purchase_order.xlsx','mimeType':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','buffer':make_extended_xlsx()})
        page.get_by_role('button',name='파일 분석 및 검증').click()
        page.get_by_role('heading',name='추출 결과 검토 — 자동 발주 전 최종 확인').wait_for()
        assert '프로젝트명' in page.locator('.import-review').inner_text()
        assert 'PO-2026-0041' in page.locator('.import-review').inner_text()
        assert '1705000' not in errors
        assert len(client.get('/api/orders').json())==len(before), 'Preview may not save an order'
        path=os.environ.get('SCREENSHOT_DIR',str(ROOT/'previews'))
        Path(path).mkdir(parents=True,exist_ok=True)
        page.screenshot(path=str(Path(path)/'v13_import_review_desktop.png'),full_page=True)
        page.locator('#import-approval').check()
        page.once('dialog',lambda d:d.accept())
        page.get_by_role('button',name='확인 후 발주 생성').click()
        page.get_by_role('heading',name='발주 생성 완료').wait_for()
        assert '1,705,000원' in page.locator('#modal-root').inner_text()
        page.get_by_role('button',name='발주서 상세 확인').click()
        page.get_by_role('heading',name='발주 및 문서 대조').wait_for()
        page.locator('.close-x').click()
        page.locator('nav [data-page=imports]').click()
        page.get_by_role('heading',name='문서 업로드 · 자동 처리').wait_for()
        page.locator('.import-stats-details summary').click()
        assert '1,705,000원' in page.locator('.import-summary').inner_text()
        assert '2026-10-16' in page.locator('.import-summary').inner_text()
        assert '산업용 부품 A' in page.locator('.import-summary').inner_text()
        assert '박스 2' in page.locator('.import-summary').inner_text()
        page.screenshot(path=str(Path(path)/'v13_import_analytics_desktop.png'),full_page=True)
        assert not errors, errors
        print('BROWSER SMART IMPORT PASS: preview no DB write → confirm → order created → analytics shown')
        browser.close()
