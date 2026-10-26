"""MFA browser UI flow with real local FastAPI, no external network or user data."""
import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
from app import main as backend
from app.security_hardening import totp_code

ROOT=Path(__file__).resolve().parents[1]
os.environ['DEMO_SEED']='1'
os.environ['JW_DATA_KEY']=Fernet.generate_key().decode()
with tempfile.TemporaryDirectory() as tmp:
    backend.DB_PATH=Path(tmp)/'mfa-browser.db'
    with TestClient(backend.app,base_url='https://testserver') as client, sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,executable_path=(os.environ.get('CHROMIUM_PATH') or shutil.which('chromium') or pw.chromium.executable_path),args=['--no-sandbox'])
        page=browser.new_page(viewport={'width':1440,'height':900})
        page.set_default_timeout(15000)
        errors=[]
        page.on('pageerror',lambda err:errors.append(str(err)))
        def bridge(url,options=None):
            options=options or {}
            response=client.request(options.get('method','GET'),url,
                    headers=options.get('headers',{}),
                    json=json.loads(options['body']) if options.get('body') else None)
            try:d=response.json()
            except:d={}
            return {'status':response.status_code,'data':d}
        page.expose_function('py_api_request',bridge)
        html=(ROOT/'app/static/index.html').read_text().replace('<link rel="stylesheet" href="/static/style.css">','<style>'+ (ROOT/'app/static/style.css').read_text()+'</style>').replace('<script src="/static/app.js" defer></script>','')
        page.set_content(html)
        page.evaluate("""() => {window.fetch=async(url,options={})=>{const r=await window.py_api_request(url,options);return {ok:r.status>=200&&r.status<300,status:r.status,json:async()=>r.data}}}""")
        page.add_script_tag(content=(ROOT/'app/static/app.js').read_text())
        page.locator('#login-form [type=submit]').click()
        page.get_by_role('heading',name='문서 업로드 · 자동 처리').wait_for()
        page.locator('nav [data-page=security]').click()
        page.get_by_role('heading',name='보안 관제 센터').wait_for()
        page.once('dialog',lambda d:d.accept('Demo!2026secure'))
        page.get_by_role('button',name='인증 앱 등록 시작').click()
        secret=page.locator('#modal-root code').first.inner_text()
        page.locator('#mfa-confirm-form input[name=otp]').fill(totp_code(secret,int(time.time()//30)))
        page.locator('#mfa-confirm-form [type=submit]').click()
        page.get_by_role('heading',name='일회용 복구 코드 보관').wait_for()
        assert page.locator('#modal-root .detail-row code').count()==8
        codes=page.locator('#modal-root .detail-row code').all_inner_texts()
        page.screenshot(path=str(Path(os.environ.get('V18_SCREENSHOT_DIR',tmp))/'v18_recovery_codes_demo.png'))
        page.locator('#modal-root [data-action=close]').click()
        assert page.locator('#login-view').is_visible()
        page.locator('#login-form input[name=recovery_code]').fill(codes[0])
        page.locator('#login-form [type=submit]').click()
        page.get_by_role('heading',name='문서 업로드 · 자동 처리').wait_for()
        page.locator('nav [data-page=security]').click()
        page.get_by_text('7개',exact=False).first.wait_for()
        page.get_by_role('button',name='복구 코드 재발급').click()
        page.locator('#mfa-rotate-form input[name=password]').fill('Demo!2026secure')
        page.locator('#mfa-rotate-form input[name=recovery_code]').fill(codes[1])
        page.locator('#mfa-rotate-form [type=submit]').click()
        page.get_by_role('heading',name='일회용 복구 코드 보관').wait_for()
        new_codes=page.locator('#modal-root .detail-row code').all_inner_texts()
        assert len(new_codes)==8 and not set(codes)&set(new_codes)
        assert page.locator('#login-view').is_visible()
        assert not errors,errors
        browser.close()
        print('BROWSER MFA RECOVERY V1.8: PASS (enroll → one-time codes → login → rotate)')
