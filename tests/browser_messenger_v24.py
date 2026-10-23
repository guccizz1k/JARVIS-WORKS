"""Real Chromium DOM + in-process FastAPI contract. No public network or phone hardware."""
from __future__ import annotations
import os
import sys
import uuid
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app import main


def execute():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ['DEMO_SEED']='1'
        original=main.DB_PATH
        main.DB_PATH=Path(tmp)/'works.db'
        try:
            with TestClient(main.app,base_url='https://testserver') as api:
                a=api.post('/api/login',json={'email':'demo@hanbit.example','password':'Demo!2026secure'})
                assert a.status_code==200
                org_a=a.json()['user']['org_id']
                h={'Cookie':main.SESSION_COOKIE+'='+a.cookies.get(main.SESSION_COOKIE), 'X-CSRF-Token':a.json()['csrf_token']}
                b=api.post('/api/login',json={'email':'demo@bada.example','password':'Demo!2026secure'})
                assert b.status_code==200
                org_b=b.json()['user']['org_id']
                thread=api.post('/api/messenger/threads',headers=h,json={'recipient_org_id':org_b})
                assert thread.status_code==201,thread.text
                tid=thread.json()['id']
                for n in range(12):
                    resp=api.post(f'/api/messenger/threads/{tid}/messages',headers=h,
                                  json={'content':f'순서 {n:02} '+'테스트 내용 '*18,'request_id':uuid.uuid4().hex})
                    assert resp.status_code==201,resp.text
                for width,height in [(1440,900),(390,844)]:
                    with sync_playwright() as p:
                        browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
                        page=browser.new_page(viewport={'width':width,'height':height},device_scale_factor=1)
                        def backend(source,path,method,headers,body):
                            r=api.request(method,path,headers=headers,content=body.encode() if body is not None else None)
                            return {'status':r.status_code,'body':r.text,'content_type':r.headers.get('content-type','application/json')}
                        page.expose_binding('__backend',backend)
                        html=(ROOT/'app/static/index.html').read_text().replace('<script src="/static/app.js" defer></script>','')
                        page.set_content(html)
                        page.add_style_tag(content=(ROOT/'app/static/style.css').read_text())
                        page.evaluate('''window.fetch=async function(path,options={}){
                           const r=await window.__backend(path,options.method||'GET',options.headers||{},options.body??null);
                           return new Response(r.body,{status:r.status,headers:{'Content-Type':r.content_type}});
                        }; void 0;''')
                        page.add_script_tag(content=(ROOT/'app/static/app.js').read_text())
                        page.locator('#app-shell:not(.hidden)').wait_for(timeout=10000)
                        if width<730:page.locator('#toggle-menu').click()
                        page.locator('[data-page="messenger"]').click()
                        page.locator('#jw-message-list .jw-msg').last.wait_for(timeout=10000)
                        assert page.locator('#jw-message-list .jw-msg').count()==12
                        page.wait_for_function('''()=>{const x=document.querySelector('#jw-message-list');return x && x.scrollHeight-x.scrollTop-x.clientHeight<80}''',timeout=4000)
                        page.wait_for_function('''()=>{const t=state.messengerThreads[0];return t&&t.unread_count===0}''',timeout=5000)
                        page.locator('[data-action="messenger-toggle-plus"]').click()
                        assert page.locator('#jw-plus-menu').is_visible()
                        assert page.locator('#jw-company-query').is_visible()
                        page.locator('#jw-company-query').fill('한빛')
                        page.wait_for_timeout(450)
                        assert page.locator('#jw-company-results').inner_text().find('한빛테크')>=0
                        path=ROOT/'proof'/f'v24_messenger_{width}px.png'
                        page.screenshot(path=str(path),full_page=True)
                        browser.close()
                print('V2.4 BROWSER: PASS Chromium 1440x900 + 390x844, real API bridge (not actual network/iPhone)')
        finally:
            main.DB_PATH=original

if __name__=='__main__': execute()
