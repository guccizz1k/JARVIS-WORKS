"""V2.5 Chromium: paginated history, scroll stability, new-event refresh, draft preservation."""
from __future__ import annotations
import os
import sys
import tempfile
import uuid
from pathlib import Path
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app import main


def run():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ['DEMO_SEED']='1'
        original=main.DB_PATH
        main.DB_PATH=Path(tmp)/'works.db'
        try:
            with TestClient(main.app,base_url='https://testserver') as api:
                a=api.post('/api/login',json={'email':'demo@hanbit.example','password':'Demo!2026secure'})
                b=api.post('/api/login',json={'email':'demo@bada.example','password':'Demo!2026secure'})
                org_a=a.json()['user']['org_id'];org_b=b.json()['user']['org_id']
                ah={'Cookie':main.SESSION_COOKIE+'='+a.cookies.get(main.SESSION_COOKIE),'X-CSRF-Token':a.json()['csrf_token']}
                bh={'Cookie':main.SESSION_COOKIE+'='+b.cookies.get(main.SESSION_COOKIE),'X-CSRF-Token':b.json()['csrf_token']}
                thread=api.post('/api/messenger/threads',headers=ah,json={'recipient_org_id':org_b})
                tid=thread.json()['id']
                with main.transaction() as db:
                    ua=db.execute('SELECT id FROM users WHERE org_id=?',(org_a,)).fetchone()['id']
                    for n in range(137):
                        db.execute('''INSERT INTO messenger_messages
                               (id,connection_id,sender_org,sender_user,kind,body,request_id,created_at)
                               VALUES(?,?,?,?,'text',?,?,?)''',
                               (uuid.uuid4().hex,tid,org_a,ua,'기존 메시지 %03d'%n,uuid.uuid4().hex,main.now()))
                with sync_playwright() as p:
                    for width,height in [(1440,900),(390,844)]:
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
                        page.wait_for_function('''()=>document.querySelectorAll('#jw-message-list .jw-msg').length===50''',timeout=10000)
                        assert page.locator('[data-action="messenger-older"]').is_visible()
                        assert ('136' if width==1440 else '초안을 입력 중입니다') in page.locator('#jw-message-list .jw-msg').last.inner_text()
                        page.locator('[data-action="messenger-older"]').click()
                        page.wait_for_function('''()=>document.querySelectorAll('#jw-message-list .jw-msg').length===100''',timeout=10000)
                        page.locator('[data-action="messenger-older"]').click()
                        page.wait_for_function('''n=>document.querySelectorAll('#jw-message-list .jw-msg').length===n''',arg=137 if width==1440 else 139,timeout=10000)
                        assert page.locator('[data-action="messenger-older"]').count()==0
                        assert page.locator('#jw-message-list .jw-msg').first.inner_text().find('000')>=0
                        box=page.locator('#jw-message-list')
                        # Scrolling up must not auto-jump to latest when new text arrives.
                        box.evaluate('(e)=>{e.scrollTop=120}')
                        page.locator('#messenger-send-form [name=content]').fill('초안을 입력 중입니다')
                        posted=api.post(f'/api/messenger/threads/{tid}/messages',headers=bh,
                                        json={'content':f'수신 {width}','request_id':uuid.uuid4().hex})
                        assert posted.status_code==201,posted.text
                        page.evaluate('messengerReceiveUpdates()')
                        page.wait_for_function('''n=>document.querySelectorAll('#jw-message-list .jw-msg').length===n''',arg=138 if width==1440 else 140,timeout=10000)
                        assert page.locator('#messenger-send-form [name=content]').input_value()=='초안을 입력 중입니다'
                        assert box.evaluate('(e)=>e.scrollTop')<300
                        assert page.locator('#jw-message-list .jw-msg').last.inner_text().find('수신')>=0
                        page.locator('[data-action="messenger-toggle-plus"]').click()
                        assert page.locator('#jw-plus-menu').is_visible()
                        # Sending must preserve the already loaded 137+ messages and clear the sent draft.
                        old_count=137 if width==1440 else 139
                        page.locator('#messenger-send-form button[type=submit]').click()
                        page.wait_for_function('''n=>document.querySelectorAll('#jw-message-list .jw-msg').length===n''',arg=old_count+2,timeout=10000)
                        assert page.locator('#messenger-send-form [name=content]').input_value()==''
                        assert page.locator('#jw-message-list .jw-msg').first.inner_text().find('000')>=0
                        (ROOT/'proof').mkdir(exist_ok=True)
                        page.screenshot(path=str(ROOT/'proof'/f'v25_messenger_{width}px.png'),full_page=True)
                        # A company without an active chat still refreshes new incoming thread listings.
                        page.evaluate('''()=>{state.messengerThreadId=null;state.messengerThreads=[]}''')
                        page.evaluate('messengerReceiveUpdates()')
                        page.wait_for_function('''()=>document.querySelectorAll('#jw-thread-list .jw-thread').length>0''',timeout=10000)
                        browser.close()
                print('V2.5 CHROMIUM: PASS 1440x900 + 390x844; real in-process API bridge, not public deployment.')
        finally:main.DB_PATH=original

if __name__=='__main__':run()
