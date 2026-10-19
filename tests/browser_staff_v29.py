"""V2.9 desktop/mobile Chromium staff offboarding UI with real TestClient API.

No external HTTP port or real customer data. Browser script/CSS are actual source.
"""
from pathlib import Path
import tempfile
import os
import sys
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app import main


def run():
    original=main.DB_PATH
    old_seed=os.environ.get('DEMO_SEED')
    with tempfile.TemporaryDirectory() as tmp:
        try:
            main.DB_PATH=Path(tmp)/'synthetic.db'
            os.environ['DEMO_SEED']='1'
            with TestClient(main.app,base_url='https://testserver') as api:
                with main.transaction() as db:
                    org=db.execute("SELECT org_id FROM users WHERE email='demo@hanbit.example'").fetchone()['org_id']
                    db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                               ('staff_ui',org,'staff_ui@example.invalid',main.hash_password('StrongStaff-2026!'),
                                'UI 검증 담당','member',main.now()))
                with sync_playwright() as pw:
                    browser=pw.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
                    for width,height in [(1440,900),(390,844)]:
                        login=api.post('/api/login',json={'email':'demo@hanbit.example','password':'Demo!2026secure'})
                        assert login.status_code==200,login.text
                        auth={'Cookie':main.SESSION_COOKIE+'='+login.cookies.get(main.SESSION_COOKIE),
                              'X-CSRF-Token':login.json()['csrf_token']}
                        page=browser.new_page(viewport={'width':width,'height':height},device_scale_factor=1)
                        errors=[]
                        page.on('pageerror',lambda exc:errors.append(str(exc)))
                        def bridge(src,path,method,headers,body):
                            all_headers={**auth,**(headers or {})}
                            response=api.request(method,path,headers=all_headers,content=body.encode() if body else None)
                            return {'status':response.status_code,'body':response.text,
                                    'content_type':response.headers.get('content-type','application/json')}
                        page.expose_binding('__backend',bridge)
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
                        page.locator('[data-page="security"]').click()
                        page.get_by_role('heading',name='보안 관제 센터').wait_for(timeout=10000)
                        row=page.locator('.staff-entry').filter(has_text='UI 검증 담당').first
                        assert '활성' in row.inner_text()
                        row.get_by_role('button',name='접속·계정 중지').click()
                        page.locator('#staff-status-form input[name=admin_password]').fill('Demo!2026secure')
                        page.locator('#staff-status-form button[type=submit]').click()
                        page.wait_for_function("()=>!!document.querySelector('tr') && Array.from(document.querySelectorAll('.staff-entry')).some(x=>x.innerText.includes('UI 검증 담당')&&x.innerText.includes('중지됨'))",timeout=15000)
                        proof=ROOT/'proof';proof.mkdir(exist_ok=True)
                        page.screenshot(path=str(proof/f'v29_staff_security_{width}px.png'),full_page=True)
                        assert not errors,errors
                        if width<730:
                            # Mobile actions still reachable without opening the drawer.
                            assert page.locator('.panel').count()>0
                        row=page.locator('.staff-entry').filter(has_text='UI 검증 담당').first
                        row.get_by_role('button',name='계정 복구').click()
                        page.locator('#staff-status-form input[name=admin_password]').fill('Demo!2026secure')
                        page.locator('#staff-status-form button[type=submit]').click()
                        page.wait_for_function("()=>Array.from(document.querySelectorAll('.staff-entry')).some(x=>x.innerText.includes('UI 검증 담당')&&x.innerText.includes('활성'))",timeout=15000)
                        page.close()
                    browser.close()
            print('V2.9 CHROMIUM: PASS 1440x900 + 390x844, disable->enable, in-process API bridge')
        finally:
            main.DB_PATH=original
            if old_seed is None:os.environ.pop('DEMO_SEED',None)
            else:os.environ['DEMO_SEED']=old_seed

if __name__=='__main__':run()
