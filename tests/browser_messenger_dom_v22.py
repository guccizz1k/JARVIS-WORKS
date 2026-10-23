"""Chromium UI + real FastAPI TestClient backend via in-process fetch bridge.

The runner host blocks all Chromium HTTP navigation (ERR_BLOCKED_BY_ADMINISTRATOR).
Using about:blank + JS bridge still runs the genuine client DOM/UI and real backend,
but it is NOT a full HTTP browser integration test.
"""
from __future__ import annotations
import os,sys,tempfile,pathlib
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import app.main as app

def login(page,company):
    page.locator('#login-form [name=email]').fill(f'demo@{"hanbit" if company=="한빛테크" else "bada"}.example')
    page.locator('#login-form [name=password]').fill('Demo!2026secure')
    page.locator('#login-form [type=submit]').click()
    page.locator('[data-page="messenger"]').wait_for(state='visible')
    page.locator('#app-shell:not(.hidden)').wait_for()

def main():
    with tempfile.TemporaryDirectory() as work:
      os.environ['DEMO_SEED']='1'
      old=app.DB_PATH;app.DB_PATH=pathlib.Path(work)/'demo.db'
      try:
       with TestClient(app.app,base_url='https://testserver') as api:
        with sync_playwright() as pw:
         browser=pw.chromium.launch(executable_path='/usr/bin/chromium',args=['--no-sandbox'],headless=True)
         context=browser.new_context(viewport={'width':1440,'height':900})
         page=context.new_page()
         def backend(source,path,method,headers,body):
            if path is None:
                return {'status':400,'body':'{}','content_type':'application/json'}
            r=api.request(method,path,headers=headers,content=body.encode('utf8') if body is not None else None)
            return {'status':r.status_code,'body':r.text,'content_type':r.headers.get('content-type','application/json')}
         page.expose_binding('__backend',backend)
         page.add_init_script('''window.fetch=async function(path,options={}){
           const r=await window.__backend(path,options.method||'GET',options.headers||{},options.body??null);
           return new Response(r.body,{status:r.status,headers:{'Content-Type':r.content_type}});
         };''')
         html=(ROOT/'app/static/index.html').read_text();html=html.replace('<script src="/static/app.js" defer></script>','')
         page.set_content(html)
         page.add_style_tag(content=(ROOT/'app/static/style.css').read_text())
         # init scripts are not run on set_content. Explicit bridge install for current document.
         page.evaluate('''window.fetch=async function(path,options={}){
           const r=await window.__backend(path,options.method||'GET',options.headers||{},options.body??null);
           return new Response(r.body,{status:r.status,headers:{'Content-Type':r.content_type}});
         };''')
         page.add_script_tag(content=(ROOT/'app/static/app.js').read_text())
         page.locator('#login-form').wait_for()
         login(page,'한빛테크')
         page.locator('[data-page="messenger"]').click()
         page.locator('#messenger-connect-form select').select_option(label='바다유통')
         page.locator('#messenger-connect-form button[type=submit]').click()
         page.wait_for_timeout(750)
         page.get_by_text('상대 기업 수락 대기',exact=True).first.wait_for(timeout=3000)
         page.locator('#logout').click()
         login(page,'바다유통')
         page.locator('[data-page="messenger"]').click()
         page.locator('[data-action="messenger-open"]').first.click()
         page.get_by_role('button',name='기업 대화 요청 수락').click()
         page.locator('#messenger-send-form textarea').fill('한빛테크 담당자님, 발주 검토하겠습니다.')
         page.locator('#messenger-send-form button[type=submit]').click()
         page.get_by_text('한빛테크 담당자님, 발주 검토하겠습니다.').wait_for(timeout=8000)
         page.locator('#logout').click()
         login(page,'한빛테크')
         page.locator('[data-page="messenger"]').click()
         page.locator('[data-action="messenger-open"]').first.click()
         page.get_by_text('한빛테크 담당자님, 발주 검토하겠습니다.').wait_for()
         page.locator('#messenger-send-form textarea').fill('네, 부탁드립니다. 전산 발주서도 전달하겠습니다.')
         page.locator('#messenger-send-form button[type=submit]').click()
         page.wait_for_timeout(1000)
         page.get_by_text('네, 부탁드립니다. 전산 발주서도 전달하겠습니다.').wait_for(timeout=8000)
         page.wait_for_timeout(4600)
         out=ROOT/'proof/v22_company_messenger_desktop.png';out.parent.mkdir(exist_ok=True)
         page.screenshot(path=str(out),full_page=True)
         print('CHROMIUM_DOM_BACKEND_DESKTOP_PASS',out)
         page.set_viewport_size({'width':390,'height':844})
         page.screenshot(path=str(ROOT/'proof/v22_company_messenger_mobile_view.png'),full_page=True)
         print('CHROMIUM_MOBILE_VIEWPORT_RENDER_PASS')
         browser.close()
      finally:
        app.DB_PATH=old
if __name__=='__main__':main()
