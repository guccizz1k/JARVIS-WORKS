"""Authenticated real FastAPI TestClient + Chromium UI integration, synthetic data."""
from __future__ import annotations
import os
import sys
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app import main


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
                customers=api.get('/api/customers',headers=head).json()
                quote=api.post('/api/quotes',headers=head,json={'customer_id':customers[0]['id'],
                    'title':'자동화 UI 검증', 'vat_mode':'taxable',
                    'items':[{'name':'검증 물품', 'quantity':2, 'unit_price':11000}]}).json()
                for s in ['sent','accepted']:
                    r=api.post('/api/quotes/'+quote['id']+'/status',headers=head,json={'status':s})
                    assert r.status_code==200,r.text
                r=api.post('/api/orders/from-quote',headers=head,json={'quote_id':quote['id'],'due_date':'2099-12-30'})
                assert r.status_code==201,r.text
                order=r.json()
                for s in ['processing','fulfilled']:
                    r=api.post('/api/orders/'+order['id']+'/status',headers=head,json={'status':s})
                    assert r.status_code==200,r.text
                with sync_playwright() as p:
                    for width,height in [(1440,900),(390,844)]:
                        browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
                        page=browser.new_page(viewport={'width':width,'height':height},device_scale_factor=1)
                        def backend(source,path,method,headers,body):
                            headers=dict(headers);headers['Cookie']=head['Cookie']
                            if method not in ['GET','HEAD'] and path!='/api/login':headers['X-CSRF-Token']=head['X-CSRF-Token']
                            r=api.request(method,path,headers=headers,content=body.encode() if body is not None else None)
                            return {'status':r.status_code,'body':r.text,'content_type':r.headers.get('content-type','application/json')}
                        page.expose_binding('__backend',backend)
                        html=(ROOT/'app/static/index.html').read_text().replace('<script src="/static/app.js" defer></script>','').replace('<script src="/static/automation_v61.js" defer></script>','').replace('<script src="/static/automation_v62.js" defer></script>','')
                        page.set_content(html)
                        page.add_style_tag(content=(ROOT/'app/static/style.css').read_text())
                        page.evaluate('''window.fetch=async function(path,options={}){
                            const r=await window.__backend(path,options.method||'GET',options.headers||{},options.body??null);
                            return new Response(r.body,{status:r.status,headers:{'Content-Type':r.content_type}});
                        }; void 0;''')
                        page.add_script_tag(content=(ROOT/'app/static/app.js').read_text())
                        page.add_script_tag(content=(ROOT/'app/static/automation_v61.js').read_text())
                        page.add_script_tag(content=(ROOT/'app/static/automation_v62.js').read_text())
                        page.locator('#app-shell:not(.hidden)').wait_for(timeout=15000)
                        if width<730:page.locator('#toggle-menu').click()
                        page.locator('[data-page="automation"]').click()
                        page.locator('[data-action="auto-create"]').first.wait_for(timeout=15000)
                        assert page.locator('#main-content').inner_text().find('업무 절감시간 측정')>=0
                        page.locator('[data-action="auto-create"]').first.click()
                        page.get_by_text('거래명세표 번호').wait_for(timeout=15000)
                        assert page.get_by_text('22,000원').count()>0
                        if width==1440:
                            with page.expect_popup(timeout=10000) as popup_info:
                                page.locator('[data-action="auto-print"]').click()
                            popup=popup_info.value
                            popup.locator('h1').get_by_text('거래명세표').wait_for(timeout=10000)
                            assert popup.get_by_text('24,200원').count()>0
                            popup.close()
                        page.keyboard.press('Escape')
                        page.locator('[data-action="auto-trace"]').first.click()
                        page.get_by_text('거래 통합 이력').wait_for(timeout=15000)
                        page.keyboard.press('Escape')
                        if width==1440:
                            page.locator('[data-action="auto-manual-start"]').click()
                            assert '진행 중' in page.locator('#jw-auto-status').inner_text()
                            page.locator('[data-action="auto-timer-cancel"]').click()
                            page.wait_for_function("()=>document.querySelector('#jw-auto-status')?.textContent.includes('진행 중인 측정 없음')",timeout=10000)
                        page.evaluate("document.querySelector('#toast').className=''")
                        (ROOT/'proof').mkdir(exist_ok=True)
                        page.screenshot(path=str(ROOT/'proof'/f'v61_automation_{width}px.png'),full_page=True)
                        browser.close()
                print('V6.1 BROWSER: PASS 1440x900 + 390x844 in-process authenticated API; not public deployment')
        finally:
            main.DB_PATH=original

if __name__=='__main__':run()
