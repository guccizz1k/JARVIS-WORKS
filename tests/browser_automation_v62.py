"""Synthetic authenticated Chromium UI check for new document drafts and bulk flow."""
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
                cust=api.get('/api/customers',headers=head).json()[0]
                quote=api.post('/api/quotes',headers=head,json={'customer_id':cust['id'],
                    'title':'원클릭 문서 변환 통합 검증','vat_mode':'taxable',
                    'items':[{'name':'신규 제품 A','quantity':3,'unit_price':9000}]}).json()
                for status in ('sent','accepted'):
                    assert api.post('/api/quotes/'+quote['id']+'/status',headers=head,json={'status':status}).status_code==200
                order=api.post('/api/orders/from-quote',headers=head,json={'quote_id':quote['id'],'due_date':'2099-12-30'}).json()
                for status in ('processing','fulfilled'):
                    assert api.post('/api/orders/'+order['id']+'/status',headers=head,json={'status':status}).status_code==200
                assert api.post('/api/invoices/from-order',headers=head,json={'order_id':order['id'],'due_date':'2099-12-30'}).status_code==201
                with sync_playwright() as p:
                    for width,height in ((1440,900),(390,844)):
                        browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
                        page=browser.new_page(viewport={'width':width,'height':height},device_scale_factor=1)
                        errors=[]
                        page.on('pageerror',lambda exc:errors.append(str(exc)))
                        def backend(source,path,method,headers,body):
                            h=dict(headers);h['Cookie']=head['Cookie']
                            if method not in ('GET','HEAD') and path!='/api/login':h['X-CSRF-Token']=head['X-CSRF-Token']
                            result=api.request(method,path,headers=h,content=body.encode() if body is not None else None)
                            return {'status':result.status_code,'body':result.text,'content_type':result.headers.get('content-type','application/json')}
                        page.expose_binding('__backend',backend)
                        html=(ROOT/'app/static/index.html').read_text()
                        for name in ('app.js','automation_v61.js','automation_v62.js'):
                            html=html.replace(f'<script src="/static/{name}" defer></script>','')
                        page.set_content(html)
                        page.add_style_tag(content=(ROOT/'app/static/style.css').read_text())
                        page.evaluate('''window.fetch=async function(path,options={}){
                            const r=await window.__backend(path,options.method||'GET',options.headers||{},options.body??null);
                            return new Response(r.body,{status:r.status,headers:{'Content-Type':r.content_type}});
                        }; void 0;''')
                        for name in ('app.js','automation_v61.js','automation_v62.js'):
                            page.add_script_tag(content=(ROOT/'app/static'/name).read_text())
                        page.locator('#app-shell:not(.hidden)').wait_for(timeout=15000)
                        if width<730:page.locator('#toggle-menu').click()
                        page.locator('[data-page="automation"]').click()
                        page.get_by_text('추가 원클릭 문서 작성').wait_for(timeout=15000)
                        assert page.locator('[data-action="auto-v62-sales"]').count()>=1
                        page.locator('[data-action="auto-v62-sales"]').first.click()
                        page.get_by_text('수주서 초안',exact=True).first.wait_for(timeout=15000)
                        assert page.get_by_text('29,700원').count()>0
                        if width == 1440:
                            with page.expect_popup(timeout=10000) as pop:
                                page.locator('[data-action="auto-v62-print"]').click()
                            popup=pop.value
                            popup.get_by_text('수주서 초안',exact=True).first.wait_for(timeout=10000)
                            assert popup.get_by_text('29,700원').count()>0
                            popup.close()
                        page.keyboard.press('Escape')
                        page.locator('.jw-v62-order').first.check()
                        page.locator('[data-action="auto-v62-batch"]').click()
                        page.get_by_text('납품서 초안',exact=True).first.wait_for(timeout=15000)
                        page.keyboard.press('Escape')
                        page.locator('[data-action="auto-v62-payment"]').first.click()
                        page.get_by_text('입금요청서 초안',exact=True).first.wait_for(timeout=15000)
                        page.keyboard.press('Escape')
                        assert not errors,errors
                        page.evaluate("document.querySelector('#toast').className=''")
                        (ROOT/'proof').mkdir(exist_ok=True)
                        page.screenshot(path=str(ROOT/'proof'/f'v62_automation_{width}px.png'),full_page=True,animations='disabled')
                        if width<730:page.locator('#toggle-menu').click()
                        page.locator('[data-page="dashboard"]').click()
                        page.get_by_text('자동 작성된 업무 문서',exact=True).wait_for(timeout=15000)
                        assert page.locator('[data-action="auto-v62-open"]').count()==3
                        page.screenshot(path=str(ROOT/'proof'/f'v62_dashboard_{width}px.png'),full_page=True,animations='disabled')
                        # Horizontal overflow detection on responsive work area.
                        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth+2'),f'mobile overflow {width}'
                        browser.close()
                print('V6.2 BROWSER PASS: PC 1440 + mobile 390, transactional API-backed click path')
        finally:
            main.DB_PATH=original

if __name__=='__main__':run()
