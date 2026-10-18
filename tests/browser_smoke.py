"""Browser rendering and UI integration using in-process FastAPI TestClient bridge.

Local browser network requests are administrator blocked here. Browser DOM/actions run
in Chromium, while each fetch is executed against the actual API in-process.
"""
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from playwright.sync_api import sync_playwright
from fastapi.testclient import TestClient
import app.main as backend
import os

ROOT=Path(__file__).resolve().parents[1]
os.environ['DEMO_SEED']='1'

with TemporaryDirectory() as temp:
 backend.DB_PATH=Path(temp)/'browser.db'
 with TestClient(backend.app,base_url='https://testserver') as client, sync_playwright() as pw:
    browser=pw.chromium.launch(headless=True,executable_path=(os.environ.get('CHROMIUM_PATH') or shutil.which('chromium') or pw.chromium.executable_path),args=['--no-sandbox'])
    screenshot_dir=Path(os.environ.get('SCREENSHOT_DIR',str(ROOT/'previews')))
    screenshot_dir.mkdir(parents=True,exist_ok=True)
    html=(ROOT/'app/static/index.html').read_text()
    css=(ROOT/'app/static/style.css').read_text()
    js=(ROOT/'app/static/app.js').read_text()
    html=html.replace('<link rel="stylesheet" href="/static/style.css">','<style>'+css+'</style>')
    html=html.replace('<script src="/static/app.js" defer></script>','')
    def bridge(path,options=None):
        options=options or {}
        import json
        data=json.loads(options['body']) if options.get('body') else None
        response=client.request(options.get('method','GET'),path,headers=options.get('headers',{}),json=data)
        try: decoded=response.json()
        except: decoded={'error':response.text}
        return {'status':response.status_code,'data':decoded}

    for device in ['desktop','mobile']:
        client.cookies.clear()  # Independent browser profile per viewport.
        kwargs={'viewport':{'width':1440,'height':900}} if device=='desktop' else {'viewport':{'width':390,'height':844},'is_mobile':True,'device_scale_factor':2,'has_touch':True}
        page=browser.new_page(**kwargs)
        page.set_default_timeout(9000)
        def go(target):
            if device=='mobile':
                if 'open' not in (page.locator('#sidebar').get_attribute('class') or ''):
                    page.locator('#toggle-menu').click()
                page.locator('#sidebar.open').wait_for()
                page.wait_for_timeout(280)
            page.locator(f'nav [data-page={target}]').click()
            page.wait_for_timeout(300)  # Wait for mobile drawer close animation before screenshots.
        errors=[]
        page.on('pageerror',lambda err:errors.append(str(err)))
        page.expose_function('py_api_request',bridge)
        page.set_content(html)
        page.evaluate("""() => {window.fetch=async(url,options={})=>{const r=await window.py_api_request(url,options);return {ok:r.status>=200&&r.status<300,status:r.status,json:async()=>r.data}}}""")
        page.evaluate("""() => {const memory={};Object.defineProperty(window,'sessionStorage',{configurable:true,value:{getItem:k=>memory[k]||null,setItem:(k,v)=>memory[k]=v,removeItem:k=>delete memory[k]}})}""")
        page.add_script_tag(content=js)
        page.wait_for_timeout(150)
        page.screenshot(path=str(screenshot_dir/f'{device}_jw_login.png'),full_page=True)

        page.locator('#login-form [type=submit]').click()


        page.get_by_role('heading',name='업무 대시보드').wait_for(timeout=10000)
        assert page.locator('.cards .card').count()==4
        page.screenshot(path=str(screenshot_dir/f'{device}_jw_dashboard.png'),full_page=True)
        # New v1.2 administrator security monitoring UI is connected to real API.
        go('security')
        page.get_by_role('heading',name='보안 관제 센터').wait_for()
        assert page.get_by_text('현재 회사 소속').count()>=1
        assert page.locator('.security-check-list .state-pending').count()==3
        page.screenshot(path=str(screenshot_dir/f'{device}_jw_security.png'),full_page=True)
        go('dashboard')

        print('STAGE navigate quotes',device,flush=True)
        go('customers')
        company=page.locator('tr').filter(has_text='미래부품').first
        company.get_by_role('button',name='수정').click()
        page.locator('input[name=contact_name]').fill('화면 검증 담당자')
        page.get_by_role('button',name='변경 저장').click()
        page.get_by_text('화면 검증 담당자').first.wait_for()
        go('quotes')
        print('STAGE quote page',device,flush=True)
        page.get_by_role('heading',name='견적 관리').wait_for()
        print('STAGE open quote',device,flush=True)
        page.locator('[data-action=new-quote]').click()
        page.locator('input[name=title]').fill('브라우저 검증 '+device)
        page.locator('input[name=item_name]').fill('테스트 부품')
        page.locator('input[name=quantity]').fill('7')
        page.locator('input[name=unit_price]').fill('150')
        assert '1,155원' in page.locator('#money-preview').inner_text()
        print('STAGE create quote',device,flush=True)
        page.locator('#entity-form button[type=submit]').click()
        page.get_by_text('브라우저 검증 '+device).first.wait_for()
        page.locator('#list-search').fill('존재하지않는견적')
        assert page.locator('tbody tr:visible').count()==0
        assert page.locator('#search-count').inner_text().startswith('0 /')
        page.locator('#list-search').fill('브라우저 검증 '+device)
        assert page.locator('tbody tr:visible').count()==1
        page.locator('#list-search').fill('')

        row=page.locator('tr').filter(has_text='브라우저 검증 '+device)
        print('STAGE quote detail',device,flush=True)
        row.get_by_role('button',name='상세').click()
        print('STAGE dialog',device,flush=True)
        page.once('dialog',lambda d:d.accept())
        page.get_by_role('button',name='발송 처리').click()
        row=page.locator('tr').filter(has_text='브라우저 검증 '+device)
        print('STAGE quote detail',device,flush=True)
        row.get_by_role('button',name='상세').click()
        print('STAGE dialog',device,flush=True)
        page.once('dialog',lambda d:d.accept())
        page.get_by_role('button',name='승인 처리').click()
        row=page.locator('tr').filter(has_text='브라우저 검증 '+device)
        row.get_by_role('button',name='발주 전환').click()
        page.get_by_role('button',name='발주 생성').click()
        page.get_by_text('저장되었습니다').wait_for()
        print('STAGE orders',device,flush=True)
        go('orders')
        row=page.locator('tr').filter(has_text='브라우저 검증 '+device)
        row.get_by_role('button',name='검증/관리').click()
        print('STAGE dialog',device,flush=True)
        page.once('dialog',lambda d:d.accept())
        page.get_by_role('button',name='업무 시작').click()
        row=page.locator('tr').filter(has_text='브라우저 검증 '+device)
        row.get_by_role('button',name='검증/관리').click()
        print('STAGE dialog',device,flush=True)
        page.once('dialog',lambda d:d.accept())
        page.get_by_role('button',name='납품 완료').click()
        row=page.locator('tr').filter(has_text='브라우저 검증 '+device)
        row.get_by_role('button',name='청구').click()
        page.get_by_role('button',name='청구서 생성').click()
        print('STAGE invoices',device,flush=True)
        go('invoices')
        row=page.locator('tr').filter(has_text='1,155원').first
        row.get_by_role('button',name='입금 기록').click()
        page.locator('input[name=amount]').fill('1155')
        page.get_by_role('button',name='입금 확정 기록').click()
        page.locator('tbody .badge.green').first.wait_for()
        paid_row=page.locator('tr').filter(has_text='1,155원').first
        paid_row.get_by_role('button',name='상세').click()
        page.once('dialog',lambda d:d.accept())
        page.get_by_role('button',name='기록 취소').click()
        page.wait_for_timeout(100)
        page.locator('tbody tr').filter(has=page.locator('.badge.orange')).first.wait_for()
        assert '1,155원' in page.locator('tbody tr').filter(has=page.locator('.badge.orange')).first.inner_text()
        page.screenshot(path=str(screenshot_dir/f'{device}_jw_invoices.png'),full_page=True)
        assert not errors,errors
        if device=='mobile':
            bodywidth=page.evaluate('document.body.scrollWidth')
            assert bodywidth<=390,bodywidth
        page.close()
    browser.close()
    print('BROWSER SMOKE: PASS (desktop+mobile, quote-to-payment end-to-end)')
