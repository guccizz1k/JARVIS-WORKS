"""Real Chromium/WebKit navigation for the isolated approved V22.3 owner review.

Local HTTPS and synthetic SQLite only. Not a physical iPhone/Safari test,
production deploy, persistent tenant data migration or release certification.
"""
from __future__ import annotations

import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / 'artifacts' / 'v223-owner-browser'

ROUTES = [
    ('home', '홈'), ('docs', '문서'), ('deals', '거래'),
    ('papers', '거래 문서'), ('money', '입금·미수금'),
    ('partners', '거래처'), ('messenger', '메신저'),
    ('automation', '자동화'), ('stats', '통계'),
    ('export', '내보내기'), ('inbox', '승인함'),
    ('files', '첨부 파일'), ('activity', '감사 이력'),
    ('team', '직원'), ('security', '보안'),
    ('settings', '설정'), ('account', '내 계정')
]


def main():
    if os.getenv('JW_ENV') != 'review':
        raise RuntimeError('Review browser test requires JW_ENV=review')
    assert len(ROUTES) == 17 and len({x[0] for x in ROUTES}) == 17
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='jw-v223-owner-browser-') as temp:
        temp = Path(temp)
        cert, key = temp / 'server.crt', temp / 'server.key'
        subprocess.run([
            'openssl','req','-x509','-newkey','rsa:2048','-sha256',
            '-days','1','-nodes','-subj','/CN=localhost',
            '-addext','subjectAltName=DNS:localhost,IP:127.0.0.1',
            '-keyout',str(key),'-out',str(cert)
        ], check=True, capture_output=True)
        key.chmod(0o600)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0))
            port = sock.getsockname()[1]
        origin = f'https://127.0.0.1:{port}'
        env = {**os.environ, 'JW_ENV':'review', 'DEMO_SEED':'1',
               'JARVIS_DB_PATH':str(temp / 'synthetic-owner.db'),
               'JW_ROOT_UI':'owner-visual-review',
               'JW_APPROVED_UI_REVIEW':'ISOLATED_REVIEW_ONLY',
               'JW_NO_EXTERNAL_DATABASE':'1'}
        for key_name in ('BOOTSTRAP_EMAIL','BOOTSTRAP_PASSWORD','BOOTSTRAP_ORG','JW_INSECURE_LOCAL_DEV'):
            env.pop(key_name, None)
        with (temp/'server.log').open('w') as log:
            proc = subprocess.Popen([
                sys.executable,'-m','uvicorn','app.owner_review_app_v223:app',
                '--host','127.0.0.1','--port',str(port),
                '--ssl-certfile',str(cert),'--ssl-keyfile',str(key)],
                cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
            try:
                ssl_context=ssl.create_default_context(cafile=str(cert))
                with httpx.Client(verify=ssl_context,trust_env=False,timeout=8) as probe:
                    for _ in range(120):
                        assert proc.poll() is None, 'Owner review TLS server stopped'
                        try:
                            if probe.get(origin+'/api/health').status_code==200:
                                break
                        except httpx.TransportError:
                            pass
                        time.sleep(.1)
                    else:
                        raise AssertionError('Owner review TLS startup failed')

                with sync_playwright() as playwright:
                    for engine in ('chromium','webkit'):
                        browser_type=getattr(playwright,engine)
                        browser=browser_type.launch(headless=True,
                            args=['--no-sandbox'] if engine=='chromium' else [])
                        try:
                            for width,height in ((1440,900),(390,844)):
                                context=browser.new_context(viewport={'width':width,'height':height},
                                    ignore_https_errors=True,reduced_motion='reduce')
                                page=context.new_page()
                                errors=[]
                                failed_5xx=[]
                                page.on('pageerror',lambda err: errors.append(str(err)))
                                page.on('response',lambda r: failed_5xx.append(r.url)
                                    if r.status>=500 else None)
                                try:
                                    page.goto(origin+'/',wait_until='domcontentloaded',timeout=25000)
                                    page.locator('.jw-review-form input[type=email]').fill('demo@hanbit.example')
                                    page.locator('.jw-review-form input[type=password]').fill('Demo!2026secure')
                                    page.locator('.jw-review-form button[type=submit]').click()
                                    page.locator('.jw-review-shell').wait_for(timeout=30000)
                                    assert page.evaluate("document.documentElement.dataset.theme==='dark'")
                                    # Independent synthetic HTTPS seed; mutations below
                                    # are then performed through the actual browser UI.
                                    with httpx.Client(verify=ssl_context,trust_env=False,timeout=8) as api:
                                        signed=api.post(origin+'/api/login',json={
                                            'email':'demo@hanbit.example',
                                            'password':'Demo!2026secure'})
                                        assert signed.status_code==200,signed.status_code
                                        headers={'X-CSRF-Token':signed.json()['csrf_token']}
                                        customers=api.get(origin+'/api/customers')
                                        assert customers.status_code==200 and customers.json()
                                        customer_id=customers.json()[0]['id']
                                        q=api.post(origin+'/api/quotes',headers=headers,json={
                                            'customer_id':customer_id,
                                            'title':f'Browser order source {engine} {width}',
                                            'vat_mode':'taxable',
                                            'items':[{'name':'Synthetic cable','quantity':2,
                                                      'unit_price':1000}]})
                                        assert q.status_code==201,q.status_code
                                        source_id=q.json()['id']
                                        for phase in ('sent','accepted'):
                                            step=api.post(origin+'/api/quotes/'+source_id+'/status',
                                                headers=headers,json={'status':phase})
                                            assert step.status_code==200,step.status_code
                                        made=api.post(origin+'/api/orders/from-quote',headers=headers,
                                            json={'quote_id':source_id,'due_date':'2099-12-30'})
                                        assert made.status_code==201,made.status_code
                                        browser_order=made.json()
                                        browser_order_id=browser_order['id']
                                        browser_order_no=browser_order['doc_no']
                                        processing=api.post(origin+'/api/orders/'+browser_order_id+
                                            '/status',headers=headers,json={'status':'processing'})
                                        assert processing.status_code==200,processing.status_code
                                    if width < 600:
                                        # Modal accessibility, genuine browser keyboard focus.
                                        menu=page.locator('#jw-owner-menu')
                                        more=page.locator('.jw-owner-bottomnav button[data-action=show-all]')
                                        more.focus()
                                        page.keyboard.press('Enter')
                                        assert menu.get_attribute('aria-hidden')=='false'
                                        assert page.evaluate("""() => document.querySelector(
                                            '.jw-review-shell').inert &&
                                            document.querySelector('.jw-owner-bottomnav').inert""")
                                        assert page.evaluate("""() => document.activeElement.textContent.trim()==='닫기'""")
                                        page.keyboard.press('Shift+Tab')
                                        assert page.evaluate("""() => document.activeElement===document.querySelector(
                                            '.jw-owner-menu-grid button:last-child')""")
                                        page.keyboard.press('Tab')
                                        assert page.evaluate("""() => document.activeElement.textContent.trim()==='닫기'""")
                                        page.keyboard.press('Escape')
                                        assert menu.get_attribute('aria-hidden')=='true'
                                        assert page.evaluate("""() => document.activeElement===document.querySelector(
                                            '.jw-owner-bottomnav button[data-action="show-all"]')""")
                                        assert not page.evaluate("""() => document.querySelector('.jw-review-shell').inert ||
                                            document.querySelector('.jw-owner-bottomnav').inert""")
                                        print(f'PASS_V223_REAL_{engine.upper()}_{width}_MODAL_FOCUS_TRAP_ESCAPE_RETURN',flush=True)
                                    for route,label in ROUTES:
                                        if width < 600:
                                            page.locator('.jw-owner-bottomnav button[data-action=show-all]').click()
                                            page.locator(f'.jw-owner-menu-grid button[data-page="{route}"]').click()
                                        else:
                                            page.locator(f'.jw-review-nav button[data-page="{route}"]').click()
                                        page.wait_for_function(
                                            "label => document.querySelector('h2.jw-review-title')?.textContent===label",
                                            arg=label,timeout=18000)
                                        page.wait_for_timeout(170)
                                        if route == 'deals':
                                            # Real browser: create a server-side draft, modify its
                                            # item and title via CAS, and verify readback via HTTPS.
                                            quote_title=f'Browser Quote {engine}-{width}'
                                            new_title=f'Browser Quote Edited {engine}-{width}'
                                            quote_form=page.locator('form.jw-review-action-form').filter(
                                                has=page.locator('h4',has_text='견적서 서버 생성')).first
                                            quote_form.locator('input[aria-label="견적 제목"]').fill(quote_title)
                                            quote_form.locator('input[aria-label="품목명"]').fill('Synthetic Part')
                                            quote_form.locator('input[aria-label="수량"]').fill('1')
                                            quote_form.locator('input[aria-label="단가(원)"]').fill('1000')
                                            quote_form.locator('button[type=submit]').click()
                                            page.wait_for_function("""title => {
                                               const p=document.querySelector('h2.jw-review-title');
                                               return p?.textContent==='거래';
                                            }""",arg=quote_title,timeout=15000)
                                            page.wait_for_timeout(120)
                                            created_quotes=page.evaluate("""async () => {
                                               const r=await fetch('/api/quotes',{credentials:'same-origin'});
                                               if(!r.ok)throw Error('draft readback '+r.status);
                                               return r.json();
                                            }""")
                                            created_quote=next((q for q in created_quotes
                                                if q['title']==quote_title),None)
                                            assert created_quote,(engine,width,'QUOTE_NOT_CREATED')
                                            page.get_by_role('button',
                                                name=created_quote['doc_no']+' · 초안 수정').click()
                                            quote_editor=page.locator('form.jw-review-action-form').filter(
                                                has=page.get_by_role('button',name='견적 초안 저장')).last
                                            quote_editor.wait_for(timeout=15000)
                                            quote_editor.locator('input[aria-label="견적 제목"]').fill(new_title)
                                            quote_editor.locator('input[aria-label="수량"]').fill('3')
                                            quote_editor.locator('input[aria-label="단가(원)"]').fill('450')
                                            quote_editor.locator('button[type=submit]').click()
                                            page.get_by_text('견적 초안을 서버에 저장하고 재조회했습니다.',
                                                exact=False).wait_for(timeout=20000)
                                            after=page.evaluate("""async (quoteId) => {
                                               const r=await fetch('/api/quotes/'+quoteId,{
                                                 credentials:'same-origin',cache:'no-store'});
                                               if(!r.ok)throw Error('quote readback '+r.status);
                                               return r.json();
                                            }""",created_quote['id'])
                                            assert after['title']==new_title,(engine,width,'QUOTE_TITLE')
                                            assert after['money']['total']==1485,(engine,width,'QUOTE_MONEY')
                                            assert after['items'][0]['quantity']==3,(engine,width,'QUOTE_QUANTITY')
                                            print(f'PASS_V223_REAL_{engine.upper()}_{width}_QUOTE_DRAFT_CAS_HTTPS',flush=True)
                                        if route == 'money':
                                            panel=page.locator('.jw-review-order-panel')
                                            panel.wait_for(timeout=20000)
                                            panel.get_by_role('button',
                                                name=browser_order_no+' · 변경·검토').click()
                                            form=panel.locator('form.jw-review-action-form').last
                                            form.wait_for(timeout=15000)
                                            form.locator('input[aria-label="수량"]').first.fill('3')
                                            form.locator('textarea[aria-label="수주 변경 사유 (5자 이상)"]').fill(
                                                'Browser QA requested quantity change')
                                            page.once('dialog',lambda dialog:dialog.accept())
                                            form.locator('button[type=submit]').click()
                                            panel.get_by_text('수주 변경 서버 저장·재조회 완료',
                                                exact=False).wait_for(timeout=20000)
                                            with httpx.Client(verify=ssl_context,trust_env=False,
                                                              timeout=8) as verify:
                                                login=verify.post(origin+'/api/login',json={
                                                    'email':'demo@hanbit.example',
                                                    'password':'Demo!2026secure'})
                                                assert login.status_code==200
                                                csrf={'X-CSRF-Token':login.json()['csrf_token']}
                                                current=verify.get(origin+'/api/review/orders/'+
                                                   browser_order_id+'/edit-context')
                                                assert current.status_code==200
                                                order_doc=current.json()['order']
                                                assert order_doc['review_state']=='pending'
                                                assert order_doc['items'][0]['quantity']==3
                                                assert order_doc['money']['total']==3300
                                                blocked=verify.post(origin+'/api/orders/'+browser_order_id+
                                                    '/status',headers=csrf,json={'status':'fulfilled'})
                                                assert blocked.status_code==409
                                            page.once('dialog',lambda dialog:dialog.accept())
                                            panel.get_by_role('button',name='변경사항 확인·승인').click()
                                            panel.get_by_text('관리자 변경 확인·서버 재조회 완료',
                                                exact=False).wait_for(timeout=20000)
                                            with httpx.Client(verify=ssl_context,trust_env=False,
                                                              timeout=8) as verify:
                                                login=verify.post(origin+'/api/login',json={
                                                    'email':'demo@hanbit.example',
                                                    'password':'Demo!2026secure'})
                                                assert login.status_code==200
                                                csrf={'X-CSRF-Token':login.json()['csrf_token']}
                                                status=verify.get(origin+'/api/orders/'+browser_order_id)
                                                assert status.status_code==200
                                                assert status.json()['review_state']=='acknowledged'
                                                fulfilled=verify.post(origin+'/api/orders/'+browser_order_id+
                                                    '/status',headers=csrf,json={'status':'processing'})
                                                assert fulfilled.status_code==409  # already processing
                                                fulfilled=verify.post(origin+'/api/orders/'+browser_order_id+
                                                    '/status',headers=csrf,json={'status':'fulfilled'})
                                                assert fulfilled.status_code==200
                                            print(f'PASS_V223_REAL_{engine.upper()}_{width}_ORDER_EDIT_ACK_HTTPS',flush=True)
                                            # Real UI: invoice creation, payment and admin reversal.
                                            # Reload money to include the newly fulfilled order.
                                            if width < 600:
                                                page.locator('.jw-owner-bottomnav button[data-action=show-all]').click()
                                                page.locator('.jw-owner-menu-grid button[data-page="money"]').click()
                                            else:
                                                page.locator('.jw-review-nav button[data-page="money"]').click()
                                            invoice_form=page.locator('form.jw-review-action-form').filter(
                                                has=page.locator('h4',has_text='납품 완료 수주에서 청구서 생성')).first
                                            invoice_form.wait_for(timeout=20000)
                                            invoice_form.locator('select[aria-label="납품 완료 수주"]').select_option(
                                                browser_order_id)
                                            invoice_form.locator('input[aria-label="입금기한"]').fill('2099-12-31')
                                            # A click is NOT a completed server write.
                                            # Observe the authenticated POST response then the
                                            # refreshed server-rendered finance panel. This
                                            # prevents racing the still-pending invoice write.
                                            with page.expect_response(
                                                lambda r:r.url.endswith('/api/invoices/from-order')
                                                 and r.request.method=='POST',
                                                timeout=20000) as response_wait:
                                                invoice_form.locator('button[type=submit]').click()
                                            issued=response_wait.value
                                            assert issued.status==201,(engine,width,'INVOICE_HTTP',issued.status)
                                            current_invoice=issued.json()
                                            assert current_invoice['order_id']==browser_order_id
                                            assert current_invoice['money']['total']==3300
                                            invoice_id=current_invoice['id']
                                            finance=page.locator('.jw-review-finance-panel')
                                            invoice_button=finance.get_by_role('button',
                                                name=current_invoice['doc_no']+' · 입금·정산 확인')
                                            invoice_button.wait_for(state='visible',timeout=20000)
                                            invoice_button.click()
                                            invoices=page.evaluate("""async () => {
                                               const response=await fetch('/api/invoices',{
                                                 credentials:'same-origin',cache:'no-store'});
                                               if(!response.ok)throw Error('invoice list HTTP '+response.status);
                                               return response.json();
                                            }""")
                                            matching=[x for x in invoices if x['order_id']==browser_order_id]
                                            assert len(matching)==1,(engine,width,'INVOICE_READBACK_MISMATCH')
                                            assert matching[0]['id']==invoice_id
                                            finance.get_by_text('원본 수주·청구·입금 원장 대조 완료',
                                                exact=False).wait_for(timeout=16000)
                                            payment_form=finance.locator('form.jw-review-action-form').last
                                            payment_form.locator('input[aria-label="입금 고유 요청번호"]').fill(
                                                f'BRW-PAY-{engine.upper()}-{width}')
                                            payment_form.locator('input[aria-label="입금액(원)"]').fill('3300')
                                            page.once('dialog',lambda dialog:dialog.accept())
                                            payment_form.locator('button[type=submit]').click()
                                            finance.get_by_text('입금 처리·원장 잔액 재조회 완료',
                                                exact=False).wait_for(timeout=20000)
                                            paid_invoice=page.evaluate("""async invoiceId => {
                                               const response=await fetch('/api/invoices/'+invoiceId,{
                                                 credentials:'same-origin',cache:'no-store'});
                                               if(!response.ok)throw Error('invoice detail HTTP '+response.status);
                                               return response.json();
                                            }""",invoice_id)
                                            assert paid_invoice['paid']==3300,(engine,width,'PAID')
                                            assert paid_invoice['balance']==0,(engine,width,'BALANCE')
                                            page.once('dialog',lambda dialog:dialog.accept())
                                            finance.get_by_role('button',name='입금 반제 · BRW-PAY-'+
                                                engine.upper()+'-'+str(width)).click()
                                            finance.get_by_text('입금 반제 및 서버 원장 재조회 완료',
                                                exact=False).wait_for(timeout=20000)
                                            after_reverse=page.evaluate("""async invoiceId => {
                                               const response=await fetch('/api/invoices/'+invoiceId,{
                                                 credentials:'same-origin',cache:'no-store'});
                                               if(!response.ok)throw Error('invoice reversal readback '+response.status);
                                               return response.json();
                                            }""",invoice_id)
                                            assert after_reverse['paid']==0,(engine,width,'REVERSAL_TOTAL')
                                            assert after_reverse['balance']==3300,(engine,width,'REVERSAL_BALANCE')
                                            assert len(after_reverse['payments'])==1
                                            assert after_reverse['payments'][0]['reversed_at']
                                            print(f'PASS_V223_REAL_{engine.upper()}_{width}_INVOICE_PAYMENT_REVERSAL_HTTPS',flush=True)

                                        if route == 'partners':
                                            # Real user path: create in the approved UI, edit with
                                            # CAS, verify authenticated server state. No mocks.
                                            root=page.locator('.jw-review-view')
                                            created_name=f'Browser QA {engine}-{width}'
                                            edited_name=f'Browser Verified {engine}-{width}'
                                            editor=root.locator('.jw-review-customer-edits')
                                            editor.wait_for(timeout=15000)
                                            create_form=root.locator('form.jw-review-action-form').first
                                            create_form.locator('input[aria-label="거래처명"]').fill(created_name)
                                            create_form.locator('button[type=submit]').click()
                                            editor=root.locator('.jw-review-customer-edits')
                                            editor.get_by_role('button',name=created_name+' · 수정').wait_for(timeout=15000)
                                            editor.get_by_role('button',name=created_name+' · 수정').click()
                                            edit_form=editor.locator('form.jw-review-action-form').first
                                            edit_form.locator('input[name="name"]').fill(edited_name)
                                            edit_form.locator('button[type=submit]').click()
                                            edit_form.get_by_text('서버 저장 및 재조회 완료').wait_for(timeout=15000)
                                            actual=page.evaluate("""async () => {
                                               const response=await fetch('/api/customers',{
                                                 credentials:'same-origin',cache:'no-store'});
                                               if(!response.ok)throw Error('customer readback HTTP '+response.status);
                                               return response.json();
                                            }""")
                                            assert sum(1 for record in actual
                                                if record['name']==edited_name)==1,(engine,width,'CUSTOMER_READBACK')
                                            print(f'PASS_V223_REAL_{engine.upper()}_{width}_CUSTOMER_CREATE_CAS_EDIT_HTTPS',flush=True)
                                        if width > 900:
                                            # Catch real geometry overlap, not just page overflow.
                                            assert page.evaluate("""
                                                (() => {
                                                  const rail=document.querySelector('.jw-review-nav.rail');
                                                  const body=document.querySelector('.jw-review-main.main');
                                                  if(!rail||!body)return false;
                                                  return body.getBoundingClientRect().left>=
                                                    rail.getBoundingClientRect().right+8;
                                                })()
                                            """),(engine,width,route,'EXPANDED_RAIL_COVERS_MAIN')
                                        if route == 'account':
                                            page.wait_for_function("""
                                                () => [...document.querySelectorAll('.jw-review-card [role=status]')]
                                                  .some(x=>x.textContent.includes('서버 프로필 확인 완료'))
                                            """,timeout=10000)
                                        if route == 'settings':
                                            page.wait_for_function("""
                                                () => [...document.querySelectorAll('.jw-review-card [role=status]')]
                                                  .some(x=>x.textContent.includes('서버 설정 확인 완료'))
                                            """,timeout=10000)
                                        assert not page.locator('.jw-review-unwired').count(),(engine,width,route)
                                        assert not page.locator('.jw-review-failure').count(),(engine,width,route)
                                        assert page.evaluate(
                                            "document.documentElement.scrollWidth<=innerWidth+2"),(
                                            engine,width,route)
                                    assert not errors,(engine,width,errors)
                                    assert not failed_5xx,(engine,width,failed_5xx)
                                    path=ARTIFACTS/f'{engine}_{width}_owner_17routes.png'
                                    page.screenshot(path=str(path),full_page=True,animations='disabled')
                                    print(f'PASS_V223_REAL_{engine.upper()}_{width}_17_MENUS_HTTPS_NO_PAGE_ERRORS',flush=True)
                                finally:
                                    context.close()
                        finally:
                            browser.close()
            finally:
                proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill();proc.wait()

if __name__=='__main__':
    main()
