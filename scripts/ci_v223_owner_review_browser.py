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
