"""Actual owner-approved CSS / server-auth review screen in Chromium & WebKit.

Runs a disposable, loopback HTTPS FastAPI server with synthetic SQLite only.
The original 229028-byte owner HTML is NEVER executed or changed.
Browser checks are UI and same-origin server E2E, NOT actual Render or iPhone Safari.
"""
from pathlib import Path
import json, ssl, urllib.request
from playwright.sync_api import sync_playwright

BASE='https://127.0.0.1:8787'
OUT=Path('artifacts/jw-v223-owner-visual-browser')
OUT.mkdir(parents=True,exist_ok=True)
ROUTES=['home','docs','deals','papers','money','partners','messenger','automation','stats',
        'export','inbox','files','activity','team','security','settings','account']
def check(value,code):
    if not value:raise AssertionError('FAIL_'+code)
def one(browser,engine,width,height):
    ctx=browser.new_context(viewport={'width':width,'height':height},
                            ignore_https_errors=True,device_scale_factor=1)
    errors=[]
    try:
        page=ctx.new_page()
        page.on('pageerror',lambda ex:errors.append(str(ex)))
        page.goto(BASE,wait_until='domcontentloaded',timeout=50000)
        heading=page.locator('#login .poster .mega')
        heading.wait_for(state='visible',timeout=20000)
        check('WORK' in heading.inner_text() and 'EDGES.' in heading.inner_text(),'APPROVED_POSTER_'+engine+str(width))
        check(page.locator('#login .lcard').is_visible(),'APPROVED_LOGIN_CARD_'+engine+str(width))
        check(page.locator('#login input[type="email"]').count()==1,'SERVER_LOGIN_EMAIL_'+engine+str(width))
        check('회사 등록하고 시작하기' not in page.locator('#login').inner_text() and page.locator('#login input[autocomplete="organization"]').count()==0,'LOCAL_REGISTER_NOT_AVAILABLE_'+engine+str(width))
        check(page.evaluate("localStorage.getItem('jw3.db')") is None,'LOCAL_DB_NOT_CREATED_'+engine+str(width))
        page.screenshot(path=str(OUT/f'owner-visual-login-{engine}-{width}.png'),full_page=True)
        page.locator('input[aria-label="이메일"]').fill('demo@hanbit.example')
        page.locator('input[aria-label="비밀번호"]').fill('Demo!2026secure')
        page.locator('#login button[type="submit"]').click()
        page.locator('#app.on .jw-review-user').wait_for(state='visible',timeout=25000)
        check('한빛테크' in page.locator('.jw-review-user').inner_text(),'REAL_SERVER_SESSION_'+engine+str(width))
        check(page.locator('#app .jw-review-nav button[data-page]').count()==17,'ALL_17_ROUTES_DESKTOP_NAV_'+engine+str(width))
        if width>900:
            check(page.locator('nav.rail').is_visible(),'OWNER_DESKTOP_RAIL')
        else:
            check(page.locator('nav.jw-owner-bottomnav').is_visible(),'OWNER_MOBILE_BOTTOM_NAV_'+engine+str(width))
            more=page.locator('button[data-action="show-all"]')
            more.click()
            dialog=page.locator('#jw-owner-menu[role="dialog"][aria-hidden="false"]')
            dialog.wait_for(state='visible',timeout=10000)
            check(dialog.locator('button[data-page]').count()==17,'ALL_17_REACHABLE_MOBILE_'+engine+str(width))
            dialog.locator('button[data-page="automation"]').click()
            check(page.locator('#jw-owner-menu').get_attribute('aria-hidden')=='true','MOBILE_MENU_CLOSED')
            page.locator('#app .jw-review-title').wait_for(state='visible')
        nav=page.locator('#app nav.jw-review-nav')
        visited=[]
        for route in ROUTES:
            if width>900:
                nav.locator('button[data-page="'+route+'"]').click()
            else:
                page.locator('button[data-action="show-all"]').click()
                dialog=page.locator('#jw-owner-menu[aria-hidden="false"]')
                dialog.locator('button[data-page="'+route+'"]').click()
            title=page.locator('#app .jw-review-title')
            title.wait_for(state='visible',timeout=15000)
            check(bool(title.inner_text().strip()),'EMPTY_ROUTE_'+route+'_'+engine+str(width))
            visited.append(route)
        page.locator('#app nav.jw-review-nav button[data-page="partners"]').click(force=True) if width>900 else None
        if width<=900:
            page.locator('button[data-action="show-all"]').click()
            page.locator('#jw-owner-menu[aria-hidden="false"] button[data-page="partners"]').click()
        page.locator('#app .jw-review-card').first.wait_for(state='visible',timeout=20000)
        check(not errors,'JAVASCRIPT_EXCEPTIONS_'+engine+str(width))
        check(not page.evaluate('document.documentElement.scrollWidth > window.innerWidth + 2'),
              'HORIZONTAL_OVERFLOW_'+engine+str(width))
        check(page.evaluate("localStorage.getItem('jw3.db')") is None,'NEVER_SAVED_LOCAL_DB_'+engine+str(width))
        check(page.evaluate("getComputedStyle(document.documentElement).getPropertyValue('--acc').trim()")=='#d4ff3a',
              'EXACT_OWNER_LIME_COLOR_'+engine+str(width))
        page.screenshot(path=str(OUT/f'owner-visual-workspace-{engine}-{width}.png'),full_page=True)
        page.locator('#app .jw-review-logout').click()
        page.locator('#login input[type="email"]').wait_for(state='visible',timeout=15000)
        check(not errors,'LOGOUT_JS_EXCEPTION_'+engine+str(width))
        return dict(engine=engine,width=width,routes=len(visited),poster=True,server_login=True,
                    owner_css=True,local_store_unused=True,horizontal_overflow=False,
                    js_exceptions=0,logout=True)
    finally:ctx.close()

def main():
    result=[]
    with sync_playwright() as p:
        c=p.chromium.launch(headless=True,args=['--no-sandbox'])
        w=p.webkit.launch(headless=True)
        try:
            for browser,engine,width,height in [(c,'chromium',1440,900),(c,'chromium',390,844),(c,'chromium',320,740),
                                                 (w,'webkit',390,844)]:
                result.append(one(browser,engine,width,height))
        finally:c.close();w.close()
    report={'scope':'DISPOSABLE_LOCAL_HTTPS_FASTAPI_SYNTHETIC_SQLITE',
            'original_owner_html_executed':False,'approved_css_reused':True,
            'results':result,'limitations':['Not external Render HTTPS','Not iPhone hardware Safari',
            'Not 17 fully implemented business operations','Not P1 independent PG17 restore',
            'Not final production UI parity','Not P4 release']}
    (OUT/'evidence.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
    print('PASS_REAL_BROWSER_OWNER_APPROVED_CSS_SERVER_MODE_CHROMIUM_WEBKIT_4_VIEWPORTS')
if __name__=='__main__':main()
