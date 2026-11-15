"""REAL browser Chromium/WebKit authenticated review-only operational menus.

Runs only against the public *synthetic* Render QA environment. No production DB
access, data migration or writes. Headless WebKit != iPhone hardware Safari.
"""
from __future__ import annotations
from pathlib import Path
import json
from playwright.sync_api import sync_playwright

URL='https://jw-v223-qa-isolated-20261115.onrender.com'
ROOT=Path('artifacts/jw-v223-operational-browser')
ROOT.mkdir(parents=True,exist_ok=True)
PANELS={
 'stats':'기업별 실제 서버 현황',
 'automation':'업무 처리시간',
 'activity':'서버 조회 결과',
 'messenger':'서버 조회 결과',
 'docs':'서버 조회 결과',
 'files':'서버 조회 결과',
 'inbox':'서버 조회 결과',
 'security':'관리자 전용 보안',
 'team':'관리자 전용 보안'
}
ROUTES=['home','docs','deals','papers','money','partners','messenger','automation','stats','export','inbox','files','activity','team','security','settings','account']
def check(ok,code):
    if not ok:raise AssertionError('FAIL_'+code)
def run_browser(engine,viewport):
    ww,hh=viewport
    ctx=engine.new_context(viewport={'width':ww,'height':hh},ignore_https_errors=False)
    try:
        page=ctx.new_page()
        exceptions=[]
        page.on('pageerror',lambda e: exceptions.append(str(e)))
        resp=page.goto(URL,wait_until='domcontentloaded',timeout=75000)
        check(resp.status==200,'HTML_200_'+str(ww))
        page.locator('input[aria-label="이메일"]').wait_for(state='visible',timeout=25000)
        page.locator('input[aria-label="이메일"]').fill('demo@hanbit.example')
        page.locator('input[aria-label="비밀번호"]').fill('Demo!2026secure')
        page.locator('button[type="submit"]').click()
        nav=page.locator('.jw-review-nav')
        nav.wait_for(state='visible',timeout=20000)
        check(nav.locator('.jw-review-navitem').count()==17,'ROUTE_COUNT_'+str(ww))
        panel_counts=0
        for route in ROUTES:
            nav.locator('button[data-page="'+route+'"]').click(timeout=20000)
            page.locator('h2.jw-review-title').wait_for(state='visible',timeout=15000)
            # These exact routes have been newly connected to live server data.
            if route in PANELS:
                box=page.locator('.jw-review-card').first
                box.wait_for(state='visible',timeout=25000)
                text=box.inner_text(timeout=12000)
                check(bool(text.strip()),'EMPTY_PANEL_'+route)
                check('조회 차단' not in page.locator('main.jw-review-main').inner_text(),'SERVER_READ_DENIED_'+route)
                panel_counts+=1
            check(not exceptions,'JS_EXCEPTION_'+route)
        nav.locator('button[data-page="stats"]').click()
        card=page.locator('.jw-review-card').first
        card.wait_for(state='visible',timeout=15000)
        check('기업별 실제 서버 현황' in card.inner_text(),'STATS_LIVE_RENDER')
        check('미수금' in page.locator('main.jw-review-main').inner_text(),'STATS_REAL_MONEY')
        check(not page.evaluate('document.documentElement.scrollWidth > window.innerWidth + 2'),'HORIZONTAL_OVERFLOW')
        image=ROOT/(f'operational-{engine.name}-{ww}.png')
        page.screenshot(path=str(image),full_page=True)
        page.locator('.jw-review-logout').click()
        page.locator('input[aria-label="이메일"]').wait_for(state='visible',timeout=20000)
        check(not exceptions,'JS_EXCEPTION_LOGOUT')
        return {'engine':engine.name,'width':ww,'routes':len(ROUTES),'live_panels':panel_counts,'js_exceptions':0,'horizontal_overflow':False,'image':str(image)}
    finally:ctx.close()
def main():
    entries=[]
    with sync_playwright() as p:
        chromium=p.chromium.launch(headless=True,args=['--no-sandbox'])
        webkit=p.webkit.launch(headless=True)
        try:
            for engine,size in ((chromium,(1440,900)),(chromium,(390,844)),(chromium,(320,740)),(webkit,(390,844))):
                entries.append(run_browser(engine,size))
        finally:
            chromium.close();webkit.close()
    report={'scope':'REAL_RENDER_HTTPS_SYNTHETIC_CHROMIUM_AND_LINUX_WEBKIT',
            'live_service_source_sha_from_render':'5711acaa9203341dbd190f30efd9ed7009bca4f5',
            'results':entries,'checked_routes':len(ROUTES),'new_panels':len(PANELS),
            'limitations':['Linux WebKit is not iPhone hardware','No operational Supabase or B2/B3 PG17 restore',
                           'No full 17-menu write-side integration','Not final release PASS']}
    (ROOT/'evidence.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
    print('PASS_LIVE_CHROMIUM_WEBKIT_OPERATIONAL_PANELS_'+str(len(entries))+'_VIEWPORTS')
if __name__=='__main__':main()
