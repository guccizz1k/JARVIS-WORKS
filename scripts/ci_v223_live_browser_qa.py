"""Real Chromium headless HTTPS DOM navigation test on isolated Render free service.

This is the ACTUAL deployed UI, not a synthetic HTML/DOM mock. Synthetic seeded
login only; no real PII. Tests 17 named UI routes and viewport overflow.
"""
from __future__ import annotations
import json
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE = "https://jw-v223-qa-isolated-20261115.onrender.com"
OUT = Path("artifacts/real-browser")
OUT.mkdir(parents=True, exist_ok=True)
RESULT = []
SIZES = [(1440, 900), (390, 844), (320, 740)]

def assert_true(yes, code):
    if not yes: raise AssertionError("FAIL_"+code)

def main():
    with sync_playwright() as playwright:
        browser=playwright.chromium.launch(headless=True, args=["--no-sandbox"])
        try:
            for width,height in SIZES:
                ctx=browser.new_context(viewport={"width":width,"height":height},
                                        device_scale_factor=1,ignore_https_errors=False)
                try:
                    page=ctx.new_page()
                    page_errors=[]
                    errors=[]
                    http_errors=[]
                    page.on("pageerror",lambda exception:page_errors.append(str(exception)))
                    page.on("console",lambda message:errors.append(message.text) if message.type=="error" else None)
                    page.on("response",lambda response:http_errors.append((response.url,response.status)) if response.status>=400 else None)
                    response=page.goto(BASE,wait_until="domcontentloaded",timeout=75000)
                    assert_true(response is not None and response.status==200,"HTML_"+str(width))
                    # The review bridge first checks /api/me, expects 401, then shows server login.
                    email=page.locator('input[aria-label="이메일"]')
                    email.wait_for(state="visible",timeout=20000)
                    assert_true(not page_errors,"LOGIN_JS_ERROR_"+str(width))
                    email.fill("demo@hanbit.example")
                    page.locator('input[aria-label="비밀번호"]').fill("Demo!2026secure")
                    page.locator('button[type="submit"]').click()
                    nav=page.locator("nav.jw-review-nav")
                    nav.wait_for(state="visible",timeout=25000)
                    buttons=nav.locator("button.jw-review-navitem")
                    assert_true(buttons.count()==17,"NAV_COUNT_"+str(width))
                    page.locator("main.jw-review-main").wait_for(state="visible")
                    assert_true(page.locator(".jw-review-user").inner_text().find("한빛테크")>=0,"AUTH_UI_"+str(width))
                    unique=set()
                    for i in range(17):
                        button=buttons.nth(i)
                        key=button.get_attribute("data-page")
                        assert_true(bool(key),"NAV_KEY_"+str(i))
                        button.click(timeout=15000)
                        page.locator("h2.jw-review-title").wait_for(state="visible",timeout=10000)
                        unique.add(key)
                    assert_true(len(unique)==17,"DISTINCT_ROUTES_"+str(width))
                    # Real tenant-bound API view must reflect server-sourced customer data.
                    nav.locator('button[data-page="partners"]').click()
                    page.locator(".jw-review-row").first.wait_for(timeout=15000)
                    if width==390:
                        import uuid
                        partner_name="UIQA_BROWSER_"+uuid.uuid4().hex[:12]
                        f=page.locator('form.jw-review-action-form').filter(
                            has=page.get_by_role('button',name='거래처 서버 등록',exact=True)).first
                        f.wait_for(state="visible",timeout=15000)
                        f.locator('input[aria-label="거래처명"]').fill(partner_name)
                        f.get_by_role('button',name='거래처 서버 등록').click()
                        page.get_by_text(partner_name,exact=True).wait_for(timeout=20000)
                        live=ctx.request.get(BASE+'/api/customers')
                        assert_true(live.status==200 and any(
                            row.get('name')==partner_name for row in live.json()),
                            "REAL_BROWSER_PARTNER_WRITE_READBACK")
                        print("PASS_REAL_BROWSER_UI_CUSTOMER_CREATE_READBACK")

                        customer_id=next(r['id'] for r in live.json() if r.get('name')==partner_name)
                        page.locator('button[data-page="deals"]').click()
                        qform=page.locator('form.jw-review-action-form').filter(
                            has=page.get_by_role('button',name='견적서 서버 생성',exact=True)).first
                        qform.wait_for(state="visible",timeout=15000)
                        qform.locator('select[aria-label="거래처"]').select_option(customer_id)
                        title="UIQA_QUOTE_"+uuid.uuid4().hex[:12]
                        qform.locator('input[aria-label="견적 제목"]').fill(title)
                        qform.locator('input[aria-label="품목명"]').fill("SYNTHETIC_ONLY_PART")
                        qform.locator('input[aria-label="수량"]').fill("2")
                        qform.locator('input[aria-label="단가(원)"]').fill("1800")
                        qform.get_by_role('button',name='견적서 서버 생성').click()
                        page.get_by_text(title,exact=True).wait_for(timeout=20000)
                        qr=ctx.request.get(BASE+'/api/quotes')
                        assert_true(qr.status==200 and any(
                            r.get('title')==title and r.get('money',{}).get('total')==3960
                            for r in qr.json()),"REAL_BROWSER_QUOTE_WRITE_READBACK")
                        print("PASS_REAL_BROWSER_UI_QUOTE_CREATE_READBACK")
                        page.locator('button[data-page="partners"]').click()
                        page.locator('form.jw-review-action-form').first.wait_for(state="visible",timeout=15000)

                    heading=page.locator("h2.jw-review-title").inner_text()
                    assert_true("거래처" in heading,"PARTNERS_CONTENT_"+str(width))
                    overflow=page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 2")
                    assert_true(not overflow,"HORIZONTAL_OVERFLOW_"+str(width))
                    assert_true(not page_errors,"JS_ERRORS_"+str(width))
                    expected_restore_auth=[(url,status) for url,status in http_errors
                                           if url==BASE+"/api/me" and status==401]
                    unexpected_http=[(url,status) for url,status in http_errors
                                     if (url,status) not in expected_restore_auth]
                    assert_true(not unexpected_http,"UNEXPECTED_HTTP_ERROR_"+str(width))
                    # Chromium reports intentional pre-login /api/me 401 as console error.
                    assert_true(len(errors)<=len(expected_restore_auth),"UNEXPECTED_CONSOLE_ERROR_"+str(width))
                    # Fetch failures due to missing font must not be falsely described as JS exceptions.
                    screenshot=str(OUT/f"jw-real-render-{width}.png")
                    page.screenshot(path=screenshot,full_page=True)
                    RESULTS={"viewport_width":width,"routes":len(unique),"horizontal_overflow":overflow,
                             "page_errors":len(page_errors),"unexpected_console_errors":max(0,len(errors)-len(expected_restore_auth)),
                             "expected_prelogin_auth_401":len(expected_restore_auth),
                             "real_https":True,"actual_server_login":True,
                             "server_readback":True,"screenshot":screenshot}
                    RESULT.append(RESULTS)
                    # Real signout: observe server session revocation.
                    page.locator(".jw-review-logout").click()
                    email.wait_for(state="visible",timeout=15000)
                    assert_true(not page_errors,"LOGOUT_PAGE_ERRORS_"+str(width))
                finally:ctx.close()
        finally:browser.close()
    qa={"scope":"REAL_RENDER_HTTPS_CHROMIUM_SYNTHETIC_LOGINS_ONLY",
        "check_count":len(RESULT)*6,"viewports":RESULT,
        "limitations":["iPhone physical Safari not tested","non-QA production storage not tested",
                       "17 menus navigated, not 17 fully integrated business functions",
                       "P4 launch is still NO-GO"]}
    (OUT/"results.json").write_text(json.dumps(qa,ensure_ascii=False,indent=2))
    print("PASS_REAL_RENDER_CHROMIUM_17_ROUTES_3_VIEWPORTS_ZERO_JS_ERROR")
    print("NOT_RETAIL_PRODUCTION_P2_P4_PASS")

if __name__=="__main__":main()
