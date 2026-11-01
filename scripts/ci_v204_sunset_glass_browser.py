"""V20.4 sunset-glass reference browser acceptance.
Synthetic company-specific API; no production access, writes, API tokens or paid calls.
"""
from __future__ import annotations
import os
import json
from pathlib import Path
from threading import Thread
from http.server import ThreadingHTTPServer
from playwright.sync_api import sync_playwright
from scripts.ci_v202_bento_browser import Handler, STATIC, ROOT

OUT=ROOT/"artifacts/v204-glass"

def check(page,url,width,height,*,snapshot=True):
    js_errors=[]
    page.on("pageerror",lambda err:js_errors.append(str(err)))
    page.goto(url,wait_until="networkidle")
    page.evaluate("""async () => {
      state.user={name:'검증 사용자',org_name:'검증 기업',role:'admin',csrf_token:'fake-review-only'};
      state.csrf='fake-review-only'; showApp();
      await navigate('dashboard');
    }""")
    page.wait_for_selector(".jw-v204 .v204-head")
    assert page.locator(".v204-stat").count()==4,"Four real-metric widgets"
    assert "40건" in page.locator(".v204-stat").first.inner_text(),"25+12+3 documents"
    assert "1건" in page.locator(".v204-approvals").inner_text()
    assert "2,050,000" in page.locator(".v204-stat").nth(2).inner_text()
    assert page.locator(".v204-hero").inner_text().find("검증 사용자")>=0
    assert page.locator(".v204-chart-bar").count()==4
    assert page.evaluate("getComputedStyle(document.querySelector('.app-shell')).backgroundImage.includes('sunset_v204.svg')")
    assert page.locator("#login-view").is_hidden()
    # Check actual feedback and correct filter state.
    page.locator('[data-v204-filter="documents"]').click()
    assert page.locator('[data-v204-filter="documents"]').get_attribute("aria-pressed")=="true"
    assert page.locator(".v204-chart-bar").count()==4
    page.locator('[data-v204-filter="all"]').click()
    assert page.locator('[data-v204-filter="all"]').get_attribute("aria-pressed")=="true"
    # Protect against horizontal overflow at mobile and desktop.
    dims=page.evaluate("""() => ({width:innerWidth,scrollWidth:document.documentElement.scrollWidth,
      main:document.getElementById('main-content').getBoundingClientRect().width})""")
    assert dims["scrollWidth"]<=dims["width"]+1, dims
    assert not js_errors,js_errors
    if snapshot:
        page.wait_for_timeout(550)
        page.screenshot(path=str(OUT/f"sunset-{width}.png"),full_page=(width!=1672),animations="disabled")
    # XSS escapes quote data, and test reveals no hidden fake metrics.
    page.evaluate("""() => {
      state.dashboard.recent_quotes=[{doc_no:'<img src=x onerror=window.__v204_xss=1>',
      customer_name:'<svg onload=alert(1)>',status:'draft'}];
      state.dashboard.issues=[{title:'<img src=x onerror=window.__v204_xss=1>',doc_no:'safe'}];
      document.getElementById('main-content').innerHTML=dashboardPage();
    }""")
    assert page.locator(".jw-v204 img").count()==0
    assert not page.evaluate("window.__v204_xss===1")
    # Actual navigation button invokes *existing* app action, not fake UI navigation.
    page.locator('.jw-v204 [data-v204-nav="orders"]').first.click()  # visible dashboard trade control even when mobile top pills are hidden
    page.wait_for_function("() => state.page==='orders'")
    page.wait_for_function("""() => !document.querySelector('#main-content .jw-v204')""",timeout=12000)
    assert page.locator("#main-content .jw-v204").count()==0
    assert not js_errors,js_errors
    print("PASS_V204_CHROMIUM",width,"scene, authenticated metrics, chart tabs, XSS, real navigation, overflow",flush=True)

def main():
    assert os.environ.get("JW_ENV")=="review","review-only"
    assert STATIC.joinpath("sunset_v204.svg").exists()
    OUT.mkdir(parents=True,exist_ok=True)
    Handler.requests=[]
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    worker=Thread(target=server.serve_forever,daemon=True);worker.start()
    url=f"http://127.0.0.1:{server.server_port}/"
    try:
      with sync_playwright() as p:
       browser=p.chromium.launch(headless=True,args=["--no-sandbox"])
       try:
        for width,height in [(1672,941),(1440,900),(768,1024),(390,844)]:
         context=browser.new_context(viewport={"width":width,"height":height},reduced_motion="no-preference")
         page=context.new_page()
         check(page,url,width,height)
         page.close();context.close()
        context=browser.new_context(viewport={"width":1200,"height":800},reduced_motion="reduce")
        page=context.new_page()
        page.goto(url,wait_until="networkidle")
        page.evaluate("""async ()=>{state.user={name:'B',org_name:'Empty',role:'member'};state.dashboard={
          customers:0,quotes:0,orders:0,invoices:0,collected:0,outstanding:0,
          recent_quotes:[],recent_orders:[],issues:[]};state.quotes=[];
          state.automationDraftSummary={total:0,recent:[]};showApp();document.querySelector('#main-content').innerHTML=dashboardPage();}""")
        assert page.locator(".jw-v204 .v204-stat").first.inner_text().find("0건")>=0
        assert page.locator(".v204-approvals .v204-task").count()==0
        assert "12,540,000" not in page.locator(".jw-v204").inner_text()
        assert page.locator("#security-nav").is_hidden()
        assert page.evaluate("""() => getComputedStyle(document.querySelector('.v204-stat')).animationName==='none'""")
        assert page.locator(".v204-zero").count()>0
        print("PASS_V204_EMPTY_TENANT_REDUCED_MOTION_NO_LEAK",flush=True)
        page.close();context.close()
       finally:browser.close()
    finally:
      server.shutdown();server.server_close()
    assert not any(method!="GET" for method,_ in Handler.requests),Handler.requests
    print("PASS_V204_GET_ONLY_NO_WRITE",flush=True)
    print("V204_ARTIFACTS",json.dumps([x.name for x in OUT.glob("*.png")]),flush=True)

if __name__=="__main__":main()
