"""V21.2 acceptance: source SVG infinity, one internal canvas light,
genuine existing B2B routes, no backend changes. Synthetic local fixture only.
"""
from __future__ import annotations
import os, json, subprocess
from pathlib import Path
from threading import Thread
from http.server import ThreadingHTTPServer
from playwright.sync_api import sync_playwright
from scripts.ci_v211_login_photon_browser import (
    ROOT, CompleteV206Fixture, Handler, fresh_login, login_synthetic,
)
WIDTHS=(1440,1280,1024,768,390)
ROUTES=("imports","quotes","orders","invoices","automation","messenger","dashboard")
OUT=ROOT/"artifacts/v212-browser"

def sculpture(page,root):
    s=root+" .jw212-sculpt"
    page.locator(s).wait_for(state="attached",timeout=10000)
    assert page.locator(s+" canvas").count()==1
    assert page.locator(s+" svg.scv").count()==1
    assert page.locator(s).evaluate("(x)=>x.getAttribute('aria-hidden')")=="true"
    assert page.locator(s+" canvas").evaluate("(x)=>x.width>0&&x.height>0")
    assert page.locator(root+" .jw211-glass-photon").evaluate(
        "(x)=>getComputedStyle(x).visibility")=="hidden"

def run():
    assert os.environ.get("JW_ENV")=="review"
    OUT.mkdir(parents=True,exist_ok=True)
    Handler.requests=[]
    server=ThreadingHTTPServer(("127.0.0.1",0),CompleteV206Fixture)
    Thread(target=server.serve_forever,daemon=True).start()
    url="http://127.0.0.1:"+str(server.server_port)+"/"
    counts={"viewports":0,"theme_screen_pairs":0,"real_routes":0,"source_sculptures":0,
            "browser_errors":0,"http_writes":0}
    try:
      with sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,args=["--no-sandbox"])
        try:
          for width in WIDTHS:
            ctx=browser.new_context(viewport={"width":width,"height":900 if width>600 else 844},
                                    device_scale_factor=1)
            page=ctx.new_page()
            errors=[]
            page.on("pageerror",lambda error:errors.append(str(error)))
            fresh_login(page,url)
            sculpture(page,".jw211-login-infinity")
            assert page.evaluate("window.JW_PREMIUM_V212?.version")=="21.2"
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
            counts["source_sculptures"]+=1
            for theme in ("dark","light"):
              page.locator('.jw211-login-mode[data-jw211-theme="'+theme+'"]').click()
              assert page.evaluate("document.documentElement.dataset.jw206Theme")==theme
              assert page.locator(".jw211-login-infinity .jw212-sculpt").count()==1
              assert page.locator("#login-view").is_visible()
              assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
              counts["theme_screen_pairs"]+=1
              if width in (1440,390):
                page.screenshot(path=str(OUT/f"login-{width}-{theme}.png"),animations="disabled")
            page.locator('.jw211-login-mode[data-jw211-theme="dark"]').click()
            canvas=".jw211-login-infinity .jw212-sculpt canvas"
            page.evaluate("(selector)=>{window.__v212_start=document.querySelector(selector).toDataURL('image/png')}",canvas)
            page.wait_for_timeout(380)
            assert page.evaluate("(selector)=>window.__v212_start!==document.querySelector(selector).toDataURL('image/png')",canvas),"Photon not moving"
            login_synthetic(page)
            sculpture(page,".jw210-home .jw210-infinity-stage")
            counts["source_sculptures"]+=1
            assert page.locator("#login-view").is_hidden()
            for theme in ("dark","light"):
              page.locator('[data-jw206-theme-choice="'+theme+'"]').click()
              assert page.evaluate("document.documentElement.dataset.jw206Theme")==theme
              assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
              counts["theme_screen_pairs"]+=1
              if width in (1440,390):
                page.screenshot(path=str(OUT/f"home-{width}-{theme}.png"),animations="disabled")
            for route in ROUTES:
              if route=="dashboard":page.locator(".jw210-brand").click()
              else:page.locator('.jw210-business-nav [data-jw210-page="'+route+'"]').click()
              page.wait_for_function("(r)=>state.page===r",arg=route,timeout=20000)
              assert page.locator("#main-content").inner_text().strip()
              assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
              counts["real_routes"]+=1
            page.wait_for_selector(".jw210-home .jw212-sculpt")
            assert page.locator(".jw210-home .jw212-sculpt").count()==1
            assert not errors,(width,errors)
            counts["viewports"]+=1
            ctx.close()
          ctx=browser.new_context(viewport={"width":1024,"height":768},reduced_motion="reduce")
          page=ctx.new_page();fresh_login(page,url)
          sculpture(page,".jw211-login-infinity")
          assert page.evaluate("matchMedia('(prefers-reduced-motion: reduce)').matches")
          assert page.locator(".jw212-sculpt canvas").count()==1
          login_synthetic(page)
          sculpture(page,".jw210-home .jw210-infinity-stage")
          ctx.close()
        finally:
          browser.close()
    finally:
      server.shutdown();server.server_close()
    counts["browser_errors"]=0
    counts["http_writes"]=len([(m,p) for m,p in Handler.requests if m!="GET"])
    assert counts["http_writes"]==0,Handler.requests
    (OUT/"acceptance.json").write_text(json.dumps(counts,indent=2))
    print("PASS JW V21.2 source-rendered glass, 5 widths, 2 themes, 7 authentic business routes, reduced motion, 0 writes",counts)

if __name__=="__main__":
    run()
