"""Isolated real-browser UI and typography measurement. No external service."""
from __future__ import annotations
import os,json
from threading import Thread
from http.server import ThreadingHTTPServer
from pathlib import Path
from playwright.sync_api import sync_playwright
from scripts.ci_v206_premium_browser import CompleteV206Fixture
from scripts.ci_v202_bento_browser import Handler,ROOT
OUT=ROOT/"artifacts/v209-review"
def main():
 assert os.getenv("JW_ENV")=="review"
 OUT.mkdir(parents=True,exist_ok=True);Handler.requests=[]
 srv=ThreadingHTTPServer(("127.0.0.1",0),CompleteV206Fixture)
 Thread(target=srv.serve_forever,daemon=True).start()
 results=[]
 try:
  with sync_playwright() as pw:
   browser=pw.chromium.launch(headless=True,args=["--no-sandbox"])
   try:
    for width in (1440,1280,1024,768,390):
     context=browser.new_context(viewport={"width":width,"height":900})
     page=context.new_page();errors=[]
     page.on("pageerror",lambda e:errors.append(str(e)))
     page.goto("http://127.0.0.1:"+str(srv.server_port),wait_until="networkidle")
     page.evaluate("""async()=>{state.user={name:'QA',org_name:'검증기업',role:'admin',csrf_token:'test'};
       state.csrf='test';showApp();await navigate('dashboard');}""")
     page.wait_for_selector(".jw206-dashboard")
     assert page.locator(".jw209-top-nav .jw209-tab").count()==8
     assert page.locator(".jw206-metric").count()==4
     for mode in ("light","dark"):
      page.locator('[data-jw206-theme-choice="'+mode+'"]').click()
      x=page.evaluate("""()=>{const n=document.querySelector('.jw209-top-nav').getBoundingClientRect();const d=document.querySelector('.jw206-dashboard').getBoundingClientRect();const logo=document.querySelector('.v204-global-brand').getBoundingClientRect();
       const font=s=>parseFloat(getComputedStyle(document.querySelector(s)).fontSize);
       return {width:innerWidth,scroll:document.documentElement.scrollWidth,navLeft:n.left,navRight:n.right,
        mainWidth:d.width,logoLeft:logo.left,titleFont:font('.jw206-greeting h1'),labelFont:font('.jw206-metric-label'),
        valueFont:font('.jw206-metric strong'),navFont:font('.jw209-tab'),
        theme:document.documentElement.dataset.jw206Theme,
        sidebar:getComputedStyle(document.querySelector('.sidebar')).display,
        cardOverflow:[...document.querySelectorAll('.jw206-metric')].some(e=>e.scrollWidth>e.clientWidth+2)}}""")
      assert x["scroll"]<=width+1 and x["navLeft"]>=0 and x["navRight"]<=width+1,x
      assert x["theme"]==mode and x["sidebar"]=="none",x
      assert x["titleFont"]>=28 and x["labelFont"]>=13.5 and x["valueFont"]>=22 and x["navFont"]>=12.5,x
      assert not x["cardOverflow"],x
      if width>=1024:assert x["mainWidth"]>=width*.88,x
      if width<=480:assert x["logoLeft"]>=8 and x["logoLeft"]<=24,x
      results.append(x)
      if width in (1440,390):page.screenshot(path=str(OUT/f"dashboard-{width}-{mode}.png"),animations="disabled")
     page.locator('.jw209-top-nav button[data-jw209-page="orders"]').click()
     page.wait_for_function("()=>state.page==='orders'")
     assert page.locator("#main-content").inner_text().strip()
     if width==1440:page.screenshot(path=str(OUT/"orders.png"),animations="disabled")
     page.locator(".jw209-more-trigger").click()
     assert page.locator(".jw209-more-menu").is_visible()
     page.keyboard.press("Escape")
     assert page.locator(".jw209-more-menu").is_hidden()
     assert not errors,(width,errors)
     context.close()
   finally:browser.close()
 finally:srv.shutdown();srv.server_close()
 assert all(m=="GET" for m,_ in Handler.requests)
 (OUT/"measurements.json").write_text(json.dumps(results,ensure_ascii=False,indent=2))
 print("PASS 5 resolutions, 2 modes, typography, top nav and business routing")
if __name__=="__main__":main()
