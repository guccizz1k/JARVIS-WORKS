"""JARVIS WORKS v20.6 actual browser acceptance, synthetic localhost GET only."""
from __future__ import annotations
import json,os
from pathlib import Path
from threading import Thread
from http.server import ThreadingHTTPServer
from playwright.sync_api import sync_playwright
from scripts.ci_v2042_full_ui_video import WalkthroughHandler
from scripts.ci_v202_bento_browser import Handler, ROOT

OUT=ROOT/"artifacts/v206-premium-review"
PAGES=["dashboard","imports","orders","messenger","automation","invoices","quotes","customers","audit","security"]

def login(page,url):
    page.goto(url,wait_until="networkidle")
    page.evaluate("""async()=>{
       state.user={name:'실제 UI 검증',org_name:'검증 기업',role:'admin',csrf_token:'synthetic'};
       state.csrf='synthetic';showApp();await navigate('dashboard');
    }""")
    page.wait_for_selector(".jw206-dashboard",timeout=15000)
    assert page.locator("#nav [data-page='imports']").count()==1
    assert page.locator(".jw206-theme-option").count()==2
    assert page.locator(".jw206-metric").count()==4

def theme(page,mode):
    page.locator('[data-jw206-theme-choice="'+mode+'"]').click()
    props=page.evaluate("""()=>{
       const s=getComputedStyle(document.querySelector(".jw206-metric"));
       const side=getComputedStyle(document.querySelector(".sidebar"));
       return {theme:document.documentElement.dataset.jw206Theme,bg:s.backgroundColor,side:side.backgroundColor,
               sideLeft:document.querySelector(".sidebar").getBoundingClientRect().left,
               darkButtons:[...document.querySelectorAll('[data-jw206-theme-choice]')].map(x=>x.getAttribute('aria-pressed'))};
    }""")
    assert props["theme"]==mode,props
    assert props["darkButtons"]==(["true","false"] if mode=="light" else ["false","true"]),props
    return props

def go(page,name):
    page.locator('#nav [data-page="'+name+'"]').evaluate("(x)=>x.click()")
    page.wait_for_function("(n)=>state.page===n && document.querySelector('#main-content')?.innerText?.length>18",arg=name,timeout=16000)
    page.wait_for_timeout(110)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth+1"),name

def check_panels(page,mode,name):
    ret=page.evaluate("""()=>{
      let root=document.querySelector('#main-content');
      let node=root.querySelector('.panel,.jw-messenger,.jw206-pane,.import-hero,.page-head');
      let cs=node&&getComputedStyle(node);
      let nav=getComputedStyle(document.querySelector('.sidebar'));
      return {theme:document.documentElement.dataset.jw206Theme,
        text:root.innerText.slice(0,130),node:!!node,color:cs?.color,
        bg:cs?.backgroundColor,bgi:cs?.backgroundImage,
        mainOverflow:document.documentElement.scrollWidth-innerWidth,
        railX:document.querySelector('.sidebar').getBoundingClientRect().x,
        railWidth:document.querySelector('.sidebar').getBoundingClientRect().width,
        railBg:nav.backgroundColor};
    }""")
    assert ret["theme"]==mode and ret["node"],(name,ret)
    assert ret["mainOverflow"]<=1,(name,ret)
    assert ret["bgi"]!='none' or 'rgba' in ret["bg"] or ret["bg"].startswith('rgb('),ret
    return ret

def run_page(page,url,width,height):
    errors=[];page.on('pageerror',lambda er:errors.append(str(er)))
    login(page,url)
    p=theme(page,"light")
    assert p["sideLeft"]>width/2 if width>=1050 else True,p
    # No invented efficiency graph; show a genuine NOT_MEASURED empty state.
    assert page.locator(".jw206-eff-empty").count()==1
    assert page.locator(".v204-chart").count()==0
    assert "실측" in page.locator(".jw206-pane-eff").inner_text()
    assert page.locator(".jw206-right-head").count()==1
    assert page.locator('.jw206-more-toggle').get_attribute('aria-expanded')=='false'
    assert page.locator('#nav [data-page="security"]').get_attribute('hidden') is None
    if width>=1050:
      assert page.locator('#nav [data-page="customers"]').is_hidden()
      page.locator(".jw206-more-toggle").click()
      assert page.locator('#nav [data-page="customers"]').is_visible()
      page.locator(".jw206-more-toggle").click()
      assert page.locator('#nav [data-page="customers"]').is_hidden()
      page.locator(".jw206-rail-collapse").click()
      assert page.locator(".app-shell.jw206-compact-rail").count()==1
      page.locator(".jw206-rail-collapse").click()
      assert page.locator(".app-shell.jw206-compact-rail").count()==0
    for mode in ["light","dark"]:
      theme(page,mode)
      go(page,"dashboard")
      assert page.locator(".jw206-metric").count()==4
      if width==1440:
        page.screenshot(path=str(OUT/f"dashboard-{mode}-{width}.png"))
      if width==390:
        page.screenshot(path=str(OUT/f"dashboard-{mode}-{width}.png"),full_page=True)
      for route in PAGES[1:]:
        go(page,route)
        p=check_panels(page,mode,route)
        if width==1440 and mode=="light" and route in ("imports","orders","messenger"):
          page.screenshot(path=str(OUT/f"screen-{route}-{mode}-{width}.png"))
      go(page,"customers")
      page.locator('[data-action="new-customer"]').click()
      dialog=page.locator("#modal-root .modal")
      dialog.wait_for(state="visible")
      info=page.evaluate("""()=>{
        const d=document.querySelector("#modal-root .modal");
        return {background:getComputedStyle(d).backgroundImage,color:getComputedStyle(d).color,
                theme:document.documentElement.dataset.jw206Theme};
      }""")
      assert "gradient" in info["background"],info
      if width==1440:
        page.screenshot(path=str(OUT/f"modal-{mode}-{width}.png"))
      page.locator("#modal-root .close-x").click()
      page.wait_for_selector("#modal-root .modal",state="detached")
    # Local preference: dark persists through reload without user-specific storage.
    page.reload(wait_until="domcontentloaded")
    assert page.evaluate("document.documentElement.dataset.jw206Theme")=="dark"
    # On mobile verify actual right drawer touch path.
    if width<950:
      page.evaluate("""async()=>{
       state.user={name:'검증',org_name:'검증 기업',role:'admin',csrf_token:'test'};
       state.csrf='test';showApp();await navigate('dashboard');
      }""")
      button=page.locator("#toggle-menu")
      button.click()
      assert button.get_attribute("aria-expanded")=="true"
      rect=page.locator(".sidebar").bounding_box()
      assert rect["x"]>width/3,rect
      page.keyboard.press("Escape")
      assert button.get_attribute("aria-expanded")=="false"
    # Security: staff never sees admin-only menu even with 'more' expanded.
    page.evaluate("""async()=>{state.user={name:'검증',org_name:'검증 기업',role:'staff',csrf_token:'test'};
     state.csrf='test';showApp();await navigate('dashboard');}""")
    page.evaluate("document.querySelector('.jw206-more-toggle').click()")
    assert page.locator("#nav [data-page='security']").is_hidden()
    assert not errors,errors
    print("PASS_V206_BROWSER",width,json.dumps({"themes":2,"routes":len(PAGES),"admin_hidden":True},ensure_ascii=False),flush=True)

def main():
    if os.getenv("JW_ENV")!="review":raise RuntimeError("review only")
    OUT.mkdir(parents=True,exist_ok=True)
    Handler.requests=[]
    http=ThreadingHTTPServer(("127.0.0.1",0),WalkthroughHandler)
    Thread(target=http.serve_forever,daemon=True).start()
    url=f"http://127.0.0.1:{http.server_port}/"
    try:
      with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=["--no-sandbox"])
        try:
          for width,height in [(1440,900),(768,1024),(390,844)]:
            ctx=browser.new_context(viewport={"width":width,"height":height},device_scale_factor=1)
            run_page(ctx.new_page(),url,width,height)
            ctx.close()
          ctx=browser.new_context(viewport={"width":1100,"height":800},reduced_motion="reduce")
          page=ctx.new_page();login(page,url)
          assert page.locator(".jw206-dashboard").evaluate("(x)=>getComputedStyle(x).animationName")=="none"
          page.locator('[data-jw206-theme-choice="dark"]').click()
          assert page.evaluate("document.documentElement.dataset.jw206Theme")=="dark"
          ctx.close()
          print("PASS_V206_REDUCED_MOTION",flush=True)
        finally:browser.close()
    finally:http.shutdown();http.server_close()
    assert all(m=="GET" for m,_ in Handler.requests),Handler.requests
    print("PASS_V206_READ_ONLY",len(Handler.requests),flush=True)
if __name__=="__main__":main()
