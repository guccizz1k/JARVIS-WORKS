"""V20.5 — actual Chrome across 10 business pages: smooth transitions, glass parity, modals.
Loopback synthetic GET only; no production or real customer calls.
"""
from __future__ import annotations
import os, json, statistics
from pathlib import Path
from threading import Thread
from http.server import ThreadingHTTPServer
from playwright.sync_api import sync_playwright
from scripts.ci_v2042_full_ui_video import WalkthroughHandler
from scripts.ci_v202_bento_browser import Handler, ROOT

OUT=ROOT/"artifacts/v205-smooth-glass"
ROUTES=["dashboard","imports","orders","invoices","messenger","customers","quotes","automation","audit","security"]

def assert_ui(page,route,viewport):
    props=page.evaluate("""(route)=>{
      const main=document.getElementById('main-content');
      const panel=main.querySelector('.panel,.v204-glass,.jw-messenger');
      const header=main.querySelector('.page-head,.jw-simple-header,.v204-hero');
      const target=main.querySelector('.panel,.v204-glass');
      const style=(e)=>e?getComputedStyle(e):null;
      const s=style(target),h=style(header);
      return {
        route:state.page,visible:main.getBoundingClientRect().width>100,
        panels:main.querySelectorAll('.panel,.v204-glass').length,
        bg:s?.backgroundImage||'',filter:s?.backdropFilter||'none',
        headerBg:h?.backgroundImage||'',headerColor:h?.color||'',
        animation:getComputedStyle(main).animationName,
        overflow:document.documentElement.scrollWidth-innerWidth,
        nav:!!document.querySelector('#v204-floating-nav'),
        pageText:main.innerText.slice(0,240)
      }
    }""",route)
    assert props["route"]==route,props
    assert props["visible"],props
    assert props["nav"],props
    assert props["overflow"]<=1,props
    assert props["animation"] in {"jw205-page-in","none"},props
    assert props["headerBg"].startswith("linear-gradient") or route=="messenger",props
    # All main article panels share same tinted surface, never opaque white.
    if props["panels"]>0:
      assert "linear-gradient" in props["bg"],props
      assert props["filter"]=="none",props
    return props

def login(page,url):
    page.goto(url,wait_until="networkidle")
    page.evaluate("""async ()=>{
      state.user={id:'v205-test',name:'검증 사용자',org_name:'테스트 기업',role:'admin',csrf_token:'test-local'};
      state.csrf='test-local';showApp();await navigate('dashboard');
    }""")
    page.wait_for_selector(".jw-v204",timeout=15000)
    assert page.evaluate("Boolean(window.JW_PREMIUM_V205?.originalClosePreserved)")
    assert_ui(page,"dashboard",0)

def walk(page,width,record=False):
    elapsed=[]
    for i,route in enumerate(ROUTES):
        if route!="dashboard":
            # Route through actual original navigation button, not synthetic DOM replacement.
            selector=f'#nav [data-page="{route}"]'
            start=page.evaluate("performance.now()")
            page.locator(selector).evaluate("(el)=>el.click()")
            page.wait_for_function("(p)=>state.page===p && !document.body.classList.contains('jw-v203-loading')",arg=route,timeout=12000)
            page.locator("#main-content .page-head, #main-content .jw-simple-header").first.wait_for(state="visible",timeout=12000)
            ms=round(page.evaluate("(t)=>performance.now()-t",start))
            elapsed.append(ms)
        props=assert_ui(page,route,width)
        if record and route in {"dashboard","imports","orders","messenger"}:
            page.wait_for_timeout(350)
            page.screenshot(path=str(OUT/f"v205-{route}-{width}.png"),full_page=False)
        if route=="messenger":
            assert page.evaluate("""()=>{
              const node=document.querySelector('.jw-messenger');
              const child=document.querySelector('.jw-conversation');
              return getComputedStyle(node).backgroundImage.includes('linear-gradient')
                && getComputedStyle(child).backgroundColor!=='rgb(255, 255, 255)';
            }"""),"white messenger background persists"
        if route=="customers":
            page.locator('[data-action="new-customer"]').click()
            dialog=page.locator("#modal-root .modal")
            dialog.wait_for(state="visible")
            c=page.evaluate("""()=>{
              const d=document.querySelector('#modal-root .modal'),s=getComputedStyle(d);
              const p=document.querySelector('#modal-root .modal-top');
              return {bg:s.backgroundImage,radius:parseFloat(s.borderTopLeftRadius),title:getComputedStyle(p).backgroundColor,
                animation:s.animationName,color:s.color};
            }""")
            assert "linear-gradient" in c["bg"] and c["radius"]>=20,c
            assert c["animation"]=="jw205-modal-in",c
            if record:
               page.wait_for_timeout(160)
               page.screenshot(path=str(OUT/f"v205-unified-modal-{width}.png"))
            page.locator("#modal-root .close-x").click()
            assert page.locator("#modal-root .overlay.jw205-closing").count()==1,"missing close motion"
            page.wait_for_selector("#modal-root .modal",state="detached",timeout=2000)
            # Quick successive modal open/close must not delete a newer dialog.
            page.locator('[data-action="new-customer"]').click()
            page.locator("#modal-root .close-x").click()
            page.evaluate("""()=>{
              modal('새로운 검토 창','<p>기존 닫기 타이머는 이 창을 제거해서는 안 됩니다.</p>');
            }""")
            page.wait_for_timeout(230)
            assert page.locator('#modal-root [role="dialog"]').count()==1,"old close removed new dialog"
            page.locator("#modal-root .close-x").click()
            page.wait_for_selector("#modal-root .modal",state="detached")
    assert len(elapsed)==len(ROUTES)-1,elapsed
    assert max(elapsed)<2500,"synthetic-route excessive stalls:"+str(elapsed)
    print("PASS_V205_ROUTES",width,json.dumps(dict(zip(ROUTES[1:],elapsed))),flush=True)
    return elapsed

def main():
    if os.getenv("JW_ENV")!="review":raise RuntimeError("review-only")
    OUT.mkdir(parents=True,exist_ok=True)
    Handler.requests=[]
    server=ThreadingHTTPServer(("127.0.0.1",0),WalkthroughHandler)
    Thread(target=server.serve_forever,daemon=True).start()
    base=f"http://127.0.0.1:{server.server_port}/"
    try:
      with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=["--no-sandbox"])
        try:
          results=[]
          for width,height in [(1440,900),(768,1024),(390,844)]:
            ctx=browser.new_context(viewport={"width":width,"height":height})
            page=ctx.new_page()
            errors=[];page.on("pageerror",lambda e:errors.append(str(e)))
            login(page,base)
            timings=walk(page,width,record=True)
            assert not errors,errors
            results.extend(timings)
            page.close();ctx.close()
          # Reduced-motion flow has no visual transitions but remains functional.
          ctx=browser.new_context(viewport={"width":1024,"height":768},reduced_motion="reduce")
          page=ctx.new_page();login(page,base)
          result=page.evaluate("""()=>{
            const style=getComputedStyle(document.querySelector('#main-content'));
            return {duration:style.animationDuration,animation:style.animationName};
          }""")
          assert result["animation"]=="none",result
          page.locator('#nav [data-page="customers"]').evaluate("(el)=>el.click()")
          page.wait_for_function("()=>state.page==='customers'")
          page.locator('[data-action="new-customer"]').click()
          page.locator('#modal-root .close-x').click()
          assert page.locator('#modal-root .modal').count()==0,"reduced motion modal should close immediately"
          page.close();ctx.close()
          print("PASS_V205_REDUCED_MOTION",flush=True)
          (OUT/"timings.json").write_text(json.dumps({"synthetic_loopback_ms":results,
              "median_ms":statistics.median(results),"p95_proxy_max_ms":max(results),
              "caveat":"CI times only; not real iPhone FPS or production network"},ensure_ascii=False,indent=2))
        finally:browser.close()
    finally:server.shutdown();server.server_close()
    assert not any(m!="GET" for m,_ in Handler.requests),Handler.requests
    print("PASS_V205_NO_NETWORK_WRITES",len(Handler.requests),flush=True)
    print("PASS_V205_ALL_10_ROUTES_3_VIEWPORTS_MODAL_CLOSE_MESSENGER",flush=True)
if __name__=="__main__":main()
