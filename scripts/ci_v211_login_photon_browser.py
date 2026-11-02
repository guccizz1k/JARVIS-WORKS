"""V21.1 single internal photon, uniform login, spatial transition.
Only synthetic localhost GET and original application routes, never production.
"""
from __future__ import annotations
import json,os,shutil,subprocess,statistics
from pathlib import Path
from threading import Thread
from http.server import ThreadingHTTPServer
from playwright.sync_api import sync_playwright
from scripts.ci_v206_premium_browser import CompleteV206Fixture
from scripts.ci_v202_bento_browser import ROOT,Handler

OUT=ROOT/"artifacts/v211-browser"
WIDTHS=(1440,1280,1024,768,390)
ROUTES=("imports","orders","invoices","messenger","quotes","automation","dashboard")
def fresh_login(page,url):
    page.goto(url,wait_until="networkidle")
    page.locator("#login-view.jw211-login").wait_for(state="visible",timeout=15000)
    assert page.locator(".jw211-login-infinity-image").count()==1
    assert page.locator(".jw211-login-hero .jw211-glass-photon animateMotion").count()==1
    assert page.locator(".jw211-login-hero .jw211-photon-core").count()==1
    assert page.locator(".jw211-login-hero .jw210-orbit-overlay").count()==0
    assert page.locator('input[name="password"]').get_attribute("type")=="password"
    assert page.locator('input[name="otp"]').get_attribute("pattern")=="[0-9]{6}"
    assert page.locator('input[name="recovery_code"]').get_attribute("type")=="password"
def login_synthetic(page):
    page.evaluate("""async()=>{state.user={name:'실제 UI 검증',org_name:'검증 기업',
         role:'admin',csrf_token:'synthetic'};state.csrf='synthetic';
         showApp();await navigate('dashboard')}""")
    page.wait_for_selector(".jw210-home",timeout=15000)
    assert page.locator("#login-view").is_hidden(),"CRITICAL: login remained visible after auth"
    page.wait_for_function("""()=>document.querySelector(".jw210-home .jw211-glass-photon animateMotion")!==null""",timeout=6000)
    assert page.locator(".jw210-home .jw211-photon-core").count()==1
    assert page.locator(".jw210-home .jw210-orbit-overlay").count()==0
def measured(page,width,theme):
    v=page.evaluate("""()=>{
       const r=(s)=>{const e=document.querySelector(s);const a=e.getBoundingClientRect();return {left:a.left,right:a.right,top:a.top,bottom:a.bottom,width:a.width,height:a.height}};
       const body=document.documentElement;
       return {width:innerWidth,docWidth:body.scrollWidth,theme:body.getAttribute("data-jw206-theme"),
         login:r("#login-view"),header:r(".jw210-top-row"),nav:r(".jw210-business-nav"),
         hero:r(".jw210-infinity-stage"),metric:r(".jw210-metrics"),title:r(".jw210-hero-title"),
         loginHidden:getComputedStyle(document.getElementById("login-view")).display==="none",
         photon:document.querySelectorAll(".jw210-home .jw211-glass-photon animateMotion").length,
         orbits:document.querySelectorAll(".jw210-home .jw210-orbit-overlay").length};
    }""")
    assert v["theme"]==theme and v["loginHidden"],v
    assert v["docWidth"]<=width+1,v
    assert v["photon"]==1 and v["orbits"]==0,v
    for node in ("nav","header","metric"):
        rect=v[node]
        assert rect["left"]>=-1 and rect["right"]<=width+1,(node,v)
    return v
def test_photon_motion(page,selector):
    # Independent snapshots of the same group's animation transform.
    first=page.locator(selector).evaluate("(el)=>{const m=el.getCTM();return [m.e,m.f]}")
    page.wait_for_timeout(340)
    second=page.locator(selector).evaluate("(el)=>{const m=el.getCTM();return [m.e,m.f]}")
    assert abs(first[0]-second[0])+abs(first[1]-second[1])>0.25,(first,second)
def run():
    assert os.environ.get("JW_ENV")=="review","CI fixture must be isolated review"
    OUT.mkdir(parents=True,exist_ok=True);Handler.requests=[]
    http=ThreadingHTTPServer(("127.0.0.1",0),CompleteV206Fixture)
    Thread(target=http.serve_forever,daemon=True).start()
    url="http://127.0.0.1:"+str(http.server_port)+"/"
    reports=[]
    try:
      with sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,args=["--no-sandbox"])
        try:
          for width in WIDTHS:
            ctx=browser.new_context(viewport={"width":width,"height":900 if width>600 else 844},
                                    device_scale_factor=1)
            page=ctx.new_page();errors=[];page.on("pageerror",lambda er:errors.append(str(er)))
            fresh_login(page,url)
            for theme in ("dark","light"):
                page.locator('.jw211-login-mode[data-jw211-theme="'+theme+'"]').click()
                assert page.evaluate("document.documentElement.dataset.jw206Theme")==theme
                assert page.locator('#login-view.jw211-login').is_visible()
                assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
                if width in (1440,390):
                    page.screenshot(path=str(OUT/f"login-{width}-{theme}.png"),
                                    full_page=(width==390),animations="disabled")
            page.locator('.jw211-login-mode[data-jw211-theme="dark"]').click()
            test_photon_motion(page,".jw211-login-hero .jw211-photon-core")
            login_synthetic(page)
            test_photon_motion(page,".jw210-home .jw211-photon-core")
            for theme in ("dark","light"):
                page.locator('[data-jw206-theme-choice="'+theme+'"]').click()
                v=measured(page,width,theme);reports.append(v)
                if width in (1440,390):
                    page.screenshot(path=str(OUT/f"dashboard-{width}-{theme}.png"),
                                    animations="disabled",full_page=(width==390))
            for route in ROUTES:
                if route=="dashboard":page.locator(".jw210-brand").click()
                else:page.locator('.jw210-business-nav button[data-jw210-page="'+route+'"]').click()
                page.wait_for_function("(r)=>state.page===r",arg=route,timeout=20000)
                assert page.locator("#main-content").inner_text().strip()
                assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1"),route
                # Actual business route is shown through an aperture transition.
                if route!="dashboard":
                    page.wait_for_function("""()=>document.querySelector('#main-content')?.classList.contains('jw211-portal-reveal')""",timeout=18000)
                    assert page.locator("#main-content.jw211-portal-reveal").count()==1,route
                    assert page.locator("#main-content").evaluate("(x)=>getComputedStyle(x).animationName")=="jw211-glass-aperture",route
                if width==1440 and route in ("imports","orders","messenger"):
                    page.screenshot(path=str(OUT/f"route-{route}.png"),animations="disabled")
            page.evaluate("""async()=>{state.user={name:'직원',org_name:'검증 기업',role:'staff',csrf_token:'synthetic'};
               state.csrf='synthetic';showApp();await navigate('dashboard')}""")
            assert page.locator("#nav [data-page='security']").is_hidden()
            assert page.locator("#login-view").is_hidden()
            assert not errors,(width,errors)
            ctx.close()
          reduce=browser.new_context(viewport={"width":1100,"height":860},reduced_motion="reduce")
          rp=reduce.new_page();fresh_login(rp,url)
          assert rp.locator(".jw211-photon-core").evaluate("(x)=>getComputedStyle(x).display")=="none"
          login_synthetic(rp)
          assert rp.locator(".jw210-home .jw211-glass-photon").evaluate("(x)=>x.animationsPaused()")
          rp.locator('.jw210-business-nav [data-jw210-page="orders"]').click()
          rp.wait_for_function("()=>state.page==='orders'")
          assert rp.locator('#main-content').evaluate("(x)=>getComputedStyle(x).animationName")=="none"
          reduce.close()
          # Real playback of the initial login, the same internal photon on the
          # workspace, and the tool-triggered workspace aperture.
          vc=browser.new_context(viewport={"width":1280,"height":800},record_video_dir=str(OUT),
                  record_video_size={"width":1280,"height":800})
          vp=vc.new_page();fresh_login(vp,url)
          vp.locator('.jw211-login-mode[data-jw211-theme="dark"]').click()
          vp.wait_for_timeout(1700)
          login_synthetic(vp)
          vp.wait_for_timeout(2200)
          for route in ("imports","orders","dashboard"):
             if route=="dashboard":vp.locator(".jw210-brand").click()
             else:vp.locator('.jw210-business-nav [data-jw210-page="'+route+'"]').click()
             vp.wait_for_function("(r)=>state.page===r",arg=route)
             vp.wait_for_timeout(900)
          vp.wait_for_timeout(1600)
          video=vp.video;vc.close()
          if video:
              raw=Path(video.path())
              if raw.is_file():
                  out=OUT/"JW-V211-ACTUAL-LOGIN-AND-ROUTES.webm"
                  raw.rename(out)
                  if shutil.which("ffmpeg"):
                     subprocess.run(["ffmpeg","-y","-hide_banner","-loglevel","error",
                        "-i",str(out),"-c:v","libx264","-profile:v","baseline",
                        "-level","3.1","-pix_fmt","yuv420p","-movflags","+faststart",
                        "-r","25",str(OUT/"JW-V211-iPhone-H264.mp4")],check=True,timeout=70)
        finally:browser.close()
    finally:http.shutdown();http.server_close()
    assert all(method=="GET" for method,_ in Handler.requests),Handler.requests
    (OUT/"measurements.json").write_text(json.dumps(reports,ensure_ascii=False,indent=2))
    print("PASS V21.1: login, SINGLE internal photon animated, 5 widths 2 themes, 7 routes, spatial glass aperture, auth hidden, reduced motion, 0 API writes")
if __name__=="__main__":run()
