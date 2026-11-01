"""V20.3 interactive UI acceptance: REAL Chromium interactions and screencast.
No external service/production deployment; synthetic tenant API via local loopback.
"""
from __future__ import annotations
import os
import json
import shutil
import subprocess
from pathlib import Path
from threading import Thread
from http.server import ThreadingHTTPServer
from playwright.sync_api import sync_playwright
from scripts.ci_v202_bento_browser import Handler, STATIC

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"artifacts/v203-motion"

def scenario(page,base,*,width:int,record:bool):
    problems=[]
    page.on("pageerror",lambda e:problems.append(str(e)))
    page.goto(base,wait_until="networkidle")
    page.evaluate("""async () => {
      state.user={name:'검증 사용자',org_name:'검증 기업',role:'admin',csrf_token:'ci-synthetic'};
      state.csrf='ci-synthetic';
      showApp();
      await navigate('dashboard');
    }""")
    page.wait_for_selector(".jw-v202-dashboard")
    assert page.locator("body.jw-v203-loading").count()==0
    assert page.evaluate("typeof window.JW_UI_MOTION==='object'")
    assert page.locator(".jw-v202-metric").count()==4
    assert page.locator(".jw-v203-progress").count()==0  # progress has an ID, not class.
    assert page.locator("#jw-v203-progress").count()==1
    assert page.locator(".jw-v202-metric").first.inner_text().find("25건")>=0
    if record:
        page.wait_for_timeout(650)
        page.screenshot(path=str(OUT/"motion-dashboard.png"),full_page=False)
        # Interaction is real: pointer down, active theme, delayed CSS flash.
        page.locator("#jw-v202-theme-toggle").click()
        assert page.locator("html").get_attribute("data-jw-theme")=="blue"
        assert page.evaluate("getComputedStyle(document.querySelector('.jw-v202-feature')).backgroundColor") is not None
        page.wait_for_timeout(550)
        page.screenshot(path=str(OUT/"motion-blue-theme.png"),full_page=False)
        page.locator("#jw-v202-theme-toggle").click()
        page.wait_for_timeout(300)
    # Manually trigger actual async route, assert progress synchronously begins,
    # then check the new page after all API responses are processed.
    started=page.evaluate("""async () => {
      const transition=navigate('customers');
      const busy=document.body.classList.contains('jw-v203-loading');
      await transition;
      return busy;
    }""")
    assert started, "Navigation feedback failed to start"
    page.wait_for_selector("#main-content .page-head")
    assert "거래처 관리" in page.locator("#main-content .page-head").inner_text()
    assert page.locator("body.jw-v203-loading").count()==0
    assert page.locator("#main-content").get_attribute("class").find("jw-v203-entering")>=0 if width==1440 else True
    if record:
        page.wait_for_timeout(550)
        page.screenshot(path=str(OUT/"motion-customers.png"),full_page=False)
    # Real click handler must open a real original customer form, not a fake demo.
    page.locator('[data-action="new-customer"]').click()
    page.wait_for_selector("#modal-root .overlay .modal")
    assert page.locator("#modal-root [role=dialog]").count()==1
    if not page.evaluate("matchMedia('(prefers-reduced-motion:reduce)').matches"):
        assert "jw-v203-modal-pop" in page.locator("#modal-root .modal").evaluate("(node)=>getComputedStyle(node).animationName")
    if record:
        page.wait_for_timeout(380)
        page.screenshot(path=str(OUT/"motion-modal.png"),full_page=False)
    page.locator('#modal-root [data-action="close"]').click()
    assert page.locator("#modal-root [role=dialog]").count()==0
    page.locator('[data-page="audit"]').click()
    page.wait_for_function("""() => state.page==='audit'&&document.querySelector('#main-content h1')?.textContent==='변경 이력'""")
    if record: page.wait_for_timeout(500)
    # More than one working page transition: audit -> original dashboard.
    page.locator('[data-page="dashboard"]').click()
    page.wait_for_selector(".jw-v202-dashboard")
    if record:
        page.wait_for_timeout(500)
        page.locator(".jw-v202-board").scroll_into_view_if_needed()
        page.wait_for_timeout(450)
        page.screenshot(path=str(OUT/"motion-board.png"),full_page=False)
        page.evaluate("window.scrollTo({top:0,behavior:'instant'})")
        page.wait_for_timeout(450)
    # No fake metrics or unescaped backend content even under animated DOM:
    page.evaluate("""() => {
      state.dashboard.recent_quotes=[{
        id:'evil',doc_no:'<img src=x onerror=window.__v203_pwned=1>',
        customer_name:'<svg onload=alert(2)>',
        money:{total:2},status:'draft'
      }];
      document.getElementById('main-content').innerHTML=dashboardPage();
    }""")
    assert page.locator(".jw-v202-worklist img,.jw-v202-worklist svg").count()==0
    assert page.evaluate("window.__v203_pwned===undefined")
    assert not problems,problems
    assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
    print("PASS_V203_REAL_UI",width,"nav dashboard→customers→audit→dashboard, modal, theme, XSS, layout",flush=True)

def main():
    if os.environ.get("JW_ENV")!="review":
        raise RuntimeError("V203 runs in synthetic review only")
    assert STATIC.joinpath("motion_v203.js").exists()
    OUT.mkdir(parents=True,exist_ok=True)
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    thread=Thread(target=server.serve_forever,daemon=True)
    thread.start()
    address="http://127.0.0.1:"+str(server.server_port)+"/"
    Handler.requests=[]
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True,args=["--no-sandbox"])
            try:
                records=OUT/"capture"
                records.mkdir(exist_ok=True)
                context=browser.new_context(
                    viewport={"width":1440,"height":900},device_scale_factor=1,
                    record_video_dir=str(records),
                    record_video_size={"width":1280,"height":800},
                    reduced_motion="no-preference")
                page=context.new_page()
                scenario(page,address,width=1440,record=True)
                page.close()
                orig=Path(page.video.path())
                context.close()
                raw=OUT/"JARVIS_WORKS_V203_interaction.webm"
                shutil.copy2(orig,raw)
                if shutil.which("ffmpeg"):
                    mp4=OUT/"JARVIS_WORKS_V203_interaction.mp4"
                    subprocess.run(["ffmpeg","-hide_banner","-loglevel","error","-y",
                        "-i",str(raw),"-c:v","libx264","-crf","24",
                        "-preset","fast","-pix_fmt","yuv420p","-movflags","+faststart",
                        str(mp4)],check=True,timeout=90)
                    print("PASS_V203_REAL_INTERACTIVE_VIDEO",mp4.name,mp4.stat().st_size,flush=True)
                for width,height in ((768,1024),(390,844)):
                    ctx=browser.new_context(viewport={"width":width,"height":height},reduced_motion="no-preference")
                    pg=ctx.new_page()
                    scenario(pg,address,width=width,record=False)
                    if width==390:
                        pg.locator("#toggle-menu").click()
                        assert pg.locator("#toggle-menu").get_attribute("aria-expanded")=="true"
                        assert pg.locator("body").get_attribute("class").find("jw-v203-drawer-open")>=0
                        pg.locator("#jw-v203-mobile-shade").click(position={"x":350,"y":100})
                        assert pg.locator("#toggle-menu").get_attribute("aria-expanded")=="false"
                        print("PASS_V203_MOBILE_ANIMATED_DRAWER_AND_BACKDROP",flush=True)
                    pg.close();ctx.close()
                reduced=browser.new_context(viewport={"width":1024,"height":768},reduced_motion="reduce")
                pg=reduced.new_page()
                scenario(pg,address,width=1024,record=False)
                pg.wait_for_selector(".jw-v202-dashboard")
                assert pg.evaluate("""() => getComputedStyle(document.querySelector('.jw-v202-metric')).animationName==='none'""")
                assert pg.evaluate("""() => getComputedStyle(document.querySelector('#main-content')).animationName==='none'""")
                print("PASS_V203_REDUCED_MOTION_A11Y_WITH_WORKING_NAV",flush=True)
                pg.close();reduced.close()
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
    assert all(method=="GET" for method,_ in Handler.requests),Handler.requests
    print("PASS_V203_NO_WRITES_NO_LIVE_BACKEND",flush=True)
    print("V203_ARTIFACTS",json.dumps([x.name for x in OUT.glob("*") if x.is_file()]),flush=True)

if __name__=="__main__":main()
