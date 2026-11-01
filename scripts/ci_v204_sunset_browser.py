"""Source-exact, review-only V20.4 real browser UX and proof capture.
All business API responses synthetic and localhost; no writes or external service calls.
"""
from __future__ import annotations
import json, mimetypes, os, shutil, subprocess
from pathlib import Path
from http.server import ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright
from scripts.ci_v202_bento_browser import Handler, STATIC, DATA, ROOT

OUT=ROOT/"artifacts/v204-sunset"
class SunsetHandler(Handler):
    def do_GET(self):
        path=urlsplit(self.path).path
        extra={
            "/api/order-analytics":{"totals":{"order_count":0,"ordered_quantity":0,"subtotal":0,"vat":0,"total":0},"companies":[]},
            "/api/imports/queue":{"items":[],"total":0},
            "/api/evidence/queue":{"items":[],"total":0},
            "/api/evidence/reconciliation/queue":{"items":[],"total":0},
            "/api/messenger/directory/search":{"items":[],"next_offset":None},
            "/api/messenger/threads":[]
        }
        if path in extra:
            Handler.requests.append(("GET",path))
            raw=json.dumps(extra[path],ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(raw)))
            self.end_headers();self.wfile.write(raw);return
        return super().do_GET()

def login(page,base):
    page.goto(base,wait_until="networkidle")
    page.evaluate("""async () => {
      state.user={name:'검증 사용자',org_name:'검증 기업',role:'admin',csrf_token:'ci-synthetic'};
      state.csrf='ci-synthetic'; showApp(); await navigate('dashboard');
    }""")
    page.wait_for_selector(".jw-v204 .v204-head",timeout=14000)
    assert page.locator(".jw-v204 .v204-stat").count()==4
    assert "28건" in page.locator(".jw-v204 .v204-stat").first.inner_text()
    assert "2,050,000" in page.locator(".jw-v204 .v204-stat").nth(2).inner_text()
    assert page.locator("#v204-floating-nav .v204-nav-pill").count()==5
    assert page.locator(".jw-v204 .v204-chart-bar-container").count()==4
    assert page.evaluate("typeof window.JW_UI_MOTION === 'object'")
    assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1"),"horizontal overflow"

def interactions(page,width,video):
    # 1. Chart is real: shows counts from synthetic company API, never fake hourly series.
    chart=page.locator(".v204-chart")
    chart.get_by_role("button",name="문서").click()
    assert chart.get_by_role("button",name="문서").get_attribute("aria-pressed")=="true"
    assert "83" not in chart.inner_text() # no invented number
    chart.get_by_role("button",name="전체").click()
    chart.locator('[data-v204-inspect="견적"]').click()
    dialog=page.get_by_role("dialog",name="등록된 견적")
    assert dialog.is_visible()
    assert "25" in dialog.locator(".v204-inspect-value").inner_text()
    assert page.evaluate("getComputedStyle(document.querySelector('.v204-details')).animationName")=="v204-inspector-enter" if width==1440 else True
    if video:
        page.wait_for_timeout(350)
        page.screenshot(path=str(OUT/"02-open-inspector.png"),full_page=False)
    page.keyboard.press("Escape")
    page.wait_for_function("() => document.querySelector('.v204-overlay')===null")
    assert page.locator(".v204-overlay").count()==0
    # 2. Actual business navigation, not decorative simulation.
    page.locator('#v204-floating-nav [data-v204-nav="orders"]').click()
    page.wait_for_function("() => state.page==='orders' && document.querySelector('#main-content .page-head')")
    assert "수주·발주 관리" in page.locator("#main-content").inner_text()
    assert page.locator('#v204-floating-nav [data-v204-nav="orders"]').get_attribute("aria-current")=="page"
    if video:
        page.wait_for_timeout(420)
        page.screenshot(path=str(OUT/"03-trade-screen.png"),full_page=False)
    page.locator('#v204-floating-nav [data-v204-nav="dashboard"]').click()
    page.wait_for_selector(".jw-v204")
    assert page.locator('#v204-floating-nav [data-v204-nav="dashboard"]').get_attribute("aria-current")=="page"
    if video:
        page.wait_for_timeout(500)
        page.screenshot(path=str(OUT/"04-return-dashboard.png"),full_page=False)
    # 3. Document path enters the existing upload workflow (original source still functional).
    page.locator('#v204-floating-nav [data-v204-nav="imports"]').click()
    page.wait_for_function("() => state.page==='imports' && document.querySelector('#main-content')?.textContent?.includes('문서')")
    assert "문서" in page.locator("#main-content").inner_text()
    if video:
        page.wait_for_timeout(350)
        page.screenshot(path=str(OUT/"05-real-documents.png"),full_page=False)
    page.locator('#v204-floating-nav [data-v204-nav="dashboard"]').click()
    page.wait_for_selector(".jw-v204")
    assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
    if width<=760:
        page.locator("#toggle-menu").click()
        assert page.locator("#toggle-menu").get_attribute("aria-expanded")=="true"
        assert page.locator("body").get_attribute("class").find("jw-v203-drawer-open")>=0
        page.keyboard.press("Escape")
        assert page.locator("#toggle-menu").get_attribute("aria-expanded")=="false"

def main():
    if os.environ.get("JW_ENV")!="review":raise RuntimeError("review-only")
    assert (STATIC/"sunset_v204.js").exists() and (STATIC/"sunset_v204.css").exists()
    OUT.mkdir(parents=True,exist_ok=True)
    Handler.requests=[]
    srv=ThreadingHTTPServer(("127.0.0.1",0),SunsetHandler)
    th=Thread(target=srv.serve_forever,daemon=True);th.start()
    address="http://127.0.0.1:"+str(srv.server_port)+"/"
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True,args=["--no-sandbox"])
            try:
                for width,height in [(1440,900),(768,1024),(390,844)]:
                    rec=width==1440
                    kwargs={"viewport":{"width":width,"height":height},"device_scale_factor":1}
                    if rec:kwargs.update({"record_video_dir":str(OUT),"record_video_size":{"width":1280,"height":800}})
                    ctx=browser.new_context(**kwargs)
                    page=ctx.new_page()
                    errs=[]
                    page.on("pageerror",lambda e:errs.append(str(e)))
                    login(page,address)
                    if rec:
                        page.wait_for_timeout(600)
                        page.screenshot(path=str(OUT/"01-sunset-dashboard-1440.png"),full_page=False)
                    else:
                        page.screenshot(path=str(OUT/f"dashboard-{width}.png"),full_page=True)
                    interactions(page,width,rec)
                    if rec:
                        page.wait_for_timeout(250)
                        page.close()
                        video_path=Path(page.video.path())
                        ctx.close()
                        mp4=OUT/"JARVIS-WORKS-V204-REAL-UX.mp4"
                        if shutil.which("ffmpeg"):
                            subprocess.run(["ffmpeg","-hide_banner","-loglevel","error","-y",
                               "-i",str(video_path),"-c:v","libx264","-crf","22",
                               "-pix_fmt","yuv420p","-movflags","+faststart",str(mp4)],
                               check=True,timeout=90)
                            print("PASS_V204_USER_VIDEO_MP4",mp4.stat().st_size)
                    else:
                        page.close();ctx.close()
                    assert not errs,errs
                    print("PASS_V204_VIEWPORT",width,flush=True)
                ctx=browser.new_context(viewport={"width":1024,"height":768},reduced_motion="reduce")
                page=ctx.new_page();login(page,address)
                assert page.locator(".jw-v204 .v204-stat").first.evaluate(
                     "(el)=>getComputedStyle(el).animationName")=="none"
                interactions(page,1024,False)
                page.close();ctx.close()
                print("PASS_V204_ACCESSIBLE_REDUCED_MOTION",flush=True)
            finally:browser.close()
    finally:srv.shutdown();srv.server_close()
    assert all(k=="GET" for k,_ in Handler.requests),Handler.requests
    print("PASS_V204_SYNTHETIC_NO_POST_REAL_API_PRESERVED",flush=True)
if __name__=="__main__":main()
