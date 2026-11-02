"""V21.0 real Chromium UX acceptance: source-only, synthetic tenant, no writes."""
from __future__ import annotations
import json, os, subprocess, shutil, time, xml.etree.ElementTree as ET
from pathlib import Path
from threading import Thread
from http.server import ThreadingHTTPServer
from playwright.sync_api import sync_playwright
from scripts.ci_v206_premium_browser import CompleteV206Fixture
from scripts.ci_v202_bento_browser import ROOT, Handler

OUT = ROOT / "artifacts/v210-verified-browser"
WIDTHS = (1440, 1280, 1024, 768, 390)
ROUTES = ("imports","quotes","orders","invoices","automation","messenger","dashboard")
PAYLOADS = (
    "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>",
    "' OR 1=1 --", '\" autofocus onfocus=\"alert(1)',
    "../etc/passwd", "%00", "&lt;script&gt;", "<script>alert(1)</script>",
    "</button><iframe>", "\u202eabc", "\u200b", "복구코드",
    "사업자번호", "문서", "청구", "메신저", "계좌", "대량 업로드", "A"*200, "；";
)
def login(page, url):
    page.goto(url, wait_until="networkidle")
    page.evaluate("""async()=>{state.user={name:'검증 직원',org_name:'검증 기업',role:'admin',csrf_token:'synthetic'};
      state.csrf='synthetic';showApp();await navigate('dashboard');}""")
    page.wait_for_selector(".jw210-home", timeout=16000)
    page.wait_for_selector(".jw210-infinity-art", timeout=12000)
def diagnostics(page, width, mode):
    return page.evaluate("""() => {
      const rect=q=>{const r=document.querySelector(q).getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height}};
      const font=q=>parseFloat(getComputedStyle(document.querySelector(q)).fontSize);
      return {width:innerWidth,scroll:document.documentElement.scrollWidth,
        theme:document.documentElement.dataset.jw206Theme,
        header:rect(".jw210-top-row"),nav:rect(".jw210-business-nav"),
        art:rect(".jw210-infinity-stage"),metric:rect(".jw210-metrics"),
        heroTitle:rect(".jw210-hero-title"),fontTitle:font(".jw210-hero-title h1"),
        fontTab:font(".jw210-nav-btn"),fontMetric:font(".jw210-metric-val"),
        railExpanded:document.querySelector(".jw210-rail").dataset.open};
    }""")
def assert_geometry(r):
    w=r["width"]
    assert r["scroll"]<=w+1,r
    for key in ("header","nav","metric"):
        box=r[key]
        assert box["left"]>=-1 and box["right"]<=w+1 and box["width"]>40,(key,r)
    assert r["nav"]["top"]>=r["header"]["top"],r
    assert r["metric"]["bottom"]>r["metric"]["top"] and r["metric"]["width"]>240,r
    assert r["fontTitle"]>=24 and r["fontTab"]>=12.5 and r["fontMetric"]>=14,r
    assert r["art"]["width"]>100,r
def check_source():
    # The animation must literally travel from 0 to 1 to 0 along the same
    # SVG orbit; a static mockup or a one-direction-only animation fails.
    root=ET.parse(ROOT/"app/static/jw210_infinity.svg").getroot()
    animations=root.findall(".//{http://www.w3.org/2000/svg}animateMotion")
    assert len(animations)>=2,len(animations)
    assert all(a.get("repeatCount")=="indefinite" for a in animations)
    assert any(a.get("keyPoints")=="0;1;0" for a in animations)
    assert any(a.get("keyPoints")=="1;0;1" for a in animations)
    for path in ("app/static/premium_v210.css","app/static/premium_v210.js","app/static/jw210_infinity.svg"):
        assert (ROOT/path).stat().st_size>1000
def go(page,route):
    if route=="dashboard":
        page.locator(".jw210-brand").click()
    else:
        page.locator('.jw210-business-nav button[data-jw210-page="'+route+'"]').click()
    page.wait_for_function("(r)=>state.page===r",arg=route,timeout=16000)
    assert page.locator("#main-content").inner_text().strip(),route
def run():
    assert os.environ.get("JW_ENV")=="review", "Review-only fixture required"
    check_source()
    OUT.mkdir(parents=True,exist_ok=True)
    Handler.requests=[]
    server=ThreadingHTTPServer(("127.0.0.1",0),CompleteV206Fixture)
    Thread(target=server.serve_forever,daemon=True).start()
    url=f"http://127.0.0.1:{server.server_port}/"
    records=[]
    try:
      with sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,args=["--no-sandbox"])
        try:
          for width in WIDTHS:
            ctx=browser.new_context(viewport={"width":width,"height":900 if width>500 else 845},
                                    device_scale_factor=1)
            page=ctx.new_page();errors=[]
            page.on("pageerror",lambda e:errors.append(str(e)))
            login(page,url)
            assert page.locator(".jw210-nav-btn").count()==7
            assert page.locator(".jw210-rail-item").count()==8
            assert page.locator(".jw210-ai-launch").is_visible()
            assert page.locator(".jw210-home").inner_text().find("5,821")==-1
            for theme in ("light","dark"):
                page.locator('[data-jw206-theme-choice="'+theme+'"]').click()
                assert page.evaluate("document.documentElement.dataset.jw206Theme")==theme
                r=diagnostics(page,width,theme);assert_geometry(r)
                records.append(r)
                if width in (1440,390):
                    page.screenshot(path=str(OUT/f"dashboard-{width}-{theme}.png"),
                                    animations="disabled",full_page=(width==390))
            # Hover can reveal a left icon rail, without opening a full sidebar by default.
            if width>=1024:
                rail=page.locator(".jw210-rail")
                assert rail.get_attribute("data-open")=="false"
                rail.hover(position={"x":7,"y":75})
                page.wait_for_function("""()=>document.querySelector('.jw210-rail').dataset.open==='true'""")
                assert page.locator(".jw210-rail-panel").bounding_box()["x"]>=-1
                page.mouse.move(width-5,500)
                page.wait_for_function("""()=>document.querySelector('.jw210-rail').dataset.open==='false'""")
            # Keyboard and touch operation, without requiring hover.
            page.locator(".jw210-rail-toggle").evaluate("(x)=>x.click()")
            assert page.locator(".jw210-rail-toggle").get_attribute("aria-expanded")=="true"
            page.locator(".jw210-rail-toggle").focus()
            page.keyboard.press("Escape")
            assert page.locator(".jw210-rail-toggle").get_attribute("aria-expanded")=="false"
            page.locator(".jw210-ai-launch").click()
            assert page.locator("#jw210-ai-menu").is_visible()
            page.keyboard.press("Escape")
            assert page.locator("#jw210-ai-menu").is_hidden()
            for q in PAYLOADS:
                page.locator(".jw210-search").fill(q)
                assert page.locator(".jw210-search-results script").count()==0
                assert page.locator(".jw210-search-results img").count()==0
            page.locator(".jw210-search").fill("문서")
            page.locator(".jw210-search-results button").first.click()
            page.wait_for_function("()=>state.page==='imports'")
            for route in ROUTES:
                go(page,route)
                assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1"),route
            # Access enforcement must remain in the original navigation ACL.
            page.evaluate("""async()=>{state.user={name:'검증',org_name:'검증 기업',role:'staff',csrf_token:'synthetic'};
             state.csrf='synthetic';showApp();await navigate('dashboard')}""")
            assert page.locator("#nav [data-page='security']").is_hidden()
            # SVG source must load and expose the actual motion elements.
            graphic=page.locator(".jw210-infinity-art")
            graphic.wait_for(state="visible")
            page.wait_for_function("""()=>document.querySelector('.jw210-infinity-art')?.contentDocument?.querySelector('animateMotion')!=null""",timeout=7000)
            if width==1440:
                page.screenshot(path=str(OUT/"dashboard-final-dark.png"),animations="disabled")
            assert not errors,(width,errors)
            ctx.close()
          # Reduced motion must pause the native SVG animation.
          reduced=browser.new_context(viewport={"width":1100,"height":800},reduced_motion="reduce")
          rp=reduced.new_page();login(rp,url)
          rp.wait_for_function("""()=>document.querySelector('.jw210-infinity-art')?.contentDocument?.documentElement?.animationsPaused?.()===true""",timeout=10000)
          reduced.close()
          # Actual Chromium navigation recording rather than synthetic slideshow.
          video=browser.new_context(viewport={"width":1280,"height":720},record_video_dir=str(OUT),
              record_video_size={"width":1280,"height":720})
          vp=video.new_page();login(vp,url)
          vp.locator('[data-jw206-theme-choice="dark"]').click()
          vp.wait_for_timeout(450)
          for route in ("imports","orders","dashboard"):
              go(vp,route);vp.wait_for_timeout(280)
          vp.wait_for_timeout(440)
          raw=vp.video
          video.close()
          if raw:
              src=Path(raw.path())
              if src.exists():
                  final=OUT/"JARVIS-WORKS-V210-REAL-CHROMIUM.webm"
                  src.rename(final)
                  if shutil.which("ffmpeg"):
                      subprocess.run(["ffmpeg","-hide_banner","-loglevel","error","-y","-i",str(final),
                        "-c:v","libx264","-pix_fmt","yuv420p",str(OUT/"JARVIS-WORKS-V210-REAL-CHROMIUM.mp4")],
                        check=True,timeout=90)
        finally:browser.close()
    finally:server.shutdown();server.server_close()
    assert all(method=="GET" for method,_ in Handler.requests),Handler.requests
    (OUT/"geometry.json").write_text(json.dumps(records,ensure_ascii=False,indent=2))
    print("PASS V21.0 5 viewport x 2 themes x 7 real routes; 20 malicious search cases; bidirectional orbit; 0 writes")
if __name__=="__main__":run()
