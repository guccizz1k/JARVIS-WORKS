"""V22.2 actual FastAPI+Chromium cinematic scroll, motion, navigation regression.

All fixtures are synthetic, local temporary SQLite, no external network and
no Supabase / Render data or production changes. No appearance-based PASS.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright
from scripts.ci_v213_real_auth_ui_browser import isolated_server, sign_in, navigate_real, ROUTES
from scripts.ci_v202_bento_browser import ROOT

OUT = ROOT / "artifacts/v222-cinematic"
DESKTOPS = [(1280, 850), (1366, 768), (1440, 900), (1920, 1080)]


def run():
    assert os.environ.get("JW_ENV") == "review"
    OUT.mkdir(parents=True, exist_ok=True)
    counts = dict(real_login=0, infinity_single_photon=0, cinematic_sections=0,
                  scroll_progress=0, honest_stats=0, action_routes=0,
                  business_routes=0, mobile_desktop_only=0, reduced_motion=0,
                  ui_errors=0, server_5xx=0)
    with tempfile.TemporaryDirectory(prefix="jw-v222-") as root:
        process, log, url = isolated_server(root)
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True,args=["--no-sandbox"])
                try:
                    for width, height in DESKTOPS:
                        context = browser.new_context(viewport={"width":width,"height":height})
                        page = context.new_page()
                        errs, http500 = [], []
                        page.on("pageerror",lambda e:errs.append(str(e)))
                        page.on("response",lambda r:http500.append((r.status,r.url))
                                if r.status>=500 else None)
                        page.goto(url+"/",wait_until="domcontentloaded")
                        assert page.locator("#login-view.jw211-login").is_visible()
                        assert page.locator("#login-view .jw212-sculpt canvas").count()==1
                        assert page.locator("link[href='/static/cinematic_v222.css']").count()==1
                        assert page.evaluate("typeof JW_CINEMATIC_V222")=="object"
                        assert page.evaluate("JW_CINEMATIC_V222.usesExistingSinglePhoton") is True
                        sign_in(page,"demo@hanbit.example")
                        counts["real_login"]+=1
                        story=page.locator(".jw222-scroll-story")
                        story.wait_for(state="visible",timeout=15000)
                        assert story.locator(".jw222-scene").count()==3
                        assert page.locator(".jw210-infinity-stage .jw212-sculpt canvas").count()==1
                        assert page.locator(".jw210-home .jw222-hero-float").count()==4
                        assert page.locator(".jw222-scroll-cue").is_visible()
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth+1"),width
                        assert page.evaluate("getComputedStyle(document.body).backgroundColor")=="rgb(7, 9, 13)"
                        # No fabricated metrics, externally loaded media or copied COSMOS images.
                        assert page.locator(".jw210-home .jw210-metrics").count()==1
                        assert story.locator("img,video,iframe,canvas").count()==0
                        assert page.locator(".jw222-scene h2").count()==3
                        assert page.locator(".jw222-scene h2").first.inner_text().startswith("문서 한 장이")
                        # V21.4 entrance aperture starts black. Wait until the
                        # real animation completes before capturing acceptance.
                        page.wait_for_function("""() => {
                           const shell=document.querySelector('#app-shell');
                           const stage=document.querySelector('.jw210-infinity-stage');
                           const canvas=stage?.querySelector('.jw212-sculpt canvas');
                           if(!shell||!stage||!canvas)return false;
                           const s=stage.getBoundingClientRect(),c=canvas.getBoundingClientRect();
                           return !shell.classList.contains('jw214-entry-playing')
                             && s.width>250 && s.height>120 && c.width>150
                             && getComputedStyle(stage).visibility==='visible';
                        }""",timeout=12000)
                        if width==1440:
                            from PIL import Image
                            import io
                            raw=page.screenshot(animations="disabled")
                            im=Image.open(io.BytesIO(raw)).convert("RGB")
                            # Reject visually empty hero instead of counting DOM
                            # nodes as evidence of successful rendering.
                            crop=im.crop((460,200,1160,690)).resize((100,70))
                            pixels=list(crop.getdata())
                            assert sum(max(v)>45 for v in pixels)>140, "BLANK_INFINITY_HERO_SCREENSHOT"
                        counts["honest_stats"]+=1
                        counts["infinity_single_photon"]+=1
                        counts["cinematic_sections"]+=3
                        if width==1440:
                            page.screenshot(path=str(OUT/"home-hero-1440.png"),animations="disabled")
                        cue=page.locator(".jw222-scroll-cue")
                        cue.scroll_into_view_if_needed()
                        cue.click()
                        source=page.locator("#jw222-story-source")
                        source.scroll_into_view_if_needed()
                        page.wait_for_timeout(300)
                        assert source.is_visible()
                        stage=source.locator(".jw222-stage-art")
                        page.wait_for_function("""()=> {
                          let el=document.querySelector('#jw222-story-source');
                          return el && el.style.getPropertyValue('--jw222-shift').length>0;
                        }""",timeout=7000)
                        assert stage.evaluate("(x)=>getComputedStyle(x).transform")!="none"
                        if width==1440:
                            page.screenshot(path=str(OUT/"story-source-1440.png"),animations="disabled")
                            page.locator("#jw222-story-continuity").scroll_into_view_if_needed()
                            page.wait_for_timeout(230)
                            page.screenshot(path=str(OUT/"story-flow-1440.png"),animations="disabled")
                            page.locator("#jw222-story-assurance").scroll_into_view_if_needed()
                            page.wait_for_timeout(230)
                            page.screenshot(path=str(OUT/"story-assurance-1440.png"),animations="disabled")
                        counts["scroll_progress"]+=1
                        # New CTA MUST trigger the ORIGINAL protected business route.
                        source.locator('[data-jw222-go="imports"]').click()
                        page.locator("#import-file-form").wait_for(state="visible",timeout=15000)
                        assert not page.locator(".jw222-scroll-story").count()
                        assert page.locator("#import-batch-form").is_visible()
                        counts["action_routes"]+=1
                        if width==1440:
                            page.screenshot(path=str(OUT/"real-import-after-cinematic-cta-1440.png"),animations="disabled")
                        navigate_real(page,"dashboard")
                        page.locator("#jw222-story-source").wait_for(state="attached")
                        page.locator("#jw222-story-continuity [data-jw222-go='automation']").click()
                        page.wait_for_function("() => typeof state !== 'undefined' && state.page==='automation'",timeout=15000)
                        counts["action_routes"]+=1
                        for route in ROUTES:
                            navigate_real(page,route)
                            counts["business_routes"]+=1
                            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth+1"),(width,route)
                        assert not errs,(width,errs)
                        assert not http500,(width,http500)
                        counts["ui_errors"]+=len(errs)
                        counts["server_5xx"]+=len(http500)
                        context.close()
                    # Accessibility: no animation required to view/use content.
                    ctx=browser.new_context(viewport={"width":1440,"height":900},
                                             reduced_motion="reduce")
                    page=ctx.new_page();err=[]
                    page.on("pageerror",lambda e:err.append(str(e)))
                    page.goto(url+"/",wait_until="domcontentloaded")
                    sign_in(page,"demo@hanbit.example")
                    page.locator("#jw222-story-assurance").wait_for(state="attached")
                    page.locator("#jw222-story-continuity").scroll_into_view_if_needed()
                    assert page.locator(".jw222-object").first.evaluate(
                        "(x)=>getComputedStyle(x).animationName")=="none"
                    assert page.locator(".jw222-scene h2").count()==3
                    page.locator("#jw222-story-continuity [data-jw222-go='automation']").click()
                    page.wait_for_function("() => typeof state !== 'undefined' && state.page==='automation'",timeout=12000)
                    assert not err,err
                    counts["reduced_motion"]+=1
                    ctx.close()
                    # Desktop-only protection inherited, never regressed.
                    ctx=browser.new_context(viewport={"width":768,"height":900})
                    page=ctx.new_page();page.goto(url+"/",wait_until="domcontentloaded")
                    page.locator(".jw214-desktop-notice").wait_for(state="visible")
                    assert "PC 전용" in page.locator(".jw214-desktop-notice").inner_text()
                    counts["mobile_desktop_only"]+=1
                    ctx.close()
                finally:browser.close()
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill()
            log.close()
    assert counts["real_login"]==4
    assert counts["cinematic_sections"]==12
    assert counts["scroll_progress"]==4
    assert counts["action_routes"]==8
    assert counts["business_routes"]>=40
    assert counts["ui_errors"]==0 and counts["server_5xx"]==0
    (OUT/"acceptance.json").write_text(json.dumps(counts,ensure_ascii=False,indent=2))
    print("PASS_V222_REAL_CINEMATIC_SCROLL_AND_PROTECTED_BUSINESS_ROUTES",counts)


if __name__=="__main__":
    run()
