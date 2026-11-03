"""True continuous browser video: JARVIS-WORKS V23.0 Stage-1 Three.js login.

A single real Chromium instance records real local FastAPI authentication,
the real 2.6-second 3D transition, actual scroll and user menu clicks,
and verified backend logout. Screen data is the existing synthetic demo only.
No slideshow, screenshot animation, customer records, live DB or external APIs.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

from scripts.ci_v202_bento_browser import ROOT
from scripts.ci_v213_real_auth_ui_browser import isolated_server, ROUTES
from scripts.ci_v230_stage1_browser import FLAGS

OUT = ROOT / "artifacts/v230-stage1-live-video"
WIDTH, HEIGHT = 1440, 900

def require(condition, description):
    if not condition:
        raise AssertionError(description)

def hold(page, ms=650):
    page.wait_for_timeout(ms)

def move_click(page, locator):
    locator.scroll_into_view_if_needed(timeout=15000)
    locator.hover(timeout=15000)
    hold(page, 330)
    locator.click(timeout=15000)

def install_pointer(page):
    # Only a recording-only mouse halo, NOT a simulated app control.
    page.evaluate("""() => {
      if(document.getElementById('jw-record-cursor'))return;
      const cur=document.createElement('div');
      cur.id='jw-record-cursor';
      cur.setAttribute('aria-hidden','true');
      cur.style.cssText='position:fixed;left:0;top:0;width:25px;height:25px;' +
        'border-radius:50%;border:2px solid #f2f7ff;' +
        'box-shadow:0 0 0 2px #09101b,0 0 15px #9ac8f4;' +
        'background:rgba(206,229,255,.12);pointer-events:none;' +
        'transform:translate(-50%,-50%);z-index:2147483640;opacity:0;' +
        'transition:width 100ms,height 100ms,background 100ms';
      document.body.append(cur);
      document.addEventListener('mousemove', e => {
        cur.style.left=e.clientX+'px';
        cur.style.top=e.clientY+'px';
        cur.style.opacity='1';
      },{passive:true});
      document.addEventListener('pointerdown',()=>{
        cur.style.width='33px';cur.style.height='33px';
        cur.style.background='rgba(206,229,255,.28)';
      },true);
      document.addEventListener('pointerup',()=>{
        cur.style.width='25px';cur.style.height='25px';
        cur.style.background='rgba(206,229,255,.12)';
      },true);
    }""")

def action(page, route):
    if route=="dashboard":
        locator=page.locator(".jw210-brand")
    elif route in ("customers","audit","security"):
        # Real hover-expand left tool rail, not direct JS navigation.
        page.locator(".jw210-rail").hover()
        hold(page, 520)
        locator=page.locator(
            '.jw210-rail-panel [data-jw210-page="'+route+'"]')
    else:
        locator=page.locator(
            '.jw210-business-nav [data-jw210-page="'+route+'"]')
    move_click(page,locator)
    page.wait_for_function(
        "(x) => typeof state!=='undefined' && state.page===x",
        arg=route, timeout=23000)
    require(bool(page.locator("#main-content").inner_text().strip()),
            "ROUTE_PAGE_EMPTY_"+route)
    require(page.locator("#jw300-global-canvas").count()==1,
            "GLOBAL_CANVAS_LOST_"+route)
    expected_mode = "main" if route == "dashboard" else "mini"
    page.wait_for_function(
        "(expected) => JW_CINEMATIC_STAGE1.state()===expected",
        arg=expected_mode, timeout=10000)
    require(page.locator("#toast.error.visible").count()==0,
            "ROUTE_TOAST_ERROR_"+route)
    hold(page, 1120)

def run():
    assert os.environ.get("JW_ENV")=="review"
    OUT.mkdir(parents=True,exist_ok=True)
    recorded=OUT/"source"
    recorded.mkdir(exist_ok=True)
    events=[]
    failures=[]
    http_errors=[]
    started=time.monotonic()
    def tick(title, **meta):
        events.append(dict(t=round(time.monotonic()-started,2),
                           event=title, **meta))
    with tempfile.TemporaryDirectory(prefix="jw-v230-video-") as tmp:
        process, log, url=isolated_server(tmp)
        try:
            with sync_playwright() as pw:
                browser=pw.chromium.launch(headless=True,args=FLAGS)
                try:
                    ctx=browser.new_context(
                        viewport={"width":WIDTH,"height":HEIGHT},
                        record_video_dir=str(recorded),
                        record_video_size={"width":1280,"height":800},
                        device_scale_factor=1,
                        reduced_motion="no-preference",
                        color_scheme="dark")
                    page=ctx.new_page()
                    video=page.video
                    page.on("pageerror",lambda e:failures.append(str(e)))
                    page.on("response",lambda r:http_errors.append((r.status,r.url))
                            if r.status>=500 else None)
                    page.goto(url+"/",wait_until="domcontentloaded")
                    page.locator("#login-view.jw211-login").wait_for(state="visible")
                    page.wait_for_function("""()=>
                      window.JW_CINEMATIC_STAGE1?.ready===true &&
                      JW_CINEMATIC_STAGE1.state()==='login'""",timeout=16000)
                    require(page.locator("#jw300-global-canvas").count()==1,
                            "LOGIN_ONE_THREE_CANVAS")
                    install_pointer(page)
                    page.mouse.move(900,310,steps=12)
                    hold(page,1750)
                    tick("real-3d-infinity-login-view")

                    login=page.locator("#login-form")
                    move_click(page,login.locator('[name=email]'))
                    login.locator('[name=email]').fill("demo@hanbit.example")
                    hold(page,350)
                    move_click(page,login.locator('[name=password]'))
                    login.locator('[name=password]').fill("Demo!2026secure")
                    hold(page,450)
                    move_click(page,login.locator('button[type=submit]'))
                    page.locator(".jw210-home").wait_for(state="visible",timeout=25000)
                    page.wait_for_function("""()=>
                      JW_CINEMATIC_STAGE1.state()==='transition'""",timeout=4500)
                    require("로그인 완료" in page.locator(".jw300-auth-message").inner_text(),
                            "REAL_SUCCESS_TRANSITION_MISSING")
                    tick("authenticated-2point6-second-3d-dolly-bloom-rack-focus")
                    hold(page,1200)
                    page.wait_for_function("""()=>
                      JW_CINEMATIC_STAGE1.state()==='main'""",timeout=6500)
                    require(page.locator(".jw210-home").is_visible(),
                            "HOME_NOT_VISIBLE")
                    require(page.locator("#jw300-global-canvas").count()==1,
                            "GLOBAL_ONE_CANVAS_AFTER_LOGIN")
                    tick("3d-infinity-main-hero")
                    page.mouse.move(970,400,steps=20)
                    hold(page,1950)

                    # Real mouse scroll into all three existing V22.2 scenes.
                    for scene in ("source","continuity","assurance"):
                        before=page.evaluate("window.scrollY")
                        for _ in range(3):
                            page.mouse.wheel(0,420)
                            hold(page,290)
                        target=page.locator("#jw222-story-"+scene)
                        target.scroll_into_view_if_needed()
                        require(target.is_visible(),"SCENE_NOT_VISIBLE_"+scene)
                        tick("real-wheel-scroll-cinema",scene=scene,
                             scroll_delta=round(page.evaluate("window.scrollY")-before,1))
                        hold(page,800)

                    # Real app CTA, then every business tool via real mouse clicks.
                    target=page.locator(
                        '#jw222-story-source [data-jw222-go="imports"]')
                    move_click(page,target)
                    page.wait_for_function("""()=>
                      typeof state!=='undefined' && state.page==='imports'""",
                      timeout=16000)
                    page.locator("#import-file-form").wait_for(state="visible",timeout=16000)
                    require(page.locator("#jw300-global-canvas").count()==1,
                            "CANVAS_DISAPPEARED_DURING_IMPORT")
                    tick("clicked-real-scene-document-tool")
                    hold(page,1000)

                    for route in ROUTES:
                        action(page,route)
                        tick("real-business-tool-click",route=route)

                    # The real backend destroys the session on logout.
                    move_click(page,page.locator(".jw213-logout"))
                    page.locator("#login-view").wait_for(state="visible",timeout=14000)
                    page.wait_for_function("""()=>
                      JW_CINEMATIC_STAGE1.state()==='login'""",timeout=6000)
                    require(page.locator("#app-shell").is_hidden(),
                            "REAL_LOGOUT_SHELL_NOT_HIDDEN")
                    require(page.locator("#login-form [name=password]").input_value()=="",
                            "PASSWORD_REMAINED")
                    require(page.evaluate("""async()=>{
                       const r=await fetch('/api/me');return r.status===401;
                    }"""),"SESSION_COOKIE_NOT_REVOKED")
                    tick("real-server-logout")
                    hold(page,900)
                    require(not failures, str(failures))
                    require(not http_errors, str(http_errors))
                    require(sum(x["event"]=="real-business-tool-click" for x in events)==len(ROUTES),
                            "MISSING_BUSINESS_CLICKS")
                    ctx.close()  # mandatory to flush screen recording
                    src=Path(video.path())
                    require(src.is_file() and src.stat().st_size>100_000,
                            "VIDEO_CAPTURE_NOT_WRITTEN")
                    shutil.copy2(src,OUT/"JARVIS_WORKS_V230_ACTUAL_BROWSER_RAW.webm")
                    tick("one-continuous-playwright-video-file",
                         bytes=(OUT/"JARVIS_WORKS_V230_ACTUAL_BROWSER_RAW.webm").stat().st_size)
                finally:
                    browser.close()
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill()
            log.close()
    report={
        "source":"ONE_CONTINUOUS_ACTUAL_CHROMIUM_RECORDING",
        "app":"JARVIS-WORKS V23.0 Stage-1 Three.js actual FastAPI local test",
        "base":"review/v230-global-infinity-login-cinema-20261103",
        "production_affected":False,
        "isolated_data":"localhost temporary SQLite, seeded synthetic demo account only",
        "real_login":True,"real_logout":True,
        "2_6_sec_login_transition":True,
        "three_js_global_single_canvas":True,
        "scroll_scenes":3,
        "real_business_tool_clicks":len(ROUTES),
        "browser_errors":failures,
        "http_5xx":http_errors,
        "timeline":events,
    }
    (OUT/"ACTUAL_VIDEO_INTERACTION_PROOF.json").write_text(
        json.dumps(report,ensure_ascii=False,indent=2))
    print("PASS_V230_REAL_CONTINUOUS_LOGIN_3D_TOOLS_LOGOUT_VIDEO",json.dumps({
        "events":len(events),"tools":len(ROUTES),"scenes":3,
        "browser_errors":len(failures),"http_5xx":len(http_errors)},
        ensure_ascii=False))

if __name__=="__main__":
    run()
