"""Record real JARVIS-WORKS V22.2 UI interactions in isolated Chromium.

This is a continuous browser screen recording, NOT an edited slideshow.
Real local FastAPI, real demo login/cookie, real mouse wheel and buttons.
Synthetic in-memory demo document, temporary local SQLite, no external server.
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
from scripts.ci_v213_real_auth_ui_browser import isolated_server
from scripts.ci_v202_bento_browser import ROOT
from tests.test_evidence_v64 import xlsx

OUT = ROOT / "artifacts/v223-real-ui-video"
ROUTES = ("quotes", "orders", "invoices", "automation",
          "messenger", "customers", "audit", "security", "dashboard")
LABELS = {
    "quotes": "견적서", "orders": "수주·발주", "invoices": "청구·입금",
    "automation": "업무 자동화", "messenger": "기업 메신저",
    "customers": "거래처", "audit": "활동 기록",
    "security": "보안 관리", "dashboard": "대시보드",
}
VIDEO_W, VIDEO_H = 1280, 720

def pause(page, milliseconds=1150):
    page.wait_for_timeout(milliseconds)

def cursor_overlay(page):
    # Recording-only pointer visualizer, follows REAL Chromium mouse events.
    # No application state/API/route changes and no simulated screen content.
    page.evaluate("""() => {
      const node=document.createElement('div');
      node.setAttribute('aria-hidden','true');
      node.id='jw-recording-pointer';
      node.style.cssText=[
        'position:fixed','left:0','top:0','width:26px','height:26px',
        'border:2px solid #eaf0f7','border-radius:50%','z-index:2147483640',
        'pointer-events:none','box-shadow:0 0 0 2px #07090d,0 0 14px #adc7e2',
        'background:rgba(173,199,226,.10)','transform:translate(-50%,-50%)',
        'transition:width 90ms,height 90ms,background 90ms',
        'opacity:0'
      ].join(';');
      document.body.append(node);
      document.addEventListener('mousemove',e=>{
        node.style.left=e.clientX+'px';
        node.style.top=e.clientY+'px';
        node.style.opacity='1';
      },{passive:true});
      document.addEventListener('mousedown',()=>{
        node.style.width='34px';node.style.height='34px';
        node.style.background='rgba(173,199,226,.32)';
      },true);
      document.addEventListener('mouseup',()=>{
        node.style.width='26px';node.style.height='26px';
        node.style.background='rgba(173,199,226,.10)';
      },true);
    }""")
    assert page.locator("#jw-recording-pointer").count()==1

def hover_click(page, locator):
    locator.scroll_into_view_if_needed(timeout=12000)
    locator.hover(timeout=12000)
    pause(page,260)
    locator.click(timeout=12000)

def route_click(page, route):
    if route=="dashboard":
        button=page.locator(".jw210-brand")
    elif route in ("customers","audit","security"):
        rail=page.locator(".jw210-rail")
        rail.hover()
        pause(page,450)
        button=page.locator(f'.jw210-rail-panel [data-jw210-page="{route}"]')
    else:
        button=page.locator(f'.jw210-business-nav [data-jw210-page="{route}"]')
    hover_click(page,button)
    page.wait_for_function("(r)=>window.state&&state.page===r",arg=route,timeout=23000)
    assert page.locator("#main-content").inner_text().strip()
    assert not page.locator("#toast.error.visible").count()
    pause(page,1550)

def run():
    assert os.environ.get("JW_ENV")=="review"
    OUT.mkdir(parents=True,exist_ok=True)
    record_dir=OUT/"raw"
    record_dir.mkdir(exist_ok=True)
    steps=[]
    started=time.monotonic()
    errors=[]
    http500=[]
    def tick(name, **kw):
        steps.append({"at_seconds":round(time.monotonic()-started,2),"action":name,**kw})
    with tempfile.TemporaryDirectory(prefix="jw-v223-real-browser-") as tmp:
        proc,log,url=isolated_server(tmp)
        try:
            with sync_playwright() as pw:
                browser=pw.chromium.launch(headless=True,args=["--no-sandbox"])
                try:
                    ctx=browser.new_context(
                        viewport={"width":VIDEO_W,"height":VIDEO_H},
                        record_video_dir=str(record_dir),
                        record_video_size={"width":VIDEO_W,"height":VIDEO_H},
                        device_scale_factor=1,
                        color_scheme="dark",
                        reduced_motion="no-preference")
                    page=ctx.new_page()
                    rawvideo=page.video
                    page.on("pageerror",lambda e: errors.append(str(e)))
                    page.on("response",lambda r: http500.append((r.status,r.url))
                            if r.status>=500 else None)
                    page.goto(url+"/",wait_until="domcontentloaded")
                    page.locator("#login-view.jw211-login").wait_for(state="visible",timeout=15000)
                    page.locator("#login-view .jw212-sculpt canvas").wait_for(state="attached",timeout=15000)
                    cursor_overlay(page)
                    page.mouse.move(915,390,steps=14)
                    pause(page,2600)
                    tick("actual-login-screen-with-animated-infinity")

                    # A real Chromium mouse-click + local temporary demo account login.
                    email=page.locator('#login-form [name=email]')
                    password=page.locator('#login-form [name=password]')
                    hover_click(page,email)
                    email.fill("demo@hanbit.example")
                    pause(page,380)
                    hover_click(page,password)
                    password.fill("Demo!2026secure")
                    pause(page,450)
                    hover_click(page,page.locator('#login-form button[type=submit]'))
                    page.locator('.jw210-home').wait_for(state="visible",timeout=26000)
                    page.wait_for_function("""() => {
                      const shell=document.querySelector('#app-shell');
                      const stage=document.querySelector('.jw210-infinity-stage');
                      return shell && stage && !shell.classList.contains('jw214-entry-playing')
                        && stage.getBoundingClientRect().width>250;
                    }""",timeout=15000)
                    assert page.evaluate("window.state && state.page==='dashboard'")
                    assert page.locator(".jw210-infinity-stage .jw212-sculpt canvas").count()==1
                    tick("real-authenticated-login-cookie-dashboard")
                    page.mouse.move(890,395,steps=12)
                    pause(page,3000)

                    # Actual physical mouse wheel: observe 3 distinct 3D scenes.
                    page.mouse.move(990,570,steps=12)
                    for scene in ("source","continuity","assurance"):
                        initial=page.evaluate("window.scrollY")
                        for _ in range(3):
                            page.mouse.wheel(0,440)
                            pause(page,410)
                        target=page.locator("#jw222-story-"+scene)
                        target.scroll_into_view_if_needed(timeout=14000)
                        target.wait_for(state="visible",timeout=10000)
                        assert target.locator("h2").inner_text().strip()
                        delta=page.evaluate("window.scrollY")-initial
                        tick("real-mouse-wheel-cinematic-scroll",scene=scene,
                             wheel_delta_y=1320,observed_scroll_delta=delta)
                        pause(page,1500)

                    # Click the ACTUAL new scene CTA into the protected import view.
                    source_cta=page.locator('#jw222-story-source [data-jw222-go="imports"]')
                    hover_click(page,source_cta)
                    page.wait_for_function("() => window.state && state.page==='imports'",timeout=20000)
                    assert page.locator("#import-file-form").is_visible()
                    tick("actual-cinematic-CTA-click-to-document-imports")
                    pause(page,1850)

                    # Real file chooser event + real FastAPI OCR/XLSX preview.
                    upload=page.locator("#evidence-v64-file")
                    upload.wait_for(state="visible",timeout=12000)
                    source_bytes=xlsx(kind="영수증",company="가상 시연 기업",
                                      gross=11000,reference="DEMO-ONLY-V223",
                                      date="2026-11-03")
                    upload.locator('input[type=file]').set_input_files({
                        "name":"가상_영수증_시연자료.xlsx",
                        "mimeType":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        "buffer":source_bytes,
                    })
                    pause(page,650)
                    hover_click(page,upload.locator('button[type=submit]'))
                    preview=page.locator("#evidence-v64-confirm")
                    preview.wait_for(state="visible",timeout=18000)
                    assert page.evaluate("window.state && state.evidencePreview.status==='pending'")
                    assert page.evaluate("state.evidencePreview.confirmation_required===true")
                    tick("real-synthetic-file-upload-and-pending-review")
                    pause(page,2300)

                    # 9 REAL menu clicks / AJAX route loading, incl rail hover.
                    for route in ROUTES:
                        route_click(page,route)
                        tick("real-business-navigation-click",page=route,label=LABELS[route])

                    # Return and capture the central infinity as it continuously moves.
                    page.mouse.move(905,380,steps=10)
                    pause(page,1800)
                    # Actual logout triggers backend cookie revocation.
                    logout=page.locator(".jw213-logout")
                    hover_click(page,logout)
                    page.locator("#login-view").wait_for(state="visible",timeout=15000)
                    assert page.locator("#app-shell").is_hidden()
                    assert page.locator('#login-form [name=password]').input_value()==""
                    tick("real-server-cookie-logout")
                    pause(page,1350)
                    assert not errors,errors
                    assert not http500,http500
                    assert len([s for s in steps if s["action"]=="real-business-navigation-click"])==len(ROUTES)
                    assert len([s for s in steps if s["action"]=="real-mouse-wheel-cinematic-scroll"])==3
                    ctx.close()  # flushes actual Playwright browser-captured video
                    path=Path(rawvideo.path())
                    assert path.exists() and path.stat().st_size>80_000,path
                    shutil.copy2(path,OUT/"JARVIS_WORKS_V222_REAL_BROWSER_RAW.webm")
                    tick("real-playwright-video-flushed",bytes=(OUT/"JARVIS_WORKS_V222_REAL_BROWSER_RAW.webm").stat().st_size)
                finally:
                    browser.close()
        finally:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill()
            log.close()
    summary={
      "source":"CONTINUOUS_REAL_CHROMIUM_PLAYWRIGHT_VIDEO_NOT_STILL_SLIDES",
      "local_server":"isolated FastAPI + temporary SQLite + synthetic demo user",
      "browser_viewport":f"{VIDEO_W}x{VIDEO_H}",
      "demo_files":"in-memory artificial receipt only, no AI-Hub or customer data",
      "actual_business_route_clicks":len(ROUTES),
      "wheel_3d_scenes":3,
      "api_preview_pending":True,
      "actual_logout":True,
      "page_errors":errors,
      "http_5xx":http500,
      "events":steps
    }
    (OUT/"REAL_INTERACTION_PROOF.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2))
    print("PASS_V223_REAL_CHROMIUM_LOGIN_WHEEL_CLICK_UPLOAD_LOGOUT",json.dumps({
      "events":len(steps),"route_clicks":len(ROUTES),"scenes":3,
      "page_errors":len(errors),"http_5xx":len(http500)},ensure_ascii=False))

if __name__=="__main__":
    run()
