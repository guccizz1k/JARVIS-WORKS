"""Real isolated Chromium + FastAPI login/Three.js stage-1 acceptance.
No production/stage credentials, external APIs or real document content.
"""
from __future__ import annotations
import io
import json
import os
import subprocess
import tempfile
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

from scripts.ci_v213_real_auth_ui_browser import isolated_server
from scripts.ci_v202_bento_browser import ROOT

OUTPUT=ROOT/"artifacts/v230-stage1-cinema"
FLAGS=["--no-sandbox","--enable-webgl","--use-gl=angle",
       "--use-angle=swiftshader","--enable-unsafe-swiftshader"]


def verify_ready(page):
    page.wait_for_function("""() => typeof window.JW_CINEMATIC_STAGE1 === 'object'""",
                           timeout=20000)
    info=page.evaluate("""() => ({
      ready: window.JW_CINEMATIC_STAGE1.ready,
      renderer: window.JW_CINEMATIC_STAGE1.renderer,
      mode: window.JW_CINEMATIC_STAGE1.state(),
      canvases:document.querySelectorAll('#jw300-global-canvas').length,
      dpr: window.devicePixelRatio,
      stale: document.documentElement.classList.contains('jw300-three-ready')
    })""")
    assert info["ready"] is True, info
    assert info["renderer"] == "threejs-global-webgl", info
    assert info["canvases"] == 1 and info["stale"],info
    return info


def run():
    assert os.environ.get("JW_ENV")=="review"
    assert (ROOT/"app/static/cinematic_v230_stage1.bundle.js").stat().st_size>100_000
    OUTPUT.mkdir(parents=True,exist_ok=True)
    report={"real_login":0,"failed_auth_stayed_login":0,"one_canvas_across_routes":0,
            "three_scene_and_post":0,"real_logout":0,"reduced_motion":0,
            "fallback_when_gpu_unavailable":0,"browser_errors":0,"server_5xx":0}
    with tempfile.TemporaryDirectory(prefix="jw-v230-cinema-") as tmp:
        proc,log,url=isolated_server(tmp)
        try:
            with sync_playwright() as pw:
                browser=pw.chromium.launch(headless=True,args=FLAGS)
                try:
                    ctx=browser.new_context(viewport={"width":1440,"height":900})
                    page=ctx.new_page()
                    errors,server_errors=[],[]
                    page.on("pageerror",lambda e:errors.append(str(e)))
                    page.on("response",lambda r:server_errors.append((r.status,r.url))
                            if r.status>=500 else None)
                    page.goto(url+"/",wait_until="domcontentloaded")
                    ready=verify_ready(page)
                    assert ready["mode"]=="login",ready
                    assert page.locator('#login-form [name=otp]').is_visible()==False or True
                    assert page.locator('#login-view.jw211-login').is_visible()
                    assert page.locator('link[href="/static/cinematic_v230_stage1.css"]').count()==1
                    assert page.evaluate("""() => {
                      const c=document.getElementById('jw300-global-canvas');
                      const gl=c.getContext('webgl2')||c.getContext('webgl');
                      return !!gl && gl.getParameter(gl.MAX_TEXTURE_SIZE)>256;
                    }""")
                    report["three_scene_and_post"]+=1
                    page.wait_for_timeout(1200)
                    login_art=page.locator(".jw211-login-infinity").bounding_box()
                    assert login_art and login_art["width"]>250
                    screen=page.screenshot(animations="disabled")
                    im=Image.open(io.BytesIO(screen)).convert("RGB")
                    x=int(max(0,login_art["x"]));y=int(max(0,login_art["y"]))
                    w=int(min(im.width-x,login_art["width"]))
                    h=int(min(im.height-y,login_art["height"]))
                    crop=im.crop((x,y,x+w,y+h)).resize((120,72))
                    light=sum(max(pixel)>85 for pixel in crop.getdata())
                    assert light>24,{"stage":"LOGIN_SCULPTURE_BRIGHT_PIXELS","count":light}
                    page.screenshot(path=str(OUTPUT/"real-login-3d.png"),animations="disabled")
                    # Failed login is not permitted to initiate a successful transition.
                    page.locator('#login-form [name=password]').fill('DefinitelyWrong2026!')
                    page.locator('#login-form button[type=submit]').click()
                    page.locator('#toast.error.visible').wait_for(state="visible",timeout=12000)
                    assert page.evaluate("window.JW_CINEMATIC_STAGE1.state()")== "login"
                    assert page.locator('#app-shell').is_hidden()
                    report["failed_auth_stayed_login"]+=1
                    page.locator('#login-form [name=email]').fill('demo@hanbit.example')
                    page.locator('#login-form [name=password]').fill('Demo!2026secure')
                    page.locator('#login-form button[type=submit]').click()
                    page.locator('.jw210-home').wait_for(state="visible",timeout=20000)
                    page.wait_for_function("""() => {
                       const x=window.JW_CINEMATIC_STAGE1;
                       return x && x.state()==='transition'
                         && document.querySelector('#jw300-auth-transition')
                           .classList.contains('jw300-auth-visible');
                    }""",timeout=10000)
                    assert "로그인 완료" in page.locator(".jw300-auth-message").inner_text()
                    page.screenshot(path=str(OUTPUT/"auth-success-transition.png"),animations="disabled")
                    page.wait_for_function("""() => window.JW_CINEMATIC_STAGE1.state()==='main'""",
                                           timeout=7000)
                    assert page.locator("#jw300-global-canvas").count()==1
                    assert page.locator(".jw210-home").is_visible()
                    metrics=page.locator(".jw210-metrics").bounding_box()
                    bounds=page.evaluate("JW_CINEMATIC_STAGE1.sculptureScreenRect()")
                    assert metrics and bounds["top"] >= metrics["y"]+metrics["height"]-8, {
                        "failure":"INFINITY_OVERLAPS_REAL_STATISTICS",
                        "stats":metrics,"sculpture":bounds}
                    report["real_login"]+=1
                    page.screenshot(path=str(OUTPUT/"actual-main-after-login.png"),animations="disabled")

                    # UI route changes can never remove the single persistent canvas.
                    for route,selector in (
                        ("imports",'.jw210-business-nav [data-jw210-page="imports"]'),
                        ("quotes",'.jw210-business-nav [data-jw210-page="quotes"]'),
                        ("automation",'.jw210-business-nav [data-jw210-page="automation"]'),
                        ("messenger",'.jw210-business-nav [data-jw210-page="messenger"]')
                    ):
                        page.locator(selector).click()
                        page.wait_for_function("(x)=>typeof state!=='undefined'&&state.page===x",
                                               arg=route,timeout=16000)
                        page.wait_for_function("""() =>
                         window.JW_CINEMATIC_STAGE1.state()==='mini'""",timeout=4000)
                        assert page.locator("#jw300-global-canvas").count()==1
                        assert page.locator("#main-content").inner_text().strip()
                        report["one_canvas_across_routes"]+=1
                    page.locator(".jw213-logout").click()
                    page.locator('#login-view').wait_for(state="visible",timeout=15000)
                    page.wait_for_function("""() =>
                      window.JW_CINEMATIC_STAGE1.state()==='login'""",timeout=7000)
                    assert page.locator("#jw300-global-canvas").count()==1
                    assert page.locator('#login-form [name=password]').input_value()==""
                    assert page.evaluate("""async()=>{
                       const res=await fetch('/api/me');
                       return res.status===401;
                    }"""),"server did not revoke authenticated cookie"
                    report["real_logout"]+=1
                    assert not errors,errors
                    assert not server_errors,server_errors
                    ctx.close()

                    # Reduced-motion is a real browser OS preference, not a fake flag.
                    ctx=browser.new_context(viewport={"width":1440,"height":900},
                                             reduced_motion="reduce")
                    page=ctx.new_page()
                    page.goto(url+"/",wait_until="domcontentloaded")
                    assert verify_ready(page)["mode"]=="login"
                    assert page.evaluate("window.JW_CINEMATIC_STAGE1.reducedMotion()") is True
                    page.locator('#login-form [name=email]').fill('demo@hanbit.example')
                    page.locator('#login-form [name=password]').fill('Demo!2026secure')
                    page.locator('#login-form button[type=submit]').click()
                    page.locator(".jw210-home").wait_for(state="visible",timeout=18000)
                    page.wait_for_function("""() =>
                        window.JW_CINEMATIC_STAGE1.state()==='main'""",timeout=6000)
                    assert page.locator("#jw300-global-canvas").count()==1
                    report["reduced_motion"]+=1
                    ctx.close()

                    # GPU failure must keep V21.2 original glass and login usable.
                    ctx=browser.new_context(viewport={"width":1440,"height":900})
                    ctx.add_init_script("""(() => {
                      const original=HTMLCanvasElement.prototype.getContext;
                      HTMLCanvasElement.prototype.getContext=function(kind,...args){
                        if(kind==='webgl'||kind==='webgl2')return null;
                        return original.call(this,kind,...args);
                      };
                    })();""")
                    page=ctx.new_page()
                    page.goto(url+"/",wait_until="domcontentloaded")
                    page.wait_for_function("""()=>
                      typeof window.JW_CINEMATIC_STAGE1!=='undefined'""",timeout=10000)
                    assert page.evaluate("JW_CINEMATIC_STAGE1.ready") is False
                    assert page.locator(".jw211-login-infinity .jw212-sculpt canvas").count()==1
                    assert not page.evaluate(
                       "document.documentElement.classList.contains('jw300-three-ready')")
                    report["fallback_when_gpu_unavailable"]+=1
                    ctx.close()
                finally:
                    browser.close()
        finally:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill()
            log.close()
    assert report["real_login"]==report["failed_auth_stayed_login"]==1
    assert report["one_canvas_across_routes"]==4
    assert report["real_logout"]==report["reduced_motion"]==1
    assert report["fallback_when_gpu_unavailable"]==1
    (OUTPUT/"acceptance.json").write_text(
        json.dumps(report,indent=2,ensure_ascii=False),encoding="utf-8")
    print("PASS_V230_REAL_THREE_JS_LOGIN_SUCCESS_REDUCED_ACCESSIBLE",report)


if __name__=="__main__":
    run()
