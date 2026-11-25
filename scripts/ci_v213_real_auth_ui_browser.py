"""V21.3 production-UI readiness: original FastAPI login, actual auth cookie,
the approved V21.2 canvas UI, protected business routes, logout and fallback.
Only TEMPORARY / isolated SQLite seeded with synthetic demo accounts.
NEVER production, staging PG, customer data, external host or external API.
"""
from __future__ import annotations
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright
from scripts.ci_v202_bento_browser import ROOT

OUT=ROOT/"artifacts/v213-real-auth"
ROUTES=("imports","quotes","orders","invoices","automation","messenger","dashboard","customers","audit","security")
WIDTHS=(1440,390)

def isolated_server(tmp):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0))
        port=sock.getsockname()[1]
    env=dict(os.environ)
    env.update(JW_ENV="development",JW_INSECURE_LOCAL_DEV="1",DEMO_SEED="1",
               JARVIS_DB_PATH=str(Path(tmp)/"ephemeral-review.db"))
    env.pop("BOOTSTRAP_EMAIL",None)
    env.pop("BOOTSTRAP_PASSWORD",None)
    log=open(Path(tmp)/"uvicorn.log","w",encoding="utf-8")
    proc=subprocess.Popen([sys.executable,"-m","uvicorn","app.main:app",
                           "--host","127.0.0.1","--port",str(port)],
                           cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
    url=f"http://127.0.0.1:{port}"
    try:
        for _ in range(160):
            if proc.poll() is not None:
                raise AssertionError("Backend did not start (exit status "+str(proc.returncode)+")")
            try:
                with urllib.request.urlopen(url+"/api/health",timeout=1) as resp:
                    if resp.status==200:
                        return proc,log,url
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(.15)
        raise AssertionError("Backend health startup timeout")
    except BaseException:
        proc.terminate()
        try:proc.wait(timeout=4)
        except subprocess.TimeoutExpired:proc.kill()
        log.close()
        raise

def check_glass(page,home=False):
    loc=".jw210-home .jw210-infinity-stage" if home else ".jw211-login-infinity"
    element=page.locator(loc+" .jw212-sculpt")
    element.wait_for(state="attached",timeout=15000)
    assert page.locator(loc+" .jw212-sculpt canvas").count()==1
    assert element.evaluate("(x)=>x.querySelector('canvas').width>0")
    assert page.locator(loc+".jw212-ready").count()==1
    assert page.locator(loc+" .jw211-glass-photon").evaluate(
       "(x)=>x.animationsPaused()"),"hidden SVG photon is still burning CPU"
    return loc

def sign_in(page,email):
    page.locator('#login-form [name=email]').fill(email)
    page.locator('#login-form [name=password]').fill('Demo!2026secure')
    page.locator('#login-form button[type=submit]').click()
    page.locator('.jw210-home').wait_for(state="visible",timeout=25000)
    assert page.locator('#login-view').is_hidden()
    assert page.evaluate("state.page")=="dashboard"
    assert page.evaluate("state.csrf.length")>8
    check_glass(page,home=True)
    user=page.evaluate("state.user")
    assert user["email"]==email and user["org_id"]
    assert page.evaluate("""async()=>{const r=await fetch('/api/me');
      return r.ok&&(await r.json()).email===state.user.email}""")
    return user

def navigate_real(page,route):
    if route=="dashboard":
        page.locator('.jw210-brand').click()
    elif route in ("customers","audit","security"):
        page.locator('.jw210-rail-panel [data-jw210-page="'+route+'"]').click()
    else:
        page.locator('.jw210-business-nav [data-jw210-page="'+route+'"]').click()
    page.wait_for_function("(r)=>state.page===r",arg=route,timeout=25000)
    assert page.locator('#main-content').inner_text().strip(),route
    assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1"),route
    assert not page.locator('#toast.error.visible').count(),route

def run():
    assert os.environ.get("JW_ENV")=="review"
    OUT.mkdir(parents=True,exist_ok=True)
    report={"live_server":"isolated original FastAPI","user_logins":0,"session_restores":0,
            "real_routes":0,"logout_revoked":0,"canvas_fallback":0,"viewports":0,
            "theme_states":0,"page_errors":0,"backend_5xx":0}
    with tempfile.TemporaryDirectory(prefix="jw-v213-") as tmp:
        proc,log,url=isolated_server(tmp)
        try:
            with sync_playwright() as p:
                browser=p.chromium.launch(headless=True,args=["--no-sandbox"])
                try:
                    for width in WIDTHS:
                        ctx=browser.new_context(viewport={"width":width,
                            "height":900 if width>600 else 844},device_scale_factor=1)
                        page=ctx.new_page()
                        errors=[];server_errors=[]
                        page.on("pageerror",lambda e:errors.append(str(e)))
                        page.on("response",lambda r:server_errors.append((r.status,r.url))
                                if r.status>=500 else None)
                        page.goto(url+"/",wait_until="domcontentloaded")
                        page.locator("#login-view.jw211-login").wait_for(state="visible")
                        page.wait_for_function("()=>document.querySelector('#login-form [name=email]')?.value.length>0")
                        assert page.locator("#app-shell").is_hidden()
                        assert page.evaluate("""async()=>{const r=await fetch('/api/me');
                          return r.status===401}"""),"Unapproved direct session"
                        check_glass(page)
                        assert page.locator('#login-form [name=otp]').get_attribute("pattern")=="[0-9]{6}"
                        # Wrong password never opens the authenticated shell.
                        page.locator('#login-form [name=password]').fill('invalid-password')
                        page.locator('#login-form button[type=submit]').click()
                        page.locator('#toast.error.visible').wait_for()
                        assert page.locator("#app-shell").is_hidden()
                        page.locator('#login-form [name=password]').fill('Demo!2026secure')
                        user=sign_in(page,'demo@hanbit.example')
                        assert user["org_name"]=="한빛테크"
                        assert page.locator('.jw210-utils .jw213-logout').is_visible()
                        assert page.locator('.jw210-utils .jw213-logout').get_attribute('aria-label')=="안전하게 로그아웃"
                        assert page.evaluate("window.JW_PREMIUM_V213?.auth")=="original-server-auth"
                        report["user_logins"]+=1
                        for theme in ("light","dark"):
                            page.locator('[data-jw206-theme-choice="'+theme+'"]').click()
                            assert page.evaluate("document.documentElement.dataset.jw206Theme")==theme
                            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
                            report["theme_states"]+=1
                            if width==1440:
                                page.screenshot(path=str(OUT/f"real-home-{theme}.png"),animations="disabled")
                        page.reload(wait_until="domcontentloaded")
                        page.locator(".jw210-home").wait_for(state="visible",timeout=25000)
                        assert page.evaluate("state.page")=="dashboard"
                        assert page.locator('#login-view').is_hidden()
                        report["session_restores"]+=1
                        for route in ROUTES:
                            navigate_real(page,route)
                            report["real_routes"]+=1
                        # Failed network logout must NEVER pretend the server revoked
                        # an authenticated cookie; original flawed path was silently swallowed.
                        page.route("**/api/logout",lambda route:route.abort("failed"))
                        page.locator(".jw213-logout").click()
                        page.locator("#toast.error.visible").wait_for(timeout=10000)
                        assert page.locator("#login-view").is_hidden()
                        assert page.evaluate("state.user!==null")
                        page.unroute("**/api/logout")
                        # Original backend logout POST, not a UI-only sign-out.
                        page.locator(".jw213-logout").click()
                        page.locator("#login-view").wait_for(state="visible")
                        assert page.locator("#app-shell").is_hidden()
                        assert page.locator('#login-form [name=password]').input_value()==""
                        assert page.evaluate("""async()=>{const r=await fetch('/api/me');
                          return r.status===401}"""),"Session not revoked"
                        report["logout_revoked"]+=1
                        assert not errors,(width,errors)
                        assert not server_errors,(width,server_errors)
                        report["viewports"]+=1
                        ctx.close()
                    # Two independent actual org logins to validate frontend tenant identity.
                    ctx=browser.new_context(viewport={"width":1280,"height":800})
                    page=ctx.new_page();page.goto(url+"/")
                    page.locator("#login-view.jw211-login").wait_for()
                    other=sign_in(page,"demo@bada.example")
                    assert other["org_name"]=="바다유통" and other["org_id"]!=user["org_id"]
                    page.locator('.jw210-brand').click()
                    page.wait_for_function("()=>state.page==='dashboard'")
                    assert page.evaluate("state.user.org_name")=="바다유통"
                    report["user_logins"]+=1;ctx.close()
                    # Missing Canvas context must retain the V21.1 accessible SVG,
                    # not leave a blank hero or crash authentication.
                    ctx=browser.new_context(viewport={"width":1024,"height":800})
                    ctx.add_init_script("""(() => {
                       HTMLCanvasElement.prototype.getContext=function(){return null};
                    })();""")
                    page=ctx.new_page();errors=[]
                    page.on("pageerror",lambda e:errors.append(str(e)))
                    page.goto(url+"/")
                    page.locator("#login-view.jw211-login").wait_for()
                    assert page.locator(".jw211-login-infinity .jw212-ready").count()==0
                    assert page.locator(".jw211-login-infinity .jw211-glass-photon").is_visible()
                    assert page.locator(".jw211-login-infinity .jw212-sculpt").count()==0
                    assert not errors,errors
                    report["canvas_fallback"]+=1;ctx.close()
                    # Reduce-motion must halt both animated renderers.
                    ctx=browser.new_context(viewport={"width":1024,"height":800},
                                            reduced_motion="reduce")
                    page=ctx.new_page();page.goto(url+"/")
                    page.locator("#login-view.jw211-login").wait_for()
                    check_glass(page)
                    assert page.locator(".jw211-login-infinity .jw211-glass-photon").evaluate(
                        "(x)=>x.animationsPaused()")
                    ctx.close()
                finally:
                    browser.close()
        finally:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill()
            log.close()
            # Error log is only printed on failure from isolated synthetic app.
            if proc.returncode not in (0,-15,None):
                print("isolated server exit code:",proc.returncode)
    (OUT/"live-auth-acceptance.json").write_text(json.dumps(report,indent=2,ensure_ascii=False))
    print("PASS V21.3 LIVE FastAPI cookie auth + 2 isolated organizations + "
          "real business routes, logout revocation and Canvas fallback",report)

if __name__=="__main__":
    run()
