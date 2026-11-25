"""Actual loopback HTTPS Chromium using both synthetic HttpOnly sessions and PG17.
Never runs outside an ephemeral Actions runner. No ignored certificate errors.
"""
import os,socket,tempfile,threading,time
from pathlib import Path
import uvicorn
from playwright.sync_api import sync_playwright
from app import pg_cinema_cutover_front_v223 as cut
from scripts.ci_v93_https_pg_browser import _ssl_files

def verify_browser(app,legacy_token,pg_token):
    if os.getenv("GITHUB_ACTIONS")!="true" or os.getenv("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE" or os.getenv("NARUV_WORKSPACE_BROWSER")!="EPHEMERAL_ONLY":
        raise RuntimeError("BROWSER_ISOLATION_REQUIRED")
    with tempfile.TemporaryDirectory(prefix="naruv-browser-") as tmp:
        key,cert=_ssl_files(Path(tmp))
        sock=socket.socket();sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
        origin=f"https://127.0.0.1:{port}"
        prior=os.environ["JW_V90_ALLOWED_ORIGINS"];os.environ["JW_V90_ALLOWED_ORIGINS"]=origin
        server=uvicorn.Server(uvicorn.Config(app,host="127.0.0.1",port=port,ssl_keyfile=str(key),ssl_certfile=str(cert),lifespan="off",log_level="warning",access_log=False))
        thread=threading.Thread(target=server.run,kwargs={"sockets":[sock]},daemon=True)
        try:
            thread.start()
            for _ in range(100):
                if server.started:break
                if not thread.is_alive():raise RuntimeError("BROWSER_SERVER_STOPPED")
                time.sleep(.1)
            else:raise RuntimeError("BROWSER_SERVER_TIMEOUT")
            with sync_playwright() as pw:
                browser=pw.chromium.launch(headless=True,chromium_sandbox=True)
                try:
                    ctx=browser.new_context(viewport={"width":1440,"height":900},ignore_https_errors=False)
                    try:
                        ctx.add_cookies([{"name":name,"value":token,"url":origin,"httpOnly":True,"secure":True,"sameSite":"Strict"} for name,token in ((cut.LEGACY_COOKIE,legacy_token),(cut.PG_COOKIE,pg_token))])
                        page=ctx.new_page();errors=[];page.on("pageerror",lambda e:errors.append(str(e)))
                        page.goto(origin+"/naruv-workspace",wait_until="domcontentloaded")
                        page.locator("#pay").click()
                        page.locator("#status").get_by_text("직원과 급여 기간을 확인하세요.").wait_for()
                        page.locator("#worker").fill("worker-1");page.locator("#period").fill("2026-11");page.locator("#pay").click()
                        page.locator("#status").get_by_text("조회 완료").wait_for(timeout=20000)
                        assert "114,000 원" in page.locator("#result").inner_text()
                        page.locator("#staff").click()
                        page.locator("#status").get_by_text("조회 완료").wait_for(timeout=20000)
                        assert "worker-1" in page.locator("#result").inner_text()
                        page.locator("#overview").click()
                        page.locator("#status").get_by_text("조회 완료").wait_for(timeout=20000)
                        assert "매출 미수금" in page.locator("#result").inner_text()
                        page.locator("#doc").fill("shared");page.locator("#document").click()
                        page.locator("#status").get_by_text("조회 완료").wait_for(timeout=20000)
                        assert "원본 검토 필요" in page.locator("#result").inner_text()
                        page.set_viewport_size({"width":390,"height":844})
                        page.locator("#mobile").wait_for(state="visible")
                        assert not page.locator("#desk").is_visible()
                        page.set_viewport_size({"width":1440,"height":900})
                        page.wait_for_function("document.querySelector('#result').childElementCount===0")
                        ctx.clear_cookies()
                        page.locator("#overview").click()
                        page.locator("#status").get_by_text("조회 실패",exact=False).wait_for(timeout=20000)
                        assert page.locator("#result").inner_text()==""
                        assert not errors
                        print("NARUV_WORKSPACE_REAL_HTTPS_BROWSER_PASS desktop, mobile restriction, real PG reads, expired session, no JS errors",flush=True)
                    finally:ctx.close()
                finally:browser.close()
        finally:
            server.should_exit=True;thread.join(timeout=10);sock.close();os.environ["JW_V90_ALLOWED_ORIGINS"]=prior
            if thread.is_alive():raise RuntimeError("BROWSER_SERVER_SHUTDOWN")
