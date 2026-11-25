"""Actual loopback HTTPS Chromium using both synthetic HttpOnly sessions and PG17.
Never runs outside an ephemeral Actions runner. No ignored certificate errors.
"""
import os,socket,tempfile,threading,time,ssl,math
from concurrent.futures import ThreadPoolExecutor
import httpx
from pathlib import Path
import uvicorn
from playwright.sync_api import sync_playwright, expect
from app import pg_cinema_cutover_front_v223 as cut
from scripts.ci_v93_https_pg_browser import _ssl_files

def verify_network_reads(origin,cert,legacy_token,pg_token):
    """Actual HTTPS socket, CA/SAN verification, synthetic read-only workload.

    Existing disposable PG connection seam remains; this is not a hosted or
    database-TLS benchmark. No session, raw responses, or secret values logged.
    """
    from urllib.parse import urlsplit
    url=urlsplit(origin)
    if (os.getenv("GITHUB_ACTIONS")!="true" or os.getenv("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE"
        or url.scheme!="https" or url.hostname!="127.0.0.1" or url.username is not None
        or url.path or url.query or url.fragment or not url.port):
        raise RuntimeError("NARUV_NETWORK_ISOLATION_REQUIRED")
    context=ssl.create_default_context(cafile=str(cert))
    root="/api/naruv-review/v1"
    paths=[root+"/valuation/overview",root+"/valuation/audit",root+"/drafts/payroll/worker-1/2026-11",root+"/drafts/documents/shared"]
    cookie={cut.LEGACY_COOKIE:legacy_token,cut.PG_COOKIE:pg_token}
    with httpx.Client(base_url=origin,verify=context,trust_env=False,follow_redirects=False,timeout=12,
                      limits=httpx.Limits(max_connections=8,max_keepalive_connections=8)) as client:
        me=client.get("/api/pg-stage/v90/me",cookies=cookie)
        assert me.status_code==200
        csrf=me.json()["csrf_token"]
        h={"Origin":origin,"X-JW-PG-CSRF":csrf}
        expected={}
        for path in paths:
            r=client.post(path,headers=h,cookies=cookie)
            assert r.status_code==200
            expected[path]=r.json()
        # No cookie, single cookie, hostile origin, malformed CSRF.
        for supplied,headers,code in (
            ({},h,401),({cut.PG_COOKIE:pg_token},h,401),({cut.LEGACY_COOKIE:legacy_token},h,401),
            (cookie,dict(h,Origin="https://invalid.example"),403),
            (cookie,dict(h,**{"X-JW-PG-CSRF":"invalid"}),403)):
            assert client.post(paths[0],headers=headers,cookies=supplied).status_code==code
        def measure(path):
            start=time.perf_counter()
            r=client.post(path,headers=h,cookies=cookie)
            elapsed=(time.perf_counter()-start)*1000
            assert r.status_code==200 and r.json()==expected[path],"NARUV_NETWORK_RESPONSE_DRIFT"
            return elapsed
        start=time.perf_counter()
        with ThreadPoolExecutor(max_workers=8) as pool:
            samples=sorted(pool.map(measure,paths*16))
        elapsed=time.perf_counter()-start
        assert len(samples)==64
        for path in paths:
            r=client.post(path,headers=h,cookies=cookie)
            assert r.status_code==200 and r.json()==expected[path],"NARUV_NETWORK_POST_LOAD_DRIFT"
        p95=samples[math.ceil(len(samples)*.95)-1]
        p99=samples[math.ceil(len(samples)*.99)-1]
        print(f"NARUV_REAL_HTTPS_READ_METRICS n=64 concurrency=8 p95_ms={p95:.2f} p99_ms={p99:.2f} max_ms={samples[-1]:.2f} rps={64/elapsed:.2f}",flush=True)
        print("NARUV_REAL_HTTPS_READ_PASS 64 exact responses, 5 access denials, 4 unchanged post-load reads",flush=True)

def verify_browser(app,legacy_token,pg_token,*,hr_pilot=False):
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
            verify_network_reads(origin,cert,legacy_token,pg_token)
            with sync_playwright() as pw:
                # Ubuntu 24.04 has a vendor Chrome AppArmor profile. Use the
                # runner's installed stable browser; never relax kernel policy,
                # use --no-sandbox, or disable certificate validation.
                chrome=Path("/opt/google/chrome/chrome")
                if not chrome.is_file() or not os.access(chrome,os.X_OK):
                    raise RuntimeError("SUPPORTED_SANDBOX_BROWSER_MISSING")
                browser=pw.chromium.launch(executable_path=str(chrome),headless=True,chromium_sandbox=True)
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
                        if hr_pilot:
                            page.goto(origin+"/naruv-hr-pilot",wait_until="domcontentloaded")
                            page.locator("#register").click()
                            page.locator("#status").get_by_text("변경 확인을 선택하세요.").wait_for()
                            for action in ("register","create","attendance","review","confirm","pay","archive","pay"):
                                if action not in ("review","pay"):page.locator("#approve").check()
                                page.locator("#"+action).click()
                                page.locator("#status").get_by_text("처리 완료").wait_for(timeout=20000)
                                if action=="pay":assert "30,000 원" in page.locator("#result").inner_text()
                            page.set_viewport_size({"width":390,"height":844})
                            expect(page.locator("#desk")).to_be_hidden()
                            expect(page.locator("#mobile")).to_be_visible()
                            # Wait for the actual mobile-state clearing, not just CSS.
                            expect(page.locator("#result > *")).to_have_count(0,timeout=5000)
                            page.set_viewport_size({"width":1440,"height":900})
                            expect(page.locator("#desk")).to_be_visible()
                            expect(page.locator("#result > *")).to_have_count(0,timeout=5000)
                            print("NARUV_HR_PILOT_REAL_BROWSER_PASS confirmed writes, review, gross draft, archive, historical read",flush=True)
                            page.goto(origin+"/naruv-workspace",wait_until="domcontentloaded")
                            page.locator("#overview").click()
                            page.locator("#status").get_by_text("조회 완료").wait_for(timeout=20000)
                            assert "매출 미수금" in page.locator("#result").inner_text()
                        page.set_viewport_size({"width":390,"height":844})
                        page.locator("#mobile").wait_for(state="visible")
                        assert not page.locator("#desk").is_visible()
                        expect(page.locator("#result > *")).to_have_count(0,timeout=5000)
                        page.set_viewport_size({"width":1440,"height":900})
                        # Locator assertions avoid string evaluation blocked by the product CSP.
                        expect(page.locator("#result > *")).to_have_count(0,timeout=5000)
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
