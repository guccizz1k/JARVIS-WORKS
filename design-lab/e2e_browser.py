"""Live offline Chromium acceptance of the pinned Motion design lab (no external network)."""
from __future__ import annotations
import functools
import http.server
import pathlib
import threading
from contextlib import contextmanager

LAB = pathlib.Path(__file__).resolve().parent

@contextmanager
def server():
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(LAB))
    instance = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{instance.server_address[1]}"
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=3)

def main():
    from playwright.sync_api import sync_playwright
    assert (LAB / "dist/motion.bundle.js").is_file(), "MOTION_RUNTIME_NOT_BUNDLED"
    capture_dir = LAB / "evidence"
    capture_dir.mkdir(exist_ok=True)
    with server() as url, sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        for label, width, height in (("phone",375,812),("tablet",768,1024),("desktop",1440,900)):
            ctx = browser.new_context(viewport={"width":width,"height":height}, reduced_motion="no-preference")
            page = ctx.new_page()
            failures=[]
            page.on("pageerror",lambda e:failures.append(str(e)))
            page.route("**/*", lambda route: route.continue_() if route.request.url.startswith(url) else route.abort())
            page.goto(url+"/demo.html",wait_until="networkidle")
            page.wait_for_function("window.__jwDesignMotion?.mode === 'motion'")
            assert page.locator("[data-motion-card]").count()==3
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"),"HORIZONTAL_OVERFLOW"
            assert page.locator(".jw-action").first.evaluate("(el) => getComputedStyle(el).minHeight")=="44px"
            page.locator(".jw-action").first.focus()
            assert page.locator(".jw-action").first.evaluate("(el) => getComputedStyle(el).outlineStyle")!="none"
            page.locator(".jw-action").first.click()
            assert "동작 확인 완료" in page.locator("[data-demo-status]").inner_text()
            assert not failures,failures
            page.screenshot(path=str(capture_dir/(label+".png")),full_page=True)
            ctx.close()
        reduced = browser.new_context(viewport={"width":375,"height":812},reduced_motion="reduce")
        page = reduced.new_page()
        page.route("**/*", lambda route: route.continue_() if route.request.url.startswith(url) else route.abort())
        page.goto(url+"/demo.html",wait_until="networkidle")
        page.wait_for_function("window.__jwDesignMotion?.mode === 'reduced'")
        assert page.locator("[data-motion-card]").count()==3
        page.locator(".jw-action").first.click()
        assert "동작 확인 완료" in page.locator("[data-demo-status]").inner_text()
        page.screenshot(path=str(capture_dir/"reduced-motion.png"),full_page=True)
        reduced.close()
        browser.close()
    print("PASS: 375/768/1440 + reduced-motion + keyboard focus + safe interaction; no external requests")
if __name__=="__main__":
    main()
