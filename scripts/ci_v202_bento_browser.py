"""V20.2 Chrome layout/a11y/tenant-data UI smoke. All API replies synthetic.
Only isolated localhost static server; never touches Supabase, Render or real data.
"""
from __future__ import annotations
import json
import mimetypes
import os
from pathlib import Path
from threading import Thread
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]
STATIC=ROOT/"app/static"
OUT=ROOT/"artifacts/v202-ui"
DATA={
  "customers":8,"quotes":25,"orders":12,"invoices":3,"collected":12540000,
  "outstanding":2050000,"quote_total":17000000,
  "recent_quotes":[{"id":"q1","doc_no":"Q-2026-113","customer_name":"한빛테크","status":"draft","money":{"total":176000}},
                   {"id":"q2","doc_no":"Q-2026-114","customer_name":"바다유통","status":"sent","money":{"total":890000}}],
  "recent_orders":[{"id":"o1","doc_no":"O-2026-44","status":"fulfilled"}],
  "issues":[{"id":"i1","kind":"review","title":"발주 변경 확인 필요","doc_no":"O-2026-42"}],
  "evidence":None,
}
class Handler(BaseHTTPRequestHandler):
    requests=[]
    def log_message(self,fmt,*args):pass
    def do_GET(self):
        path=urlsplit(self.path).path
        Handler.requests.append(("GET",path))
        if path.startswith("/api/"):
            answer={
                "/api/config":{"demo_mode":False},
                "/api/me":{"detail":"Synthetic no-login boundary"},
                "/api/customers":[],
                "/api/quotes":[{"id":"q1","status":"draft","doc_no":"Q-2026-113"}],
                "/api/orders":[],
                "/api/invoices":[],
                "/api/dashboard":DATA,
                "/api/automation/drafts/summary":{"total":2,"recent":[]}
            }.get(path,[])
            code=401 if path=="/api/me" else 200
            raw=json.dumps(answer,ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        relative="index.html" if path=="/" else path.removeprefix("/static/")
        candidate=(STATIC/relative).resolve()
        if STATIC not in candidate.parents or not candidate.is_file():
            self.send_error(404);return
        data=candidate.read_bytes()
        mime=mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type",mime+"; charset=utf-8")
        self.send_header("Content-Length",str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_POST(self):
        Handler.requests.append(("POST",self.path))
        self.send_error(403)

def run():
    assert os.getenv("JW_ENV") in ("review","test")
    assert STATIC.joinpath("bento_v202.js").exists()
    OUT.mkdir(parents=True,exist_ok=True)
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    worker=Thread(target=server.serve_forever,daemon=True);worker.start()
    url="http://127.0.0.1:"+str(server.server_port)+"/"
    screenshots=[]
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True,args=["--no-sandbox"])
            try:
                for width,height in ((1440,900),(768,1024),(390,844)):
                    page=browser.new_page(viewport={"width":width,"height":height},device_scale_factor=1)
                    errors=[]
                    page.on("pageerror",lambda e:errors.append(str(e)))
                    page.goto(url,wait_until="networkidle")
                    page.evaluate("""async () => {
                      state.user={name:'검증 사용자',org_name:'검증 기업',role:'admin',csrf_token:'ci-synthetic'};
                      state.csrf='ci-synthetic'; showApp();
                      await navigate('dashboard');
                    }""")
                    assert page.locator("#app-shell").is_visible(),"App shell was rehidden after synthetic login"
                    page.wait_for_selector(".jw-v202-dashboard .jw-v202-bento")
                    assert page.locator(".jw-v202-metric").count()==4
                    assert "25건" in page.locator(".jw-v202-metric").first.inner_text()
                    assert "12건" in page.locator(".jw-v202-chart-row").nth(1).inner_text()
                    assert "12,540,000원" in page.locator(".jw-v202-gauge").first.inner_text()
                    assert page.locator(".jw-v202-task").count()>=1
                    assert page.get_by_role("button",name="강조색 변경: 현재 녹색").count()==1
                    page.locator("#jw-v202-theme-toggle").click()
                    assert page.locator("html").get_attribute("data-jw-theme")=="blue"
                    page.locator("#jw-v202-theme-toggle").click()
                    assert page.locator("html").get_attribute("data-jw-theme")=="green"
                    overflow=page.evaluate("""() => ({
                        viewport:innerWidth,
                        scrollWidth:document.documentElement.scrollWidth,
                        offenders:Array.from(document.querySelectorAll('#app-shell *'))
                            .filter(el=>el.getBoundingClientRect().right > innerWidth+1)
                            .slice(0,6).map(el=>({
                                tag:el.tagName,cls:el.className,
                                right:Math.round(el.getBoundingClientRect().right)
                            }))
                    })""")
                    assert overflow["scrollWidth"]<=overflow["viewport"]+1,overflow
                    assert not errors,errors
                    dest=OUT/("dashboard-"+str(width)+".png")
                    page.screenshot(path=str(dest),full_page=True,animations="disabled")
                    screenshots.append(str(dest))
                    # DOM XSS escaping from untrusted backend content.
                    page.evaluate("""() => {
                      state.dashboard.recent_quotes=[{
                        id:'q-malicious',
                        doc_no:'<img src=x onerror=window.__v202_pwned=1>',
                        customer_name:'<svg onload=alert(1)>',
                        money:{total:2},status:'draft'}];
                      document.querySelector('#main-content').innerHTML=dashboardPage();
                    }""")
                    assert page.locator(".jw-v202-worklist img,.jw-v202-worklist svg").count()==0
                    assert page.evaluate("window.__v202_pwned === undefined")
                    page.close()
                # A zero-data tenant must not inherit values from the demo.
                page=browser.new_page(viewport={"width":1440,"height":900})
                page.goto(url,wait_until="networkidle")
                page.evaluate("""() => {
                  state.user={name:'B',org_name:'Empty Tenant',role:'member'};
                  state.dashboard={customers:0,quotes:0,orders:0,invoices:0,
                    collected:0,outstanding:0,recent_quotes:[],recent_orders:[],issues:[]};
                  state.quotes=[];state.automationDraftSummary={total:0,recent:[]};
                  showApp();
                  document.querySelector('#main-content').innerHTML=dashboardPage();
                }""")
                assert page.locator(".jw-v202-metric").first.inner_text().find("0건")>=0
                assert "12,540,000" not in page.locator("#main-content").inner_text()
                assert "0원" in page.locator(".jw-v202-gauge").first.inner_text()
                assert page.locator(".jw-v202-task").count()==0
                assert page.locator("#security-nav").is_hidden()
                page.close()
            finally:browser.close()
    finally:server.shutdown();server.server_close()
    assert not any(method!="GET" for method,_ in Handler.requests),Handler.requests
    print("PASS_V202_BROWSER_3_BREAKPOINTS_THEME_REAL_API_SHAPE_XSS_ZERO_TENANT_NO_POST")
    print("V202_UI_SCREENSHOTS",json.dumps(screenshots,ensure_ascii=False))

if __name__=="__main__":run()
