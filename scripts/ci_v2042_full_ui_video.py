"""V20.4 full motion walkthrough video. Browser-recorded real UI clicks, no production.
Original V20.4.1 app untouched. Every endpoint local and synthetic, HTTP write blocked.
"""
from __future__ import annotations
import json, os, shutil, subprocess
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright
from scripts.ci_v204_sunset_browser import SunsetHandler, ROOT
from scripts.ci_v202_bento_browser import Handler

OUT=ROOT/"artifacts/v2042-complete-tour"
class WalkthroughHandler(SunsetHandler):
    def do_GET(self):
        path=urlsplit(self.path).path
        mocks={
            "/api/audit":[],
            "/api/security/overview":{"sessions":[],"events":[],"users":[],"failed_logins_24h":0,"mfa_enabled_user_count":0,"mfa_setup_available":False},
            "/api/security/mfa/status":{"enabled":False,"recovery_codes_remaining":0},
            "/api/automation/time-savings":{"status":"NOT_MEASURED","samples":{"manual":0,"automated":0}},
            "/api/automation/timing/active":{"mode":"none","id":None},
        }
        if path in mocks:
            Handler.requests.append(("GET",path))
            raw=json.dumps(mocks[path],ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type","application/json;charset=utf-8")
            self.send_header("Content-Length",str(len(raw)))
            self.end_headers();self.wfile.write(raw);return
        return super().do_GET()

def init_cursor(page):
    page.evaluate("""() => {
      const style=document.createElement('style');
      style.textContent=`
        #jw-tour-label{position:fixed;right:24px;bottom:22px;z-index:1000;color:#fff;font:750 16px 'Noto Sans KR',Arial,sans-serif;letter-spacing:-.4px;
        border:1px solid #fff6e088;border-radius:17px;background:#1f1d2dd9;box-shadow:0 12px 35px #130d20a6;backdrop-filter:blur(16px);
        padding:13px 18px;max-width:64vw;pointer-events:none;white-space:pre-line;line-height:1.5}
        #jw-tour-label small{display:block;color:#f1d5ba;font-size:10px;letter-spacing:1px;margin-bottom:4px}
        #jw-tour-cursor{position:fixed;left:0;top:0;width:27px;height:27px;border:2px solid #ffecc6;border-radius:50%;
        box-shadow:0 0 0 3px #45304588,0 0 19px #ffecc6aa;transform:translate(-50%,-50%);z-index:9999;pointer-events:none;opacity:0}
        #jw-tour-cursor.down{animation:jw-tour-hit .38s ease}
        @keyframes jw-tour-hit{0%{box-shadow:0 0 0 3px #ffeac6ab,0 0 20px #ffc986cf;transform:translate(-50%,-50%) scale(.75)}
        100%{box-shadow:0 0 0 20px #ffeac600;transform:translate(-50%,-50%) scale(1)}}
        @media(max-width:600px){#jw-tour-label{right:9px;bottom:10px;padding:10px 12px;max-width:86vw;font-size:13px}}
      `;
      document.head.appendChild(style);
      const label=document.createElement('div');label.id='jw-tour-label';document.body.appendChild(label);
      const dot=document.createElement('div');dot.id='jw-tour-cursor';document.body.appendChild(dot);
      document.addEventListener('pointermove',e=>{
        dot.style.left=e.clientX+'px';dot.style.top=e.clientY+'px';dot.style.opacity='1';
      },{passive:true});
      document.addEventListener('pointerdown',()=>{
        dot.classList.remove('down');void dot.offsetWidth;dot.classList.add('down');
      },{passive:true});
    }""")
def stage(page,number,title,pause=330):
    page.evaluate("""a => {
       const e=document.getElementById('jw-tour-label');
       e.innerHTML='<small>V20.4.1 / 실제 UI 조작 · 테스트 데이터 / '+a[0]+'</small>'+a[1];
    }""",[str(number).zfill(2),title])
    page.wait_for_timeout(pause)
    print("PROOF_STEP",number,title,flush=True)
def click_and_wait(page,selector,destination,wait=500):
    page.locator(selector).click(timeout=8500)
    page.wait_for_function("(x) => window.state?.page===x && !document.body.classList.contains('jw-v203-loading')",arg=destination,timeout=14000)
    assert page.locator("#main-content").inner_text().strip()
    page.wait_for_timeout(wait)

def desktop(page,base):
    errors=[]
    page.on("pageerror",lambda e:errors.append(str(e)))
    page.goto(base,wait_until="networkidle")
    page.evaluate("""async () => {
        state.user={id:'synthetic-user',name:'검증 사용자',org_name:'검증 기업',role:'admin',csrf_token:'review'};
        state.csrf='review';showApp();await navigate('dashboard');
    }""")
    page.wait_for_selector(".jw-v204 .v204-head")
    assert page.locator(".jw-v204 .v204-stat").count()==4
    init_cursor(page)
    stage(page,1,"노을 글래스 홈 · 전체 카드 등장",900)
    page.screenshot(path=str(OUT/"01-dashboard.png"))
    stage(page,2,"KPI 카드에 마우스를 올리면 입체 반응")
    for i in range(4):
        page.locator(".v204-stat").nth(i).hover()
        page.wait_for_timeout(550)
    stage(page,3,"카드를 눌러 실제 업무 화면으로 이동")
    click_and_wait(page,'.v204-stat[aria-label*="등록된 문서"]',"imports",650)
    stage(page,4,"문서 업로드 화면 → 글래스 홈")
    click_and_wait(page,'#v204-floating-nav [data-v204-nav="dashboard"]',"dashboard")
    stage(page,5,"그래프 필터: 전체 · 문서 · 거래")
    for filt in ["documents","trades","all"]:
        btn=page.locator('.v204-chart [data-v204-filter="'+filt+'"]')
        btn.click()
        assert btn.get_attribute("aria-pressed")=="true"
        page.wait_for_timeout(650)
    stage(page,6,"그래프 항목 클릭 → 상세 패널 팝업")
    page.locator('.v204-chart [data-v204-inspect="견적"]').click()
    page.get_by_role("dialog",name="등록된 견적").wait_for()
    page.wait_for_timeout(850)
    page.screenshot(path=str(OUT/"02-open-dialog.png"))
    stage(page,7,"닫기 버튼 → 상세 패널 축소")
    page.locator('.v204-details [data-v204-close]').click()
    page.wait_for_function("() => !document.querySelector('.v204-overlay')")
    page.wait_for_timeout(500)
    stage(page,8,"다른 데이터 상세 → 바깥 영역 클릭해 닫기")
    page.locator('.v204-chart [data-v204-inspect="청구"]').click()
    page.get_by_role("dialog",name="청구 문서").wait_for()
    page.wait_for_timeout(500)
    # Click overlay at safe left edge, outside central dialog.
    page.locator(".v204-overlay").click(position={"x":5,"y":5})
    page.wait_for_function("() => !document.querySelector('.v204-overlay')")
    stage(page,9,"키보드 Esc로 닫기")
    page.locator('.v204-chart [data-v204-inspect="수주·발주"]').click()
    page.get_by_role("dialog",name="수주·발주 문서").wait_for()
    page.wait_for_timeout(550)
    page.keyboard.press("Escape")
    page.wait_for_function("() => !document.querySelector('.v204-overlay')")
    stage(page,10,"3D 문서·거래 카드 호버")
    for sel in [".v204-docs",".v204-trades",".v204-chat"]:
        item=page.locator(sel)
        item.scroll_into_view_if_needed()
        item.hover()
        page.wait_for_timeout(600)
    page.evaluate("window.scrollTo({top:0,behavior:'instant'})")
    stage(page,11,"상단 플로팅 메뉴로 화면 교체")
    for sel,target in [("orders","orders"),("invoices","invoices"),("messenger","messenger"),("imports","imports")]:
        stage(page,11,target+" 화면",150)
        click_and_wait(page,'#v204-floating-nav [data-v204-nav="'+sel+'"]',target,650)
    stage(page,12,"기업 거래 메신저: 검색과 대화 영역")
    click_and_wait(page,'#v204-floating-nav [data-v204-nav="messenger"]',"messenger",500)
    query=page.locator("#jw-company-query")
    if query.count():
        query.fill("검증")
        page.wait_for_timeout(450)
        query.fill("")
        page.wait_for_timeout(350)
    stage(page,13,"왼쪽 메뉴: 거래처 관리")
    click_and_wait(page,'#nav [data-page="customers"]',"customers",560)
    stage(page,14,"거래처 추가 버튼 → 실제 입력 모달")
    page.locator('[data-action="new-customer"]').click()
    page.wait_for_selector('#modal-root .modal',state="visible")
    page.wait_for_timeout(600)
    page.screenshot(path=str(OUT/"03-customer-modal.png"))
    form=page.locator('#modal-root input[name="name"]')
    form.fill("UI 테스트용 기업")
    page.wait_for_timeout(300)
    stage(page,15,"입력 내용은 저장하지 않고 닫기")
    page.locator('#modal-root .close-x').click()
    page.wait_for_function("() => !document.querySelector('#modal-root .modal')")
    stage(page,16,"견적 목록 · 검색·필터")
    click_and_wait(page,'#nav [data-page="quotes"]',"quotes",560)
    search=page.locator("#list-search")
    if search.count():
       search.fill("Q-2026");page.wait_for_timeout(350);search.fill("")
    status=page.locator("#status-filter")
    if status.count():
       status.select_option(index=1);page.wait_for_timeout(350);status.select_option(index=0)
    stage(page,17,"감사 이력 · 업무 로그")
    click_and_wait(page,'#nav [data-page="audit"]',"audit",550)
    stage(page,18,"업무 자동화 화면")
    click_and_wait(page,'#nav [data-page="automation"]',"automation",650)
    stage(page,19,"보안 관제 화면")
    click_and_wait(page,'#nav [data-page="security"]',"security",650)
    stage(page,20,"테마 변경 버튼 · 전환 반응")
    click_and_wait(page,'#v204-floating-nav [data-v204-nav="dashboard"]',"dashboard",480)
    toggler=page.locator("#jw-v202-theme-toggle")
    if toggler.is_visible():
       toggler.click();page.wait_for_timeout(750);toggler.click();page.wait_for_timeout(600)
    stage(page,21,"검증 완료 · 실제 업무 흐름 복귀",900)
    page.screenshot(path=str(OUT/"04-finished.png"))
    assert not errors,errors
    print("PASS_COMPLETE_DESKTOP_UI_MOTION_21_CHAPTERS",flush=True)

def mobile(page,base):
    errors=[]
    page.on("pageerror",lambda e:errors.append(str(e)))
    page.goto(base,wait_until="networkidle")
    page.evaluate("""async () => {
       state.user={id:'synthetic-user',name:'검증 사용자',org_name:'검증 기업',role:'admin',csrf_token:'review'};
       state.csrf='review';showApp();await navigate('dashboard');
    }""")
    page.wait_for_selector(".jw-v204")
    init_cursor(page)
    stage(page,22,"iPhone 390px · 반응형 홈",700)
    page.screenshot(path=str(OUT/"05-mobile-dashboard.png"),full_page=True)
    stage(page,23,"모바일 상단 탭 → 거래 화면")
    click_and_wait(page,'#v204-floating-nav [data-v204-nav="orders"]',"orders",550)
    stage(page,24,"상단 탭 → 문서 화면")
    click_and_wait(page,'#v204-floating-nav [data-v204-nav="imports"]',"imports",400)
    stage(page,25,"햄버거 버튼으로 사이드 메뉴 열기")
    page.locator("#toggle-menu").click()
    assert page.locator("#toggle-menu").get_attribute("aria-expanded")=="true"
    page.wait_for_timeout(850)
    page.screenshot(path=str(OUT/"06-mobile-drawer.png"))
    stage(page,26,"배경 터치로 메뉴 닫기")
    page.locator("#jw-v203-mobile-shade").click(position={"x":380,"y":420})
    assert page.locator("#toggle-menu").get_attribute("aria-expanded")=="false"
    stage(page,27,"대시보드 복귀 후 상세 창 열기")
    click_and_wait(page,'#v204-floating-nav [data-v204-nav="dashboard"]',"dashboard",380)
    page.locator('.v204-chart [data-v204-inspect="견적"]').scroll_into_view_if_needed()
    page.locator('.v204-chart [data-v204-inspect="견적"]').click()
    page.get_by_role("dialog",name="등록된 견적").wait_for()
    page.wait_for_timeout(750)
    stage(page,28,"모바일 상세 창 닫기")
    page.locator('.v204-details [data-v204-close]').click()
    page.wait_for_function("() => !document.querySelector('.v204-overlay')")
    stage(page,29,"모바일 검증 종료",650)
    assert page.evaluate("document.documentElement.scrollWidth<=window.innerWidth+1")
    assert not errors,errors
    print("PASS_COMPLETE_MOBILE_UI_MOTION_8_CHAPTERS",flush=True)

def main():
    if os.environ.get("JW_ENV")!="review":raise RuntimeError("Review mode required")
    OUT.mkdir(parents=True,exist_ok=True)
    Handler.requests=[]
    srv=ThreadingHTTPServer(("127.0.0.1",0),WalkthroughHandler)
    Thread(target=srv.serve_forever,daemon=True).start()
    base=f"http://127.0.0.1:{srv.server_port}/"
    try:
      with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,args=["--no-sandbox"])
        try:
          for name,viewport,fn in [
            ("DESKTOP",{"width":1440,"height":900},desktop),
            ("MOBILE",{"width":390,"height":844},mobile),
          ]:
            context=browser.new_context(viewport=viewport,device_scale_factor=1,
                record_video_dir=str(OUT),
                record_video_size={"width":1280,"height":800} if name=="DESKTOP" else {"width":390,"height":844},
                reduced_motion="no-preference")
            page=context.new_page();fn(page,base)
            page.wait_for_timeout(300)
            page.close();raw=Path(page.video.path());context.close()
            mp4=OUT/("JARVIS-WORKS-V2042-"+name+"-ALL-INTERACTIONS.mp4")
            if not shutil.which("ffmpeg"):raise RuntimeError("ffmpeg required for iPhone H.264")
            cmd=["ffmpeg","-hide_banner","-loglevel","error","-y","-i",str(raw),
                  "-c:v","libx264","-pix_fmt","yuv420p","-crf","23","-preset","fast",
                  "-movflags","+faststart",str(mp4)]
            subprocess.run(cmd,check=True,timeout=150)
            assert mp4.exists() and mp4.stat().st_size>100_000
            print("PASS_RECORDING",name,mp4.name,mp4.stat().st_size,flush=True)
        finally:browser.close()
    finally:srv.shutdown();srv.server_close()
    assert all(method=="GET" for method,_ in Handler.requests),Handler.requests
    print("PASS_ISOLATED_REVIEW_ONLY_HTTP_GET_NO_POST",flush=True)
    print("VIDEO_FILES",json.dumps([x.name for x in OUT.glob("*.mp4")]),flush=True)

if __name__=="__main__":main()
