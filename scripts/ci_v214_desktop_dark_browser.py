"""V21.4 desktop-only, dark-only UI against the REAL isolated FastAPI runtime.
No external requests, customer files, PostgreSQL writes, deployment or main changes.
"""
from __future__ import annotations
import json,os,subprocess,sys,tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright
from scripts.ci_v213_real_auth_ui_browser import isolated_server,sign_in,navigate_real,ROUTES
from scripts.ci_v202_bento_browser import ROOT

OUT=ROOT/'artifacts/v214-desktop'
DESKTOPS=(1280,1366,1440,1920)
MOBILE_UNSUPPORTED=(390,768,1024)

def assert_dark(page):
    result=page.evaluate("""() => ({
      theme: document.documentElement.getAttribute('data-jw206-theme'),
      scheme: document.querySelector('meta[name=color-scheme]').content,
      stored: localStorage.getItem('jw206-theme'),
      loginChoices: document.querySelectorAll('.jw211-login-mode').length,
      appChoices: document.querySelectorAll('.jw206-theme-option').length
    })""")
    assert result=={'theme':'dark','scheme':'dark','stored':'dark',
                    'loginChoices':0,'appChoices':0},result

def validate_upload_layout(page, width):
    page.locator('.jw214-upload-grid').wait_for(state='visible')
    body=page.locator('.jw214-upload-grid .import-upload-panel .panel-body')
    assert body.count()==2
    metrics=page.evaluate("""() => {
      const grid=document.querySelector('.jw214-upload-grid');
      const form=[...grid.querySelectorAll('.import-upload-panel')];
      const cards=form.map(node=>{
        const b=node.querySelector('.panel-body'),s=getComputedStyle(b),r=node.getBoundingClientRect();
        const txt=b.querySelector('.muted'),cs=getComputedStyle(txt);
        return {bg:s.backgroundImage,color:s.color,muted:cs.color,rect:{x:r.x,y:r.y,w:r.width,h:r.height},
          file:b.querySelector('input[type=file]')?.getAttribute('accept')};
      });
      return {columns:getComputedStyle(grid).gridTemplateColumns,cards,
        screen:innerWidth,scroll:document.documentElement.scrollWidth};
    }""")
    assert metrics['screen']==width
    assert metrics['scroll']<=width+1,metrics
    x,y=metrics['cards']
    assert abs(x['rect']['y']-y['rect']['y'])<3,metrics
    assert x['rect']['x']+x['rect']['w']<=y['rect']['x']+1,metrics
    for card in metrics['cards']:
        assert card['rect']['w']>350,card
        assert card['bg'].startswith('linear-gradient('),card
        assert 'rgb(255, 255, 255)' not in card['bg']
        assert card['file']=='.xlsx,.pdf',card
        assert card['color'].startswith('rgb(')
    assert page.locator('#import-file-form button[type=submit]').is_visible()
    assert page.locator('#import-batch-form button[type=submit]').is_visible()
    assert not page.locator('#toast.error.visible').count()
    return metrics

def run():
    assert os.environ.get('JW_ENV')=='review'
    OUT.mkdir(parents=True,exist_ok=True)
    counts={'desktop_viewports':0,'mobile_blocked':0,'real_server_login':0,
      'entrance_animations':0,'business_routes':0,'upload_panels':0,
      'page_errors':0,'http_5xx':0}
    with tempfile.TemporaryDirectory(prefix='jw-v214-') as tmp:
        proc,log,url=isolated_server(tmp)
        try:
            with sync_playwright() as playwright:
                browser=playwright.chromium.launch(headless=True,args=['--no-sandbox'])
                try:
                    for width in DESKTOPS:
                        ctx=browser.new_context(viewport={'width':width,'height':920},
                             device_scale_factor=1)
                        # Assert light-mode saved from an older visit is safely retired.
                        ctx.add_init_script("""localStorage.setItem('jw206-theme','light')""")
                        page=ctx.new_page();errs=[];server=[]
                        page.on('pageerror',lambda e:errs.append(str(e)))
                        page.on('response',lambda r:server.append((r.status,r.url))
                          if r.status>=500 else None)
                        page.goto(url+'/',wait_until='domcontentloaded')
                        page.locator('#login-view.jw211-login').wait_for(state='visible')
                        assert_dark(page)
                        assert not page.locator('.jw214-desktop-notice').is_visible()
                        sign_in(page,'demo@hanbit.example')
                        assert_dark(page)
                        assert page.evaluate("window.JW_DESKTOP_V214?.mode")=='desktop-dark-only'
                        # Actual class and keyframe; the user previously observed
                        # a no-op immediate transition on successful login.
                        page.wait_for_function("""()=>{
                          const shell=document.querySelector('#app-shell');
                          const m=document.querySelector('#main-content');
                          return shell.classList.contains('jw214-entry-playing') &&
                            getComputedStyle(m).animationName==='jw214-auth-enter';
                        }""",timeout=5000)
                        counts['entrance_animations']+=1
                        if width in (1440,1920):
                            page.screenshot(path=str(OUT/f'dashboard-{width}.png'))
                        for route in ROUTES:
                            navigate_real(page,route)
                            assert_dark(page)
                            counts['business_routes']+=1
                            if route=='imports':
                                m=validate_upload_layout(page,width)
                                counts['upload_panels']+=2
                                if width in (1440,1920):
                                    page.screenshot(path=str(OUT/f'import-{width}.png'))
                        assert not errs,(width,errs)
                        assert not server,(width,server)
                        counts['desktop_viewports']+=1
                        counts['real_server_login']+=1
                        ctx.close()
                    for width in MOBILE_UNSUPPORTED:
                        ctx=browser.new_context(viewport={'width':width,'height':844})
                        page=ctx.new_page();errs=[]
                        page.on('pageerror',lambda e:errs.append(str(e)))
                        page.goto(url+'/',wait_until='domcontentloaded')
                        page.locator('.jw214-desktop-notice').wait_for(state='visible')
                        assert 'PC 전용' in page.locator('.jw214-desktop-notice').inner_text()
                        assert page.locator('#login-view').evaluate(
                           "(x)=>getComputedStyle(x).visibility=='hidden'")
                        assert not errs,(width,errs)
                        counts['mobile_blocked']+=1
                        ctx.close()
                    # Accessibility: reduced motion leaves all actual business
                    # navigation working, without entry animation.
                    ctx=browser.new_context(viewport={'width':1440,'height':900},
                                            reduced_motion='reduce')
                    page=ctx.new_page();page.goto(url+'/')
                    sign_in(page,'demo@hanbit.example')
                    assert page.evaluate(
                      "!document.querySelector('#app-shell').classList.contains('jw214-entry-playing')")
                    navigate_real(page,'imports')
                    validate_upload_layout(page,1440)
                    ctx.close()
                finally:browser.close()
        finally:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill()
            log.close()
    (OUT/'acceptance.json').write_text(json.dumps(counts,ensure_ascii=False,indent=2))
    print('PASS V21.4 PC-only dark-only real FastAPI + animated auth + upload glass',counts)

if __name__=='__main__':run()
