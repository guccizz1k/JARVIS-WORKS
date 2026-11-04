"""Real isolated FastAPI + Chromium gate for unchanged CINEMA main-route."""
from __future__ import annotations
import os
import re
import tempfile
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright
from scripts.ci_v213_real_auth_ui_browser import isolated_server
from scripts.ci_v202_bento_browser import ROOT



CLICK_BLOCKERS=[]

def click_visible_area(page, locator, label):
    """Physical click on an unobstructed pixel; never force a click through UI overlays."""
    locator.wait_for(state='visible',timeout=20000)
    page.wait_for_timeout(650)  # allow immutable .view entrance transition to finish
    locator.scroll_into_view_if_needed(timeout=10000)
    for attempt in range(3):
        position=locator.evaluate("""el=>{
          const r=el.getBoundingClientRect();
          const points=[];
          for(const yy of [.5,.25,.75,.12,.88]) for(const xx of [.5,.25,.75,.12,.88]){
            const x=r.left+r.width*xx,y=r.top+r.height*yy;
            const top=document.elementFromPoint(x,y);
            if(top&&(top===el||el.contains(top)))points.push({x:r.width*xx,y:r.height*yy});
          }
          return {points,rect:{left:r.left,top:r.top,width:r.width,height:r.height},
            topAtCenter:document.elementFromPoint(r.left+r.width/2,r.top+r.height/2)?.outerHTML.slice(0,160)};
        }""")
        if position['points']:
            point=position['points'][0]
            locator.click(position=point,timeout=5000)
            print('PASS physical click',label,'position',point,flush=True)
            return
        page.wait_for_timeout(350)
    CLICK_BLOCKERS.append((label,position))
    print('BLOCKED physical mouse click; exercising native keyboard Enter for independent server API proof:',label,position,flush=True)
    locator.focus()
    locator.press('Enter')
    return

def run():
    assert os.environ.get('JW_ENV') == 'review'
    original = (ROOT / 'app/static/cinema/JARVIS_WORKS_CINEMA.html').read_text()
    proc = log = None
    with tempfile.TemporaryDirectory(prefix='cinema-main-e2e-') as tmp:
        proc, log, url = isolated_server(tmp)
        try:
            with urllib.request.urlopen(url + '/') as r:
                assert r.status == 200
                html = r.read().decode()
                assert 'sha256-' in r.headers['Content-Security-Policy']
                assert r.headers['X-Frame-Options'] == 'DENY'
                assert r.headers['Cache-Control'] == 'no-store'
            assert re.search(r'<style>(.*?)</style>', html, re.S).group(1) == re.search(r'<style>(.*?)</style>', original, re.S).group(1)
            assert 'async function cinemaBoot()' in html
            assert 'canvas id="gl"' in html
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True,args=['--no-sandbox','--use-gl=angle','--use-angle=swiftshader','--enable-unsafe-swiftshader'])
                try:
                    ctx = browser.new_context(viewport={'width':1440,'height':900})
                    page = ctx.new_page()
                    failures = []
                    page.on('pageerror', lambda e: failures.append(str(e)))
                    page.goto(url + '/', wait_until='domcontentloaded')
                    page.locator('#login:not([hidden]) input[type="email"]').wait_for(state='visible',timeout=25000)
                    assert page.locator('#gl').count() == 1
                    assert page.evaluate("() => fetch('/api/me').then(x=>x.status)") == 401
                    page.evaluate("localStorage.setItem('jw3.db', JSON.stringify({company:{name:'FAKE'},users:[{role:'admin'}]}))")
                    page.reload()
                    page.locator('#login:not([hidden]) input[type="email"]').wait_for(state='visible',timeout=25000)
                    page.locator('#login input[type=email]').fill('demo@hanbit.example')
                    page.locator('#login input[type=password]').fill('Demo!2026secure')
                    page.locator('#login button[type=submit]').click()
                    page.locator('#app.on').wait_for(state='visible',timeout=35000)
                    user=page.evaluate("async()=>{const r=await fetch('/api/me');return r.ok?await r.json():null}")
                    assert user and user['org_id'] and user['email']=='demo@hanbit.example', user
                    assert page.evaluate("async()=>{const r=await fetch('/api/customers');return r.status}")==200
                    assert page.evaluate("async()=>{const r=await fetch('/api/logout',{method:'POST'});return r.status}")==403
                    assert page.evaluate("async()=>{const r=await fetch('/api/me');return r.status}")==200
                    assert page.locator('canvas#gl').count()==1
                    assert page.locator('#app').is_visible()
                    # Verify real CINEMA buttons, not direct fixture API shortcuts.
                    # All mutations target disposable SQLite demo tenants only.
                    page.evaluate("location.hash='#/partners'")
                    click_visible_area(page,page.get_by_role('button',name='＋ 거래처 등록').first,'partner new')
                    partner_form=page.locator('.mback').last
                    partner_form.locator('form.form input[name="name"]').fill('CINEMA 실브라우저 검증 거래처')
                    partner_form.locator('form.form input[name="contact"]').fill('검증담당')
                    partner_form.locator('button[type="submit"]').click()
                    page.wait_for_function("""async()=>{
                      const r=await fetch('/api/customers');
                      return r.ok&&(await r.json()).some(p=>p.name==='CINEMA 실브라우저 검증 거래처');
                    }""",timeout=18000)
                    partners=page.evaluate("async()=>await (await fetch('/api/customers')).json()")
                    partner=next(p for p in partners if p['name']=='CINEMA 실브라우저 검증 거래처')
                    assert partner['contact_name']=='검증담당',partner
                    page.evaluate("location.hash='#/deals'")
                    click_visible_area(page,page.get_by_role('button',name='＋ 견적서',exact=True).first,'quote new')
                    quote_form=page.locator('.mback').last
                    quote_form.locator('form.form input[maxlength="80"]').fill('CINEMA 실제 견적 API 검증')
                    quote_form.locator('form.form select').first.select_option(partner['id'])
                    quote_form.locator('form.form input[aria-label="품명"]').first.fill('검증 부품')
                    quote_form.locator('form.form input[aria-label="수량"]').first.fill('2')
                    quote_form.locator('form.form input[aria-label="단가"]').first.fill('1250')
                    quote_form.locator('.mfoot button.primary').click()
                    page.wait_for_function("""async()=>{
                      const r=await fetch('/api/quotes');
                      return r.ok&&(await r.json()).some(q=>q.title==='CINEMA 실제 견적 API 검증');
                    }""",timeout=18000)
                    quotes=page.evaluate("async()=>await(await fetch('/api/quotes')).json()")
                    quote=next(q for q in quotes if q['title']=='CINEMA 실제 견적 API 검증')
                    assert quote['customer_id']==partner['id'],quote
                    assert quote['money']['total']==2750,quote
                    page.evaluate("location.hash='#/deals/'+"+repr(quote['id'])+")")
                    click_visible_area(page,page.get_by_role('button',name='견적서 발송 처리').first,'quote send')
                    page.wait_for_function("""async(qid)=>{
                      const r=await fetch('/api/quotes/'+encodeURIComponent(qid));
                      return r.ok&&(await r.json()).status==='sent';
                    }""",arg=quote['id'],timeout=18000)
                    # A second real company must NEVER see the first company's data.
                    other_context=browser.new_context(viewport={'width':1366,'height':768})
                    try:
                        other=other_context.new_page()
                        other.goto(url+'/',wait_until='domcontentloaded')
                        other.locator('#login input[type=email]').fill('demo@bada.example')
                        other.locator('#login input[type=password]').fill('Demo!2026secure')
                        other.locator('#login button[type=submit]').click()
                        other.locator('#app.on').wait_for(state='visible',timeout=35000)
                        assert other.evaluate("""async()=>{
                           const r=await fetch('/api/customers');
                           return r.ok&&!(await r.json()).some(p=>p.name==='CINEMA 실브라우저 검증 거래처')
                        }""")
                        assert other.evaluate("""async(qid)=>{
                           const r=await fetch('/api/quotes/'+encodeURIComponent(qid));
                           return r.status===404;
                        }""",quote['id'])
                    finally:
                        other_context.close()
                    print('PASS CINEMA real buttons: customer POST, quote POST, status POST, tenant isolation')
                    if CLICK_BLOCKERS:raise AssertionError('Original CINEMA UI pointer hit-test BLOCKED despite passing server API: '+str(CLICK_BLOCKERS))
                    assert not failures,failures
                    print('PASS: original visuals, real server login, no local auth bypass, real API, CSRF, CINEMA shell')
                    ctx.close()
                finally:
                    browser.close()
        finally:
            if proc is not None:
                proc.terminate()
                try: proc.wait(timeout=10)
                except Exception: proc.kill()
            if log is not None: log.close()


if __name__ == '__main__': run()
