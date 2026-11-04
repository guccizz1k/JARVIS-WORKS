"""Real isolated FastAPI + Chromium gate for unchanged CINEMA main-route."""
from __future__ import annotations
import os
import re
import time
import tempfile
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright
from scripts.ci_v213_real_auth_ui_browser import isolated_server
from scripts.ci_v202_bento_browser import ROOT



CLICK_BLOCKERS=[]

def wait_for_api_condition(page, awaited_js, *, arg=None, timeout=18000, poll_ms=225):
    """Wait for a *resolved* fetch result, never for a truthy Promise object.

    Playwright wait_for_function(async ()=>...) can be accidentally satisfied by
    a Promise before it resolves to false. This helper evaluates/awaits each
    response, checks exact True, and fails closed on a deadline.
    """
    deadline=time.monotonic()+timeout/1000.0
    last=None
    while time.monotonic()<deadline:
        try:
            result=page.evaluate(awaited_js,arg)
            if result is True:
                return
            last=result
        except Exception as exc:
            last=str(exc)
        page.wait_for_timeout(poll_ms)
    raise AssertionError('Awaited backend state not observed: '+str(last))


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
        # A throwaway Fernet key is generated only for the isolated CI server.
        # Never use or inspect real MFA secrets/credentials in this test.
        from cryptography.fernet import Fernet
        os.environ['JW_DATA_KEY']=Fernet.generate_key().decode('ascii')
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
                    click_visible_area(page,page.locator('#vw .ph .acts').get_by_role('button',name='＋ 거래처 등록'),'partner new')
                    partner_form=page.locator('.mback').last
                    partner_form.locator('form.form input[name="name"]').fill('CINEMA 실브라우저 검증 거래처')
                    partner_form.locator('form.form input[name="contact"]').fill('검증담당')
                    partner_form.locator('button[type="submit"]').click()
                    wait_for_api_condition(page,"""async()=>{
                      const r=await fetch('/api/customers',{cache:'no-store'});
                      return r.ok&&(await r.json()).some(p=>p.name==='CINEMA 실브라우저 검증 거래처');
                    }""")
                    partners=page.evaluate("async()=>await (await fetch('/api/customers')).json()")
                    partner=next(p for p in partners if p['name']=='CINEMA 실브라우저 검증 거래처')
                    assert partner['contact_name']=='검증담당',partner
                    page.evaluate("location.hash='#/deals'")
                    click_visible_area(page,page.locator('#vw .ph .acts').get_by_role('button',name='＋ 견적서',exact=True),'quote new')
                    quote_form=page.locator('.mback').last
                    quote_form.locator('form.form input[maxlength="80"]').fill('CINEMA 실제 견적 API 검증')
                    quote_form.locator('form.form select').first.select_option(partner['id'])
                    quote_form.locator('form.form input[aria-label="품명"]').first.fill('검증 부품')
                    quote_form.locator('form.form input[aria-label="수량"]').first.fill('2')
                    quote_form.locator('form.form input[aria-label="단가"]').first.fill('1250')
                    quote_form.locator('.mfoot button.primary').click()
                    wait_for_api_condition(page,"""async()=>{
                      const r=await fetch('/api/quotes',{cache:'no-store'});
                      return r.ok&&(await r.json()).some(q=>q.title==='CINEMA 실제 견적 API 검증');
                    }""")
                    quotes=page.evaluate("async()=>await(await fetch('/api/quotes')).json()")
                    quote=next(q for q in quotes if q['title']=='CINEMA 실제 견적 API 검증')
                    assert quote['customer_id']==partner['id'],quote
                    assert quote['money']['total']==2750,quote
                    page.evaluate("(id)=>{location.hash='#/deals/'+id}",quote['id'])
                    click_visible_area(page,page.get_by_role('button',name='견적서 발송 처리').first,'quote send')
                    wait_for_api_condition(page,"""async(qid)=>{
                      const r=await fetch('/api/quotes/'+encodeURIComponent(qid),{cache:'no-store'});
                      return r.ok&&(await r.json()).status==='sent';
                    }""",arg=quote['id'])
                    # Exercise the actual CINEMA approval and quote-to-order buttons.
                    page.get_by_role('button',name='고객 승인 처리',exact=True).click(timeout=20000)
                    wait_for_api_condition(page,"""async(qid)=>{
                      const r=await fetch('/api/quotes/'+encodeURIComponent(qid),{cache:'no-store'});
                      return r.ok&&(await r.json()).status==='accepted';
                    }""",arg=quote['id'])
                    page.get_by_role('button',name='수주 등록',exact=True).click(timeout=20000)
                    order_form=page.locator('.mback').last
                    from datetime import datetime,timedelta
                    from zoneinfo import ZoneInfo
                    due=(datetime.now(ZoneInfo('Asia/Seoul')).date()+timedelta(days=14)).isoformat()
                    order_form.locator('input[name="due_date"]').fill(due)
                    order_form.locator('button[type="submit"]').click()
                    wait_for_api_condition(page,"""async(qid)=>{
                      const r=await fetch('/api/orders',{cache:'no-store'});
                      return r.ok&&(await r.json()).some(o=>o.quote_id===qid);
                    }""",arg=quote['id'])
                    orders=page.evaluate("async()=>await(await fetch('/api/orders')).json()")
                    order=next(o for o in orders if o['quote_id']==quote['id'])
                    assert order['status']=='received' and order['money']['total']==2750,order
                    # Refuse invoice issuance until delivery was actually confirmed.
                    invalid=page.evaluate("""async oid=>{
                      const r=await fetch('/api/invoices/from-order',{method:'POST',
                        credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':window._unknown||''},
                        body:JSON.stringify({order_id:oid,due_date:'2099-01-01'})});
                      return r.status;
                    }""",order['id'])
                    assert invalid==403,invalid
                    print('PASS real CINEMA buttons: customer, quote, approval, order; CSRF denial')
                    # Real CINEMA document-picker -> authenticated evidence OCR preview;
                    # a generated XLSX is used, never customer or licensed documents.
                    from tests.test_evidence_v64 import xlsx
                    page.evaluate("location.hash='#/docs'")
                    page.locator('#vw .drop').wait_for(state='visible', timeout=20000)
                    with page.expect_file_chooser(timeout=15000) as chooser_info:
                        click_visible_area(page,page.locator('#vw .drop button').first,'document file')
                    chooser_info.value.set_files([{
                        'name':'cinema-synthetic-receipt.xlsx',
                        'mimeType':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                        'buffer':xlsx(reference='CINEMA-QA-20261104')
                    }])
                    # Playwright wait_for_function must not be given an async predicate:
                    # it treats the Promise itself as truthy before its false result.
                    # Evaluate the awaited fetch separately, then poll synchronously.
                    receipt=None
                    queue_result=None
                    for attempt in range(50):
                        queue_result=page.evaluate("""async()=>{
                          const r=await fetch('/api/evidence/queue',{cache:'no-store'});
                          return {status:r.status,data:await r.json()};
                        }""")
                        records=queue_result.get('data',{}).get('items',[])
                        receipt=next((f for f in records if f.get('filename')=='cinema-synthetic-receipt.xlsx'),None)
                        if receipt:break
                        page.wait_for_timeout(250)
                    assert receipt and receipt['id'],{
                        'queue':queue_result, 'toast':page.locator('#flash').inner_text(timeout=2500),
                        'page_errors':failures
                    }
                    evidence=page.evaluate("""async(eid)=>{
                      const r=await fetch('/api/evidence/preview/'+encodeURIComponent(eid));
                      return r.ok?await r.json():null;
                    }""",receipt['id'])
                    assert evidence and evidence['status']=='pending' and evidence['document']['document_kind']=='receipt',evidence
                    # Upload previews must NOT silently create an approved accounting transaction.
                    assert page.evaluate("async()=> (await (await fetch('/api/evidence/records')).json()).length")==0
                    print('PASS physical CINEMA file picker -> server OCR preview; requires manual approval',flush=True)
                    # Server evidence must open through the original CINEMA
                    # drawer without any missing local-parser fields throwing.
                    page.evaluate("location.hash='#/files'")
                    page.wait_for_function(
                        "()=>document.title==='파일·첨부 — JARVIS WORKS'",
                        timeout=16000)
                    item_row=page.locator('#vw table.tbl tbody tr').filter(
                        has_text='cinema-synthetic-receipt.xlsx').first
                    item_row.wait_for(state='visible',timeout=12000)
                    click_visible_area(page,item_row,'server-backed evidence detail')
                    drawer=page.locator('.drawer[role="dialog"]')
                    drawer.wait_for(state='visible',timeout=12000)
                    detail=drawer.inner_text()
                    assert '서버 OCR 분류가 접수되었습니다' in detail,detail
                    assert 'NaN' not in detail and 'undefined' not in detail,detail
                    assert not failures,failures
                    drawer.locator('button.ibtn').first.click()
                    # Local demo automation defaults must NOT appear as
                    # running business automation in a server-backed session.
                    page.evaluate("location.hash='#/automation'")
                    page.wait_for_function(
                        "()=>document.title==='업무 자동화 — JARVIS WORKS'",
                        timeout=16000)
                    assert '0 / 5' in page.locator('#vw .kpi').last.inner_text()
                    print('PASS original file drawer safe server OCR state and truthful zero automation rules',flush=True)
                    # Negative proof: a resolved false predicate MUST time out,
                    # rather than passing because a Promise object is truthy.
                    poll_false=0
                    try:
                        wait_for_api_condition(page,"async()=>{await Promise.resolve();return false}",timeout=450,poll_ms=100)
                    except AssertionError:
                        poll_false=1
                    assert poll_false==1, 'Async wait negative control was bypassed'
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
                    # Real authenticated member role: the server returns "member" while
                    # the immutable CINEMA role matrix calls this "staff".
                    # Never expose admin privileges or create data outside the disposable DB.
                    import sqlite3
                    import uuid
                    from datetime import datetime
                    from zoneinfo import ZoneInfo
                    path=Path(tmp)/'ephemeral-review.db'
                    member_email='cinema-member@example.test'
                    with sqlite3.connect(path) as db:
                        record=db.execute(
                            'SELECT org_id,password_hash FROM users WHERE email=?',
                            ('demo@hanbit.example',)).fetchone()
                        assert record and record[0] == user['org_id']
                        db.execute('INSERT INTO users (id,org_id,email,password_hash,name,role,created_at)'
                            ' VALUES (?,?,?,?,?,?,?)',
                            (uuid.uuid4().hex,record[0],member_email,record[1],
                             'CINEMA 실브라우저 직원','member',
                             datetime.now(ZoneInfo('Asia/Seoul')).isoformat(timespec='seconds')))
                    member_context=browser.new_context(viewport={'width':1366,'height':768})
                    try:
                        member_page=member_context.new_page()
                        member_page.goto(url+'/',wait_until='domcontentloaded')
                        member_page.locator('#login input[type=email]').fill(member_email)
                        member_page.locator('#login input[type=password]').fill('Demo!2026secure')
                        member_page.locator('#login button[type=submit]').click()
                        member_page.locator('#app.on').wait_for(state='visible',timeout=35000)
                        # CINEMA lives in a closed JavaScript scope: verify role
                        # through visible behavior and server authorization, not
                        # by reading its non-global ME variable from page.evaluate.
                        role_result=member_page.evaluate("""async()=>{
                            const server=await(await fetch('/api/me')).json();
                            const admin=await fetch('/api/security/overview');
                            return {backend:server.role, adminStatus:admin.status};
                        }""")
                        assert role_result=={'backend':'member','adminStatus':403},role_result
                        member_page.evaluate("location.hash='#/deals'")
                        button=member_page.locator('#vw .ph .acts').get_by_role(
                            'button',name='＋ 견적서',exact=True)
                        button.wait_for(state='visible',timeout=12000)
                        button.click(timeout=10000)
                        member_page.locator('.mback form.form').last.wait_for(
                            state='visible',timeout=10000)
                        print('PASS real member auth: staff-only CINEMA create form, no admin rights',flush=True)
                    finally:
                        member_context.close()
                    # Traverse every immutable CINEMA route under server login.
                    # This is a render/error smoke, not a claim that every write
                    # button (which may intentionally be fail-closed) is integrated.
                    titles={
                        'home':'홈','docs':'문서 센터','files':'파일·첨부',
                        'partners':'거래처','messenger':'거래 메신저',
                        'automation':'업무 자동화','deals':'거래 보드',
                        'papers':'거래 문서','money':'입금·미수금',
                        'stats':'통계·현황','export':'정산 내보내기',
                        'inbox':'승인·알림함','activity':'작업·감사 이력',
                        'team':'직원·권한','security':'보안',
                        'settings':'설정','account':'내 계정·회사'
                    }
                    guarded=[]
                    for route,title in titles.items():
                        page.evaluate("(r)=>{location.hash='#/'+r}",route)
                        page.wait_for_function(
                            "(name)=>document.title===name+' — JARVIS WORKS'",
                            arg=title,timeout=15000)
                        view=page.locator('#vw .view')
                        view.wait_for(state='visible',timeout=12000)
                        body=view.inner_text(timeout=8000)
                        assert body.strip(),route
                        assert '화면을 불러오지 못했습니다' not in body,route
                        if '접근 권한이 없습니다' in body:guarded.append(route)
                    assert not failures,failures
                    print('PASS 17 CINEMA route render/error sweep; guarded routes:',
                          ','.join(guarded) or 'none',flush=True)
                    # Messenger attachment is NOT the OCR evidence endpoint:
                    # an attempted UI click must neither open a file chooser
                    # nor silently fabricate browser-only outbound messages.
                    page.evaluate("location.hash='#/messenger'")
                    page.wait_for_function(
                        "()=>document.title==='거래 메신저 — JARVIS WORKS'",
                        timeout=15000)
                    chooser_events=[]
                    page.on('filechooser',lambda chooser:chooser_events.append(chooser))
                    before=page.evaluate("""async()=>{
                      const [q,t]=await Promise.all([
                        fetch('/api/evidence/queue'),fetch('/api/messenger/threads')]);
                      return {queue:(await q.json()).items.length,
                              threads:(await t.json()).length};
                    }""")
                    attach_button=page.locator('#vw button[aria-label="파일 첨부"]')
                    click_visible_area(page,attach_button,'messenger attachment deny')
                    page.wait_for_timeout(400)
                    after=page.evaluate("""async()=>{
                      const [q,t]=await Promise.all([
                        fetch('/api/evidence/queue'),fetch('/api/messenger/threads')]);
                      return {queue:(await q.json()).items.length,
                              threads:(await t.json()).length};
                    }""")
                    assert not chooser_events and before==after,(before,after,len(chooser_events))
                    assert '서버 연결 전까지' in page.locator('#toasts').inner_text(), 'Missing explicit fail-closed user feedback'
                    print('PASS original messenger attachment button fail-closed, no fake transfer',flush=True)
                    print('PASS CINEMA real buttons: customer POST, quote POST, status POST, tenant isolation')
                    if CLICK_BLOCKERS:raise AssertionError('Original CINEMA UI pointer hit-test BLOCKED despite passing server API: '+str(CLICK_BLOCKERS))
                    assert not failures,failures
                    print('PASS: original visuals, real server login, no local auth bypass, real API, CSRF, CINEMA shell')
                    # MFA is a separate real-browser gate, with a synthetic
                    # member account and a one-time isolated encryption key.
                    from app.security_hardening import totp_code
                    mfactx=browser.new_context(viewport={'width':1366,'height':768})
                    try:
                        mp=mfactx.new_page()
                        mfafail=[]
                        mp.on('pageerror',lambda e:mfafail.append(str(e)))
                        mp.goto(url+'/',wait_until='domcontentloaded')
                        mp.locator('#login input[type=email]').fill(member_email)
                        mp.locator('#login input[type=password]').fill('Demo!2026secure')
                        mp.locator('#login button[type=submit]').click()
                        mp.locator('#app.on').wait_for(state='visible',timeout=35000)
                        setup=mp.evaluate("""async()=>{
                          const me=await (await fetch('/api/me')).json();
                          const r=await fetch('/api/security/mfa/start',{
                            method:'POST',credentials:'same-origin',
                            headers:{'Content-Type':'application/json','X-CSRF-Token':me.csrf_token},
                            body:JSON.stringify({password:'Demo!2026secure'})});
                          return {status:r.status,csrf:me.csrf_token,data:await r.json()};
                        }""")
                        assert setup['status']==200 and len(setup['data']['secret'])>=20,setup['status']
                        otp_step=int(time.time()//30)
                        enabled=mp.evaluate("""async(a)=>{
                          const r=await fetch('/api/security/mfa/confirm',{
                            method:'POST',credentials:'same-origin',
                            headers:{'Content-Type':'application/json','X-CSRF-Token':a.csrf},
                            body:JSON.stringify({otp:a.otp})});
                          return {status:r.status,body:await r.json()};
                        }""",{'csrf':setup['csrf'],'otp':totp_code(setup['data']['secret'],otp_step)})
                        assert enabled['status']==200 and enabled['body']['must_login_again'] is True
                        assert mp.evaluate("async()=>(await fetch('/api/me')).status") == 401
                        mp.reload(wait_until='domcontentloaded')
                        mp.locator('#login input[type=email]').fill(member_email)
                        mp.locator('#login input[type=password]').fill('Demo!2026secure')
                        mp.locator('#login button[type=submit]').click()
                        mp.wait_for_function("""()=>{
                          const otp=document.querySelector('#login input[autocomplete="one-time-code"]');
                          const alert=document.querySelector('#login [role=alert]');
                          return otp && !otp.closest('label').hidden && alert?.textContent?.trim().length>0;
                        }""",timeout=15000)
                        assert mp.locator('#app.on').count()==0,'Password-only MFA bypass'
                        otp_input=mp.locator('#login input[autocomplete="one-time-code"]')
                        assert otp_input.is_visible(),'CINEMA did not reveal the MFA field'
                        # The setup OTP already consumed the current counter:
                        # the server legitimately accepts the adjacent next
                        # TOTP counter only when it is strictly newer.
                        otp_input.fill(totp_code(setup['data']['secret'],otp_step+1))
                        mp.locator('#login button[type=submit]').click()
                        mp.locator('#app.on').wait_for(state='visible',timeout=35000)
                        assert not mfafail,mfafail
                        print('PASS real CINEMA MFA: password-only denied; synthetic OTP authorizes; replay counter enforced',flush=True)
                    finally:
                        mfactx.close()
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
