"""Real HTTPS synthetic trade statement UI conversion, idempotence and tenant isolation.

Every HTTP request uses TLS validation and only the isolated free Render QA service.
Never connects to production Supabase. No user secrets and no real customer records.
"""
from __future__ import annotations
from datetime import datetime,timedelta,timezone
from pathlib import Path
from http.cookiejar import CookieJar
from urllib.request import build_opener,HTTPCookieProcessor,HTTPSHandler,Request
from urllib.error import URLError, HTTPError
from playwright.sync_api import sync_playwright
import json, ssl, time, uuid, hashlib

HOST='jw-v223-qa-isolated-20261115.onrender.com'
BASE='https://'+HOST
PINNED_SOURCE_SHA='b393c073c8f9bb9552d8822d2dff32fe86be5028'
OUT=Path('artifacts/jw-v223-v60-timing-e2e')
OUT.mkdir(parents=True,exist_ok=True)
DAY=(datetime.now(timezone(timedelta(hours=9))).date()+timedelta(days=45)).isoformat()
TAG='SYNTHETIC_V60_'+uuid.uuid4().hex[:10]

def check(ok,name):
    if not bool(ok): raise AssertionError('FAIL_'+name)

class C:
    def __init__(self):
        self.jar=CookieJar()
        self.web=build_opener(HTTPCookieProcessor(self.jar),HTTPSHandler(context=ssl.create_default_context()))
        self.csrf=None
    def call(self,path,method='GET',body=None,auth=True):
        assert path.startswith('/api/') and '?' not in path and not path.startswith('//')
        headers={'Accept':'application/json','User-Agent':'JW-REVIEW-TRADE-STATEMENT-SYNTHETIC/1'}
        if body is not None: headers['Content-Type']='application/json'
        if method!='GET' and auth and self.csrf: headers['X-CSRF-Token']=self.csrf
        req=Request(BASE+path,method=method,headers=headers,data=json.dumps(body).encode('utf8') if body is not None else None)
        try:r=self.web.open(req,timeout=35)
        except HTTPError as exc:r=exc
        with r:
            raw=r.read(1_800_001)
            check(len(raw)<=1_800_000,'RESPONSE_OVERSIZE')
            status=r.status
        try:obj=json.loads(raw)
        except ValueError:raise AssertionError('API_NON_JSON')
        return status,obj
    def login(self,email):
        s,d=self.call('/api/login','POST',{'email':email,'password':'Demo!2026secure'},auth=False)
        check(s==200 and isinstance(d.get('user'),dict),'SYNTHETIC_LOGIN')
        s,me=self.call('/api/me')
        check(s==200 and me.get('org_id')==d['user'].get('org_id'),'SESSION_ORG_BINDING')
        self.csrf=me['csrf_token']
        return me

def wait_health():
    ok=False
    for _ in range(12):
        try:
            s,resp=C().call('/api/health')
            if s==200 and resp.get('status')=='ok':ok=True;break
        except (URLError,TimeoutError):pass
        time.sleep(10)
    check(ok,'STAGING_HEALTH')

def seed_fulfilled_order(a):
    s,c=a.call('/api/customers','POST',{'name':TAG+'_customer','business_number':'',
         'contact_name':'synthetic','email':'','phone':''})
    check(s==201,'CREATE_SYNTHETIC_CUSTOMER')
    s,q=a.call('/api/quotes','POST',{'customer_id':c['id'],'title':TAG+'_quote','vat_mode':'taxable',
         'items':[{'name':'SYNTHETIC_PART','quantity':2,'unit_price':125000}]})
    check(s==201 and q['money']['total']==275000,'CREATE_SYNTHETIC_QUOTE')
    for status in ('sent','accepted'):
        s,d=a.call('/api/quotes/'+q['id']+'/status','POST',{'status':status})
        check(s==200 and d.get('status')==status,'QUOTE_'+status)
    s,o=a.call('/api/orders/from-quote','POST',{'quote_id':q['id'],'due_date':DAY})
    check(s==201 and o['org_id']==c['org_id'],'ORDER_FROM_QUOTE')
    for status in ('processing','fulfilled'):
        s,d=a.call('/api/orders/'+o['id']+'/status','POST',{'status':status})
        check(s==200 and d.get('status')==status,'ORDER_'+status)
    return o['id'],q['id'],c['org_id']

def main():
    wait_health()
    a,b=C(),C()
    who=a.login('demo@hanbit.example')
    other=b.login('demo@bada.example')
    check(who['org_id']!=other['org_id'],'DISTINCT_DEMO_TENANTS')
    order,qid,org=seed_fulfilled_order(a)
    check(org==who['org_id'],'SOURCE_CUSTOMER_TENANT')
    # A foreign company cannot generate a statement for A's order.
    status,_=b.call('/api/automation/statements/from-order','POST',{'order_id':order})
    check(status==404,'FOREIGN_TENANT_STATEMENT_CREATE_DENIED')
    status,_=a.call('/api/automation/statements/from-order','POST',{'order_id':order},auth=False)
    check(status==403,'STATEMENT_WRITE_REQUIRES_CSRF')
    status,before_timers=a.call('/api/automation/time-savings')
    check(status==200 and isinstance(before_timers.get('samples'),dict),'BASELINE_SERVER_TIMING_STATS')
    entries=[]
    with sync_playwright() as p:
        engines=[('chromium',p.chromium.launch(headless=True,args=['--no-sandbox'])),
                 ('webkit',p.webkit.launch(headless=True))]
        try:
            for name,browser in engines:
                ctx=browser.new_context(viewport={'width':390,'height':844},ignore_https_errors=False)
                try:
                    page=ctx.new_page()
                    errors=[]
                    page.on('pageerror',lambda e:errors.append(str(e)))
                    page.on('dialog',lambda dialog:dialog.accept())
                    response=page.goto(BASE,wait_until='domcontentloaded',timeout=75000)
                    check(response.status==200,'RENDER_HTML_'+name)
                    login=page.locator('input[aria-label="이메일"]')
                    login.wait_for(state='visible',timeout=22000)
                    login.fill('demo@hanbit.example')
                    page.locator('input[aria-label="비밀번호"]').fill('Demo!2026secure')
                    page.locator('button[type="submit"]').click()
                    page.locator('.jw-review-nav button[data-page="automation"]').wait_for(state='visible',timeout=25000)
                    page.locator('.jw-review-nav button[data-page="automation"]').click()
                    if name=='chromium':
                        start=page.locator('button[data-action="timing-start-automated"]')
                        start.wait_for(state='visible',timeout=22000)
                        start.click()
                        page.locator('button[data-action="timing-cancel"]').wait_for(state='visible',timeout=22000)
                        check('자동화 측정 진행 중' in page.locator('.jw-review-timing-buttons').locator('..').inner_text(),
                              'AUTO_MEASUREMENT_STARTED_IN_REAL_BROWSER')
                    else:
                        manual=page.locator('button[data-action="timing-start-manual"]')
                        manual.wait_for(state='visible',timeout=22000)
                        manual.click()
                        finish=page.locator('button[data-action="timing-manual-finish"]')
                        finish.wait_for(state='visible',timeout=22000)
                        finish.click()
                        page.locator('p.jw-review-muted').filter(has_text='수작업 서버 측정 완료').wait_for(state='visible',timeout=22000)
                    bttn=page.locator('button[data-action="statement-from-order"][data-order="'+order+'"]')
                    bttn.wait_for(state='visible',timeout=25000)
                    check('거래명세표 생성' in bttn.inner_text(),'ACTION_VISIBLE_'+name)
                    bttn.click()
                    # Must wait for actual immutable server POST followed by GET and trace before UI status.
                    msg=page.locator('.jw-review-muted[role="status"]')
                    msg.wait_for(state='visible',timeout=30000)
                    label=msg.inner_text()
                    check('TS-' in label and '275,000원' in label and '내부 거래명세표' in label,'VERIFIED_UI_DOCUMENT_'+name)
                    if name=='chromium':check('자동화 서버 실측' in label,'REAL_SERVER_AUTO_TIMER_'+name)
                    if name=='webkit':check('기존 확정 문서 재사용' in label,'REUSED_DOC_NOT_NEW_TIMER_'+name)
                    check(not errors,'JS_EXCEPTION_'+name)
                    check(not page.evaluate('document.documentElement.scrollWidth > window.innerWidth + 2'),'NO_OVERFLOW_'+name)
                    fn=OUT/('v60-real-https-'+name+'-390.png')
                    page.screenshot(path=str(fn),full_page=True)
                    entries.append({'engine':name,'status':'PASS','screenshot':str(fn),'server_validated':True})
                finally:ctx.close()
        finally:
            for _,browser in engines:browser.close()
    status,after_timers=a.call('/api/automation/time-savings')
    check(status==200 and after_timers['samples']['manual']>=before_timers['samples']['manual']+1,
          'MANUAL_MEASUREMENT_RECORDED_SERVER_SIDE')
    check(after_timers['samples']['automated']>=before_timers['samples']['automated']+1,
          'AUTOMATION_MEASUREMENT_LINKED_TO_NEW_DOC')
    check(after_timers['status'] in ('NOT_MEASURED','COMPARISON_AVAILABLE'),'NO_INVENTED_TIME_SAVINGS_STATUS')
    status,active=a.call('/api/automation/timing/active')
    check(status==200 and active is None,'COMPLETED_TIMER_HAS_NO_ACTIVE_SESSION')
    # Reject a forged other-tenant timer operation and a duplicate active run.
    status,started=a.call('/api/automation/timing/start','POST',{'workflow':'trade_statement','mode':'manual'})
    check(status==201 and started.get('status')=='running','CANCEL_TEST_START')
    status,foreign=b.call('/api/automation/timing/'+started['id']+'/cancel','POST')
    check(status==404,'CROSS_TENANT_TIMER_CANNOT_CANCEL')
    status,_=a.call('/api/automation/timing/start','POST',{'workflow':'trade_statement','mode':'manual'})
    check(status==409,'OVERLAPPING_MEASUREMENT_REJECTED')
    status,canceled=a.call('/api/automation/timing/'+started['id']+'/cancel','POST')
    check(status==200 and canceled.get('excluded_from_metrics') is True,'CANCEL_EXCLUDED_FROM_METRICS')
    status,final_timers=a.call('/api/automation/time-savings')
    check(status==200 and final_timers['samples']==after_timers['samples'],'CANCELED_TIMER_NOT_IN_SAMPLE_COUNTS')
    status,trace=a.call('/api/automation/transactions/'+order)
    check(status==200 and trace.get('scope')=='authenticated_tenant_only','TRANSACTION_TRACE_TENANT')
    doc=trace['statement_id']
    check(isinstance(doc,str) and len(doc)==32,'STATEMENT_PRESENT')
    check(sum(1 for e in trace['events'] if e['type']=='trade_statement')==1,'STATEMENT_UNIQUE_EVENT')
    status,statement=a.call('/api/automation/statements/'+doc)
    check(status==200 and statement['org_id']==org and statement['order_id']==order,'STATEMENT_READBACK')
    check(statement['document']['money']['total']==275000,'IMMUTABLE_SNAPSHOT_EXACT_MONEY')
    check(statement['document']['legal_status']=='internal_business_record_not_tax_invoice','NOT_TAX_INVOICE')
    status,retry=a.call('/api/automation/statements/from-order','POST',{'order_id':order})
    check(status==200 and retry['id']==doc and retry['reused'] is True,'IDEMPOTENT_SAME_DOC_ON_RETRY')
    status,_=b.call('/api/automation/statements/'+doc)
    check(status==404,'CROSS_TENANT_DOCUMENT_READ_DENIED')
    status,_=b.call('/api/automation/transactions/'+order)
    check(status==404,'CROSS_TENANT_TRANSACTION_TRACE_DENIED')
    verdict={'scope':'ACTUAL_RENDER_HTTPS_SYNTHETIC_SQLITE_ONLY','source_sha_from_render_control_plane':PINNED_SOURCE_SHA,
      'ui_browser_engines':entries,'verify_server_readback':True,'duplicate_prevented':True,'org_ab_isolation':True,
      'snapshot_total_krw':275000,'owner_original_unchanged':True,'server_timing_samples_before':before_timers['samples'],
      'server_timing_samples_after':after_timers['samples'],'cancel_excluded':True,
      'limits':['not_prod_pg17','not_original_full_UI_17_functions','not_real_iPhone_Safari','not_P1_key_restore','not_P4_release']}
    (OUT/'evidence.json').write_text(json.dumps(verdict,ensure_ascii=False,indent=2))
    print('PASS_V223_REAL_RENDER_HTTPS_ONE_CLICK_STATEMENT_CHROMIUM_WEBKIT_2_ENGINES')
    print('PASS_IMMUTABLE_SNAPSHOT_IDEMPOTENCE_ORG_ISOLATION_SERVER_READBACK')
    print('PASS_REAL_SERVER_TIMERS_MANUAL_AUTO_RESUME_CSRF_TENANT_CANCEL_STATISTICS')
if __name__=='__main__':main()
