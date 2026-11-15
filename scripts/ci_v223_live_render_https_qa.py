"""Real HTTPS requests to isolated Render free staging; synthetic seeded companies ONLY.
Validates actual TLS, cookie/CSRF, org A/B isolation, and logout without DB admin.
Does NOT attest PG17, 17 complete business routes, backed up data, Safari or launch readiness.
"""
from __future__ import annotations
import http.cookiejar
import json
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import build_opener, Request, HTTPCookieProcessor, HTTPSHandler, HTTPRedirectHandler
from urllib.error import HTTPError, URLError

HOST='jw-v223-qa-isolated-20261115.onrender.com'
BASE='https://'+HOST
SHA='cdcdc857e173f572fb1815f657cbc5d9b117bbd4'
MAX_RESPONSE=1_800_000

class Redirects(HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        from urllib.parse import urlsplit
        p=urlsplit(newurl)
        if p.scheme!='https' or p.netloc!=HOST:
            raise RuntimeError('BLOCKED_REDIRECT_OUTSIDE_ISOLATED_STAGING')
        return super().redirect_request(req,fp,code,msg,headers,newurl)

class Client:
    def __init__(self):
        self.cookies=http.cookiejar.CookieJar()
        self.opener=build_opener(HTTPCookieProcessor(self.cookies),HTTPSHandler(context=ssl.create_default_context()),Redirects())
    def request(self,path,method='GET',data=None,csrf=None):
        assert path.startswith('/') and not path.startswith('//') and '?' not in path
        headers={'Accept':'application/json' if path.startswith('/api/') else 'text/html',
                 'User-Agent':'JARVIS-WORKS-REVIEW-ISOLATED-E2E/1.0'}
        if data is not None:headers['Content-Type']='application/json'
        if csrf:headers['X-CSRF-Token']=csrf
        req=Request(BASE+path,data=json.dumps(data).encode('utf8') if data is not None else None,
                    method=method,headers=headers)
        try:
            res=self.opener.open(req,timeout=25)
        except HTTPError as exc:
            res=exc
        with res:
            raw=res.read(MAX_RESPONSE+1)
            if len(raw)>MAX_RESPONSE:raise RuntimeError('OVERSIZED_RESPONSE')
            status=res.status
            response_headers={k.lower():v for k,v in res.headers.items()}
        if path.startswith('/api/'):
            try: obj=json.loads(raw)
            except ValueError: raise RuntimeError('NON_JSON_API_RESPONSE')
        else:
            obj=raw.decode('utf8')
        return status,obj,response_headers

def require(ok,code):
    if not ok:raise RuntimeError('FAIL_'+code)

def main():
    qa={'scope':'ISOLATED_SYNTHETIC_SQLITE_HTTPS_ONLY',
        'target_url':BASE,'expected_source_sha_via_render_service_api':SHA,
        'source_sha_cryptographically_attested_by_http':False,
        'verified_real_https':False,'checks':{},'records':[]}
    def check(key,condition):
        require(bool(condition),key);qa['checks'][key]='PASS'
    probe=Client();ready=False
    for attempt in range(12):
        try:
            status,data,hdr=probe.request('/api/health')
            if status==200 and data.get('status')=='ok':ready=True;break
        except (TimeoutError,URLError):
            pass
        time.sleep(10)
    check('https_health_200',ready)
    qa['verified_real_https']=True  # Python default system TLS verification was enabled.
    status,body,h=probe.request('/')
    check('preview_html_200',status==200 and 'JWOwnerServerUI.start()' in body and '/static/approved_ui_server_review_v223.js' in body and '#d4ff3a' in body)
    csp=h.get('content-security-policy','')
    check('strict_inline_script_hash_csp',"'sha256-" in csp and "object-src 'none'" in csp and "frame-ancestors 'none'" in csp)
    check('no_store_root',h.get('cache-control')=='no-store')
    status,data,h=probe.request('/api/me')
    check('unauthenticated_me_401',status==401)
    clients=[]
    for index,email in enumerate(('demo@hanbit.example','demo@bada.example')):
        u=Client()
        status,result,headers=u.request('/api/login','POST',{'email':email,'password':'Demo!2026secure'})
        check('synthetic_login_'+str(index),status==200 and isinstance(result.get('user'),dict))
        cookie=list(u.cookies)
        check('synthetic_cookie_secure_httponly_'+str(index),
              len(cookie)==1 and cookie[0].secure and cookie[0].has_nonstandard_attr('HttpOnly'))
        status,me,h=u.request('/api/me')
        check('real_session_me_'+str(index),status==200 and me.get('org_id')==result['user'].get('org_id') and len(me.get('csrf_token',''))>=30)
        status,customers,h=u.request('/api/customers')
        check('real_customers_list_'+str(index),status==200 and isinstance(customers,list) and customers and all(x.get('org_id')==me['org_id'] for x in customers))
        status,quotes,h=u.request('/api/quotes')
        check('real_quotes_list_'+str(index),status==200 and isinstance(quotes,list) and quotes and all(x.get('org_id')==me['org_id'] for x in quotes))
        clients.append((u,me,quotes))
    org_a,org_b=clients[0][1]['org_id'],clients[1][1]['org_id']
    check('separate_tenant_ids',org_a!=org_b)
    qid=clients[0][2][0]['id']
    status,other,h=clients[1][0].request('/api/quotes/'+qid)
    check('cross_tenant_quote_refused',status in (403,404))
    # Perform actual business writes on the isolated, disposable synthetic-only
    # Render SQLite staging. This never touches real PG17, customer DB or prod.
    import uuid
    from datetime import date,timedelta
    a_client,a_me,_=clients[0]
    b_client,b_me,_=clients[1]
    synthetic_name='QA-ONLY-'+uuid.uuid4().hex[:20]
    customer_payload={'name':synthetic_name,'business_number':'','contact_name':'',
                      'email':'','phone':''}
    status,_,h=a_client.request('/api/customers','POST',data=customer_payload)
    check('synthetic_customer_missing_csrf_refused',status==403)
    status,customer,h=a_client.request('/api/customers','POST',data=customer_payload,csrf=a_me['csrf_token'])
    check('synthetic_customer_created_201',status==201 and customer.get('org_id')==org_a and customer.get('name')==synthetic_name)
    new_customer=customer['id']
    status,_,h=a_client.request('/api/customers','POST',data=customer_payload,csrf=a_me['csrf_token'])
    check('synthetic_duplicate_customer_409',status==409)
    status,all_a,h=a_client.request('/api/customers')
    check('synthetic_customer_read_after_write',status==200 and sum(x.get('id')==new_customer for x in all_a)==1)
    status,all_b,h=b_client.request('/api/customers')
    check('synthetic_customer_hidden_other_company',status==200 and all(x.get('id')!=new_customer for x in all_b))
    q_payload={'customer_id':new_customer,'title':'SYNTHETIC_QA_'+uuid.uuid4().hex[:12],
               'vat_mode':'taxable','items':[{'name':'SYNTHETIC_PART','quantity':3,'unit_price':1250}]}
    status,_,h=b_client.request('/api/quotes','POST',data=q_payload,csrf=b_me['csrf_token'])
    check('cross_tenant_customer_cannot_create_quote',status in (403,404))
    status,_,h=a_client.request('/api/quotes','POST',data=q_payload)
    check('synthetic_quote_missing_csrf_refused',status==403)
    status,created_q,h=a_client.request('/api/quotes','POST',data=q_payload,csrf=a_me['csrf_token'])
    check('synthetic_quote_created_201',status==201 and created_q.get('org_id')==org_a and created_q.get('money',{}).get('subtotal')==3750)
    qid=created_q['id']
    status,read_q,h=a_client.request('/api/quotes/'+qid)
    check('synthetic_quote_amount_read_after_write',status==200 and read_q.get('money',{}).get('total')==4125)
    status,_,h=b_client.request('/api/quotes/'+qid)
    check('synthetic_quote_cross_tenant_read_denied',status in (403,404))
    status,_,h=a_client.request('/api/quotes/'+qid+'/status','POST',data={'status':'accepted'},csrf=a_me['csrf_token'])
    check('synthetic_quote_invalid_direct_approval_refused',status==409)
    status,sent,h=a_client.request('/api/quotes/'+qid+'/status','POST',data={'status':'sent'},csrf=a_me['csrf_token'])
    check('synthetic_quote_submitted',status==200 and sent.get('status')=='sent')
    status,accepted,h=a_client.request('/api/quotes/'+qid+'/status','POST',data={'status':'accepted'},csrf=a_me['csrf_token'])
    check('synthetic_quote_accepted_legacy',status==200 and accepted.get('status')=='accepted')
    order_data={'quote_id':qid,'due_date':(date.today()+timedelta(days=7)).isoformat()}
    status,order,h=a_client.request('/api/orders/from-quote','POST',data=order_data,csrf=a_me['csrf_token'])
    check('synthetic_order_from_quote_created',status==201 and order.get('org_id')==org_a and order.get('quote_id')==qid)
    status,_,h=b_client.request('/api/orders/'+order['id'])
    check('synthetic_order_cross_tenant_denied',status in (403,404))
    status,_,h=a_client.request('/api/orders/from-quote','POST',data=order_data,csrf=a_me['csrf_token'])
    check('synthetic_duplicate_order_refused',status==409)
    # Legacy server accepted same-user quote status as designed; this is NOT
    # a claim that CINEMA two-person approvals were exercised.

    status,data,h=clients[0][0].request('/api/logout','POST',csrf='bad')
    check('logout_wrong_csrf_403',status==403)
    status,data,h=clients[0][0].request('/api/me')
    check('csrf_failure_keeps_session',status==200)
    for i,(u,me,quotes) in enumerate(clients):
        status,result,h=u.request('/api/logout','POST',csrf=me['csrf_token'])
        check('logout_server_'+str(i),status==200)
        status,result,h=u.request('/api/me')
        check('logout_revoked_'+str(i),status==401)
    check('hsts_https',h.get('strict-transport-security','').startswith('max-age='))
    qa['timestamp_utc']=datetime.now(timezone.utc).isoformat()
    qa['counts']={'passed':len(qa['checks']),'failed':0,'skipped':0}
    qa['not_verified']=['PG17 production data','real backup restore','full 17 business API paths',
                        'iOS Safari hardware','operational load and rollback','P4 release']
    Path('jw-v223-live-render-http-e2e.json').write_text(json.dumps(qa,ensure_ascii=False,indent=2))
    print('PASS_REAL_RENDER_HTTPS_SYNTHETIC_TWO_ORG_AUTH_CSRF_TENANT '+str(len(qa['checks']))+' CHECKS')
    print('EXACT_SHA_FROM_RENDER_CONTROL_PLANE_NOT_API; NOT_RELEASE_PASS')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
