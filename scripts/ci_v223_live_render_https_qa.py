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
            response_headers=dict(res.headers.items())
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
    csp=h.get('Content-Security-Policy','')
    check('strict_inline_script_hash_csp',"'sha256-" in csp and "object-src 'none'" in csp and "frame-ancestors 'none'" in csp)
    check('no_store_root',h.get('Cache-Control')=='no-store')
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
    status,data,h=clients[0][0].request('/api/logout','POST',csrf='bad')
    check('logout_wrong_csrf_403',status==403)
    status,data,h=clients[0][0].request('/api/me')
    check('csrf_failure_keeps_session',status==200)
    for i,(u,me,quotes) in enumerate(clients):
        status,result,h=u.request('/api/logout','POST',csrf=me['csrf_token'])
        check('logout_server_'+str(i),status==200)
        status,result,h=u.request('/api/me')
        check('logout_revoked_'+str(i),status==401)
    check('hsts_https',h.get('Strict-Transport-Security','').startswith('max-age='))
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
