"""Independent real HTTPS GET-only E2E for approved review operational panels.
Source is the isolated Render synthetic SQLite service. Nothing here changes data.
Missing evidence MUST fail CI; this is not PostgreSQL or production proof.
"""
from __future__ import annotations
import http.cookiejar, json, ssl, time, hashlib
from pathlib import Path
from urllib.request import build_opener, Request, HTTPCookieProcessor, HTTPSHandler
from urllib.error import HTTPError, URLError
from datetime import datetime, timezone

HOST='jw-v223-qa-isolated-20261115.onrender.com'
BASE='https://'+HOST
EXPECTED_DEPLOY_SOURCE='5711acaa9203341dbd190f30efd9ed7009bca4f5'
REQUIRED={
 '/api/dashboard':dict,
 '/api/automation/time-savings':dict,
 '/api/audit':list,
 '/api/messenger/threads':list,
 '/api/evidence/records':list,
 '/api/evidence/queue':dict,
 '/api/security/overview':dict,
}
class Client:
    def __init__(self):
        self.cookies=http.cookiejar.CookieJar()
        self.opener=build_opener(HTTPCookieProcessor(self.cookies),
                                 HTTPSHandler(context=ssl.create_default_context()))
    def request(self,path,method='GET',payload=None):
        assert path.startswith('/api/') and '?' not in path
        data=json.dumps(payload).encode() if payload is not None else None
        headers={'Accept':'application/json'}
        if payload is not None:headers['Content-Type']='application/json'
        req=Request(BASE+path,headers=headers,method=method,data=data)
        try:r=self.opener.open(req,timeout=35)
        except HTTPError as ex:r=ex
        with r:
            raw=r.read(2*1024*1024+1)
            if len(raw)>2*1024*1024:raise AssertionError('TOO_BIG')
            status=r.status
        try:return status,json.loads(raw)
        except json.JSONDecodeError:raise AssertionError('NON_JSON')

def run():
    checks=[]
    def check(name,condition):
        if not condition:raise AssertionError('FAIL_'+name)
        checks.append(name)
    p=Client();connected=False
    for _ in range(12):
        try:
            status,data=p.request('/api/health')
            if status==200 and data.get('status')=='ok':connected=True;break
        except (URLError,TimeoutError):pass
        time.sleep(10)
    check('https_service_healthy',connected)
    status,data=p.request('/api/security/overview')
    check('prelogin_security_denied',status==401)
    ids=[]
    for i,email in enumerate(('demo@hanbit.example','demo@bada.example')):
        c=Client()
        status,result=c.request('/api/login','POST',{'email':email,'password':'Demo!2026secure'})
        check('login_'+str(i),status==200 and isinstance(result.get('user'),dict))
        status,me=c.request('/api/me')
        check('server_identity_'+str(i),status==200 and me.get('org_id')==result['user']['org_id'])
        org=me['org_id'];ids.append(org)
        for route,typ in REQUIRED.items():
            status,body=c.request(route)
            check('api_'+route.strip('/').replace('/','_')+'_'+str(i),
                status==200 and type(body) is typ)
            if status!=200:continue
            if route=='/api/dashboard':
                check('stats_are_real_ints_'+str(i),
                    all(type(body.get(k)) is int and body[k]>=0 for k in
                        ('customers','quotes','orders','invoices','collected','outstanding','quote_total')))
            if route=='/api/automation/time-savings':
                check('no_faked_savings_'+str(i),
                    body.get('status') in ('NOT_MEASURED','COMPARISON_AVAILABLE')
                    and (body.get('status')!='NOT_MEASURED' or body.get('observed_difference_ms') is None))
            if route=='/api/evidence/queue':
                check('evidence_queue_shape_'+str(i),type(body.get('items')) is list)
            if route=='/api/audit':
                check('tenant_audit_isolation_'+str(i),
                    all(row.get('org_id')==org for row in body))
            if route=='/api/security/overview':
                check('admin_scope_and_true_db_limit_'+str(i),
                    type(body.get('users')) is list and
                    type(body.get('sessions')) is list and
                    body.get('db_row_level_security_enabled') is False)
            if route=='/api/messenger/threads':
                check('messenger_is_tenant_scoped_'+str(i),
                    all(row.get('other_org_id')!=org for row in body))
        status,who=c.request('/api/me')
        check('session_survives_read_only_'+str(i),status==200 and who['org_id']==org)
    check('independent_org_sessions',len(ids)==2 and len(set(ids))==2)
    verdict={
        'scope':'ISOLATED_RENDER_HTTPS_SYNTHETIC_READ_ONLY',
        'expected_source_sha_from_render_control_plane':EXPECTED_DEPLOY_SOURCE,
        'deployed_sha_proven_by_http':False,
        'timestamp_utc':datetime.now(timezone.utc).isoformat(),
        'passes':len(checks),'checks':checks,'failed':0,'skipped':0,
        'limitations':['not Real Supabase PostgreSQL','not iOS Safari hardware','not final P2/P3/P4 release PASS']
    }
    Path('operational_https_qa.json').write_text(json.dumps(verdict,indent=2,ensure_ascii=False))
    print('PASS_REAL_HTTPS_OPERATIONAL_PANELS_'+str(len(checks)))
if __name__=='__main__':run()
