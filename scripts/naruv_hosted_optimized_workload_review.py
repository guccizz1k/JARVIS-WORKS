"""Disposable hosted ERP workload. No original data copy or original role changes."""
import getpass, hashlib, hmac, base64, json, os, re, secrets, signal, sys, time, warnings
from pathlib import Path
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from decimal import Decimal
import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

ROOT=Path.home()/'.naruv-qa-review'
HOST='aws-0-ap-northeast-2.pooler.supabase.com'
REF='scvqtsyxkqddoorcaiqr'
SCHEMA_PIN='0bc7e5d525faaaefdf1fbe3ef3efb9b9e080e206'
CANDIDATE_PIN='07fc6dd4ae72e27ed005b27143e1087437d6adf9'
ORIGINAL_RECONCILE_MD5='bae4c77687cd2b3106a4efca3ded6850'
CA_PIN='3d693669b23c340c57a3457bdc8b6fefe1806cc5'
POLICY='afdf015a5917727d12817a8b4107d16f'
MARKER='631b6ff1423ad473138e8a2eb75ddf4b'
def need(ok, code):
    if not ok: raise RuntimeError(code)
def blob(data):
    return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
def pinned(path,pin):
    data=path.read_bytes(); need(blob(data)==pin,'SOURCE_PIN'); return data
def verifier(pw):
    salt=secrets.token_bytes(16)
    salted=hashlib.pbkdf2_hmac('sha256',pw.encode('ascii'),salt,4096)
    enc=lambda b:base64.b64encode(b).decode('ascii')
    return 'SCRAM-SHA-256$4096:'+enc(salt)+'$'+enc(hashlib.sha256(hmac.digest(salted,b'Client Key','sha256')).digest())+':'+enc(hmac.digest(salted,b'Server Key','sha256'))
def rpc(c,name,*args):
    return c.execute(sql.SQL('SELECT {}({})').format(sql.Identifier(*name.split('.')),sql.SQL(',').join(sql.Placeholder()*len(args))),args).fetchone()[0]
def cmd(c,schema,k,r,a,p,csrf):
    return rpc(c,schema+'.command',k,r,a,Jsonb(p),True,csrf)
def one(c,q,args=None):
    return (c.execute(q) if args is None else c.execute(q,args)).fetchone()
def setrole(c,r):
    c.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(r)))
def bind(c,r,t):
    setrole(c,r);rpc(c,'pg_catalog.set_config','jw.session_hash',t,True)
def baseline(c):
    need(one(c,"SELECT current_database(),session_user,current_setting('server_version_num')::int") == ('postgres','postgres',170012),'ORIGINAL_SCOPE')
    need(one(c,"SELECT md5(prosrc) FROM pg_proc WHERE oid='naruv_valuation.reconcile_bill(text,text)'::regprocedure")== (ORIGINAL_RECONCILE_MD5,),'ORIGINAL_RECONCILE_DRIFT')
    need(one(c,"SELECT count(*),md5(coalesce(string_agg(to_jsonb(f)::text,',' ORDER BY to_jsonb(f)::text),'')) FROM naruv_qa_probe.fixture f")== (2,MARKER),'MARKER_DRIFT')
    need(one(c,"SELECT md5(string_agg(to_jsonb(p)::text,',' ORDER BY schemaname,tablename,policyname)) FROM pg_policies p WHERE left(schemaname,6)='naruv_' OR schemaname='jw_dev'")== (POLICY,),'POLICY_DRIFT')
def candidate_body(src):
    marker='FUNCTION naruv_valuation.reconcile_bill('
    need(src.count(marker)==1,'RECONCILE_BODY_BOUNDARY')
    start=src.index('AS $$',src.index(marker))+5
    end=src.index('$$;',start)
    return src[start:end]
def optimized_source(src):
    old=candidate_body(src)
    need(hashlib.md5(old.encode()).hexdigest()==ORIGINAL_RECONCILE_MD5,'ORIGINAL_RECONCILE_BODY')
    candidate=pinned(ROOT/'reconcile-candidate.sql',CANDIDATE_PIN).decode()
    new=candidate_body(candidate)
    need(new!=old and src.count(old)==1,'CANDIDATE_BODY_BOUNDARY')
    modified=src.replace(old,new,1)
    need(candidate_body(modified)==new and modified.replace(new,old,1)==src,'CANDIDATE_ONLY_BODY')
    return modified,new
def transform(src,db,prefix):
    roles=re.findall(r'^CREATE ROLE "([a-z_0-9]+)" NOLOGIN ',src,re.M)
    need(len(set(roles))==len(roles)==21,'ROLE_SOURCE_COUNT')
    names={r:prefix+r for r in roles}
    rx=re.compile(r'(?<![A-Za-z0-9_])(?:'+ '|'.join(sorted(roles,key=len,reverse=True))+r')(?![A-Za-z0-9_])')
    need(max(map(len,names.values()))<64,'ROLE_LENGTH')
    out=rx.sub(lambda m:names[m.group()],src)
    need(not rx.search(out),'ROLE_SOURCE_RESIDUAL')
    old="current_database()<>'postgres'"
    need(out.count(old)==2 and out.count('ON DATABASE postgres ')==10,'DB_SOURCE_GUARD')
    out=out.replace(old,"current_database()<>'"+db+"'").replace('ON DATABASE postgres ','ON DATABASE '+db+' ')
    # Pooler upstream pg_stat_ssl differs from client TLS. Replace ONLY installer
    # transport assertion; client verify-full, DB name and OID are checked externally.
    tls=" OR NOT EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)\n"
    need(out.count(tls)==1,'TLS_SOURCE_GUARD')
    out=out.replace(tls,'')
    need(not re.search(r'^(?:ALTER SYSTEM|ALTER ROLE|DROP ROLE|CREATE DATABASE|DROP DATABASE|ALTER DATABASE|CREATE TABLESPACE|CREATE SUBSCRIPTION|COPY )',out,re.M),'INSTALL_GLOBAL_DDL')
    return out,names
def run(pw,src):
    tag=secrets.token_hex(6); db='naruv_qa_workload_'+tag; prefix='nq_'+tag+'_'
    modified,candidate=optimized_source(src)
    install,names=transform(modified,db,prefix)
    role=lambda r:names[r]
    ca=str(ROOT/'ca.crt')
    phase='ADMIN';created=False;oid=None;result=None
    def connect(database,user='postgres',password=pw):
        c=psycopg.connect(host=HOST,port=5432,dbname=database,user=user+'.'+REF,password=password,sslmode='verify-full',sslrootcert=ca,gssencmode='disable',connect_timeout=8,autocommit=True,application_name='naruv_qa_disposable_review')
        try:
            need(one(c,"SELECT current_database(),session_user,current_setting('server_version_num')::int")== (database,user,170012),'DB_ROUTE_IDENTITY')
            if database==db: need(one(c,"SELECT oid FROM pg_database WHERE datname=current_database()")== (oid,),'DB_ROUTE_OID')
            c.execute("SET statement_timeout='35s'");c.execute("SET lock_timeout='10s'")
            c.execute("SET idle_in_transaction_session_timeout='40s'")
            return c
        except BaseException:
            c.close();raise
    logins={k:role(r) for k,r in [('auth','naruv_v85_cutover_ci'),('ingest','naruv_ci_ingest'),('trade','jw_ci_trade')]}
    passwords={k:secrets.token_urlsafe(40) for k in logins}
    tenants={k:('qa-'+k,'qa-u'+k,'source-'+k,p,secrets.token_hex(32),secrets.token_hex(32)) for k,p in [('a',105),('b',205)]}
    def userconn(k): return connect(db,logins[k],passwords[k])
    def role_baseline(c):
        # Non-secret role flags and grants only; password values never returned.
        flags=one(c,"SELECT md5(string_agg(to_jsonb(r)::text,',' ORDER BY rolname)) FROM (SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,rolvaliduntil,rolpassword IS NULL AS password_absent FROM pg_authid WHERE rolname=ANY(%s)) r",(list(names.keys()),))[0]
        edges=one(c,"SELECT md5(coalesce(string_agg(to_jsonb(m)::text,',' ORDER BY m.roleid,m.member,m.grantor),'')) FROM pg_auth_members m WHERE roleid IN (SELECT oid FROM pg_roles WHERE rolname=ANY(%s)) OR member IN (SELECT oid FROM pg_roles WHERE rolname=ANY(%s))",(list(names.keys()),list(names.keys())))[0]
        return flags,edges
    with closing(connect('postgres')) as admin:
        baseline(admin)
        need(one(admin,"SELECT pg_try_advisory_lock(hashtextextended('naruv-isolated-qa-disposable-workload-v1',0))")== (True,),'OTHER_REVIEW_RUNNING')
        saved_roles=role_baseline(admin)
        need(one(admin,"SELECT count(*) FROM pg_roles WHERE left(rolname,3)='nq_'")== (0,),'OLD_WORKLOAD_ROLES')
        need(one(admin,"SELECT count(*) FROM pg_database WHERE left(datname,18)='naruv_qa_workload_'")== (0,),'OLD_WORKLOAD_DB')
        need(one(admin,"SELECT count(*) FROM pg_roles WHERE rolname=ANY(%s)",(list(names.values()),))==(0,),'ROLE_COLLISION')
        phase='CREATE_DB'
        try:
            admin.execute(sql.SQL('CREATE DATABASE {} WITH TEMPLATE template0 OWNER postgres ALLOW_CONNECTIONS false CONNECTION LIMIT 8').format(sql.Identifier(db)))
            created=True
            oid=one(admin,"SELECT oid FROM pg_database WHERE datname=%s AND datdba=(SELECT oid FROM pg_roles WHERE rolname='postgres')",(db,))[0]
            print('TEMP_DB_CREATED',db,oid,flush=True)
            admin.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(db)))
            admin.execute(sql.SQL('ALTER DATABASE {} ALLOW_CONNECTIONS true').format(sql.Identifier(db)))
            phase='POOLER_DB_ROUTE'
            with closing(connect(db)) as a:
                print('TEMP_DB_ROUTE_PASS',flush=True)
                phase='INSTALL'
                a.execute("CREATE SCHEMA naruv_qa_probe; CREATE TABLE naruv_qa_probe.fixture(id integer PRIMARY KEY); INSERT INTO naruv_qa_probe.fixture VALUES(1),(2); ALTER TABLE naruv_qa_probe.fixture ENABLE ROW LEVEL SECURITY; ALTER TABLE naruv_qa_probe.fixture FORCE ROW LEVEL SECURITY",prepare=False)
                a.execute(install,prepare=False)
                phase='POST_INSTALL_SESSION'
                # Dump installer uses session-scoped SET row_security=off and
                # check_function_bodies=false. SET LOCAL in its final audit
                # does not restore those session defaults after COMMIT.
                # Restore normal enforcement before any fixture DML.
                a.execute("SET row_security=on")
                a.execute("SET check_function_bodies=on")
                a.execute("SET search_path=pg_catalog,pg_temp")
                need(one(a,"SELECT current_setting('row_security'),current_setting('check_function_bodies')")==('on','on'),'INSTALL_SESSION_SECURITY')
                print('POST_INSTALL_SESSION_SECURITY_PASS',flush=True)
                need(one(a,"SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (left(n.nspname,6)='naruv_' OR n.nspname='jw_dev' OR n.nspname=%s) AND c.relkind IN ('r','p') AND c.relrowsecurity AND c.relforcerowsecurity",(role('naruv_quote_fence'),))==(66,),'INSTALLED_RLS')
                phase='CANDIDATE_READBACK'
                need(one(a,"SELECT prosrc,pg_get_userbyid(proowner),prosecdef,provolatile,proconfig FROM pg_proc WHERE oid='naruv_valuation.reconcile_bill(text,text)'::regprocedure")==(candidate,role('naruv_native_owner'),True,'v',['search_path=pg_catalog']),'CANDIDATE_BODY_OWNER')
                need(one(a,"SELECT has_function_privilege(%s,'naruv_valuation.reconcile_bill(text,text)','EXECUTE'),has_function_privilege(%s,'naruv_valuation.reconcile_bill(text,text)','EXECUTE')",(role('jw_app_dev'),role('naruv_native_stage')))==(True,False),'CANDIDATE_ACL')
                need(one(a,"SELECT count(*) FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid='naruv_valuation.reconcile_bill(text,text)'::regprocedure AND a.grantee=0")== (0,),'CANDIDATE_PUBLIC')
                print('HOSTED_OPTIMIZED_RECONCILE_BODY_ACL_PASS',flush=True)
                print('TEMP_SCHEMA_INSTALL_PASS',flush=True)
                phase='LOGIN_SETUP'
                # The original roles are not granted to any new login.
                # The package created exclusively namespaced NOLOGIN roles.
                # Verify no application-schema access in original DB, even through new roles.
                for n in logins.values():
                    need(one(admin,"SELECT count(*) FROM pg_namespace WHERE (left(nspname,6)='naruv_' OR nspname='jw_dev') AND has_schema_privilege(%s,oid,'USAGE')",(n,))==(0,),'ORIGINAL_SCHEMA_ACCESS')
                    need(one(admin,"SELECT count(*) FROM pg_roles WHERE rolname=ANY(%s) AND pg_has_role(%s,oid,'MEMBER')",(list(names.keys()),n))==(0,),'ORIGINAL_ROLE_MEMBERSHIP')
                with a.transaction():
                    expiry=one(a,"SELECT clock_timestamp()+interval '20 minutes'")[0].isoformat()
                    for k,n in logins.items():
                        a.execute(sql.SQL('ALTER ROLE {} LOGIN CONNECTION LIMIT 4 PASSWORD {} VALID UNTIL {}').format(sql.Identifier(n),sql.Literal(verifier(passwords[k])),sql.Literal(expiry)))
                        a.execute(sql.SQL('GRANT CONNECT ON DATABASE {} TO {}').format(sql.Identifier(db),sql.Identifier(n)))
                phase='SEED'
                with a.transaction():
                    for org,actor,source,price,token,csrf in tenants.values():
                        phase='SEED_ORGANIZATION'
                        a.execute("INSERT INTO jw_dev.organizations VALUES(%s,%s,clock_timestamp()::text)",(org,org))
                        phase='SEED_USER'
                        a.execute("INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES(%s,%s,%s,'synthetic-unused',%s,'admin',clock_timestamp()::text)",(actor,org,actor+'@invalid.test',actor))
                        phase='SEED_CUSTOMER'
                        a.execute("INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES(%s,%s,'Synthetic supplier',clock_timestamp()::text)",('vendor-'+org,org))
                        phase='SEED_SOURCE'
                        a.execute("INSERT INTO jw_dev.naruv_review_sources(org_id,source_id,entity,revision,existing_ids) VALUES(%s,%s,'item','fixture',ARRAY[]::text[])",(org,source))
                        # Dedicated, transaction-local fixture policy on NEW DB only.
                    phase='SEED_IDENTITY'
                    setrole(a,role('naruv_hid_owner'))
                    a.execute(sql.SQL("CREATE POLICY qa_seed_org ON naruv_hosted_identity_review.organizations FOR INSERT TO {} WITH CHECK (id IN ('qa-a','qa-b'))").format(sql.Identifier(role('naruv_hid_owner'))))
                    a.execute(sql.SQL("CREATE POLICY qa_seed_user ON naruv_hosted_identity_review.users FOR INSERT TO {} WITH CHECK ((id,org_id) IN (('qa-ua','qa-a'),('qa-ub','qa-b')))").format(sql.Identifier(role('naruv_hid_owner'))))
                    for org,actor,source,price,token,csrf in tenants.values():
                        a.execute("INSERT INTO naruv_hosted_identity_review.organizations VALUES(%s,%s)",(org,org))
                        a.execute("INSERT INTO naruv_hosted_identity_review.users VALUES(%s,%s,'admin',true,0)",(actor,org))
                    a.execute('DROP POLICY qa_seed_org ON naruv_hosted_identity_review.organizations')
                    a.execute('DROP POLICY qa_seed_user ON naruv_hosted_identity_review.users')
                    a.execute('RESET ROLE')
                phase='AUTH_RPC'
                with closing(userconn('auth')) as auth:
                    for org,actor,source,price,token,csrf in tenants.values():
                        with auth.transaction():
                            setrole(auth,role('jw_auth_stage_v85'))
                            need(bool(rpc(auth,'jw_dev.v85_auth_issue_session',actor,token,csrf,None,None)),'AUTH_ISSUE')
                for org,actor,source,price,token,csrf in tenants.values():
                    with a.transaction():
                        bind(a,role('naruv_native_owner'),token)
                        a.execute("INSERT INTO naruv_inventory.warehouses VALUES(%s,'W1','Warehouse',true)",(org,))
                        a.execute("INSERT INTO naruv_accounting.periods(org_id,period_start) VALUES(%s,date_trunc('month',clock_timestamp() AT TIME ZONE 'Asia/Seoul')::date)",(org,))
                    phase='INGEST_RPC'
                    rows=json.dumps([{'source_item_id':i,'name':n,'unit':'EA'} for i,n in [('001','Bolt'),('002','Nut'),('003','Assembly')]],separators=(',',':'))
                    digest=hashlib.sha256(rows.encode()).hexdigest()
                    snapshot=hashlib.sha256(json.dumps({'entity':'item','existing_source_ids':[],'organization_id':org,'revision':'fixture','source_id':source,'version':1},separators=(',',':')).encode()).hexdigest()
                    with closing(userconn('ingest')) as c,c.transaction():
                        bind(c,role('naruv_native_stage'),token)
                        need(one(c,"SELECT * FROM naruv_native_review.read_source(%s,'item',%s)",(source,csrf))==('fixture',[]),'SOURCE_READ')
                        need(rpc(c,'naruv_native_review.store_stage','load-items',source,'item','csv',digest,len(rows.encode()),digest,digest,digest,snapshot,'fixture',[],rows,csrf)=='STAGED','STORE_STAGE')
                    phase='APPROVE_COMMIT_RPC'
                    with closing(userconn('trade')) as c,c.transaction():
                        bind(c,role('jw_app_dev'),token)
                        need(rpc(c,'naruv_native_review.approve','load-items',digest,digest,snapshot,True,csrf)=='APPROVED','APPROVE')
                        need(rpc(c,'naruv_native_review.commit_stage','load-items',digest,digest,snapshot,'load-commit',csrf)['row_count']==3,'IMPORT_COMMIT')
                        for item in ('001','002'):
                            rpc(c,'naruv_valuation.receive',item,'opening-'+item,Jsonb(dict(source_id=source,warehouse_id='W1',quantity=100,unit_cost=price)),True,csrf)
                        cmd(c,'naruv_production','load-bom','load-bom-define','define',dict(source_id=source,product_id='003',lines=[dict(material_id='001',per_unit=1),dict(material_id='002',per_unit=1)]),csrf)
                print('INDEPENDENT_AUTH_INGEST_TRADE_SEED_PASS',flush=True)
            phase='WORKLOAD'
            barrier=Barrier(4)
            def worker(i):
                org,actor,source,price,token,csrf=tenants['ab'[i%2]]
                times=[]
                with closing(userconn('trade')) as c:
                    barrier.wait(timeout=20)
                    for j in range(10):
                        key='load-'+str(i)+'-'+str(j); start=time.perf_counter()
                        with c.transaction():
                            bind(c,role('jw_app_dev'),token)
                            payload=dict(kind='purchase',counterparty_id='vendor-'+org,source_id=source,item_id='001',warehouse_id='W1',quantity=2,unit_price=price,vat_mode='taxable')
                            first=cmd(c,'naruv_trade',key+'-purchase',key+'-open','open',payload,csrf)
                            need(cmd(c,'naruv_trade',key+'-purchase',key+'-open','open',payload,csrf)==first,'REPLAY')
                            cmd(c,'naruv_trade',key+'-purchase',key+'-fulfill','fulfill',dict(quantity=2),csrf)
                            cmd(c,'naruv_finance',key+'-bill',key+'-bill-request','bill',dict(doc_id=key+'-purchase',fulfillment_id=key+'-fulfill'),csrf)
                            cmd(c,'naruv_production',key+'-job',key+'-job-open','open',dict(bom_id='load-bom',warehouse_id='W1',quantity=1),csrf)
                            cmd(c,'naruv_production',key+'-job',key+'-complete','complete',dict(quantity=1),csrf)
                            journal=rpc(c,'naruv_accounting.inspect_bill',key+'-bill',csrf)
                            need(journal['debit']==journal['credit'] and journal['journal_count']==1,'BALANCED_JOURNAL')
                        times.append((time.perf_counter()-start)*1000)
                return times
            started=time.perf_counter()
            with ThreadPoolExecutor(max_workers=4) as pool:
                times=sorted(x for arr in pool.map(worker,range(4)) for x in arr)
            elapsed=time.perf_counter()-started
            need(len(times)==40,'COMMIT_COUNT')
            phase='LEDGER_READBACK'
            for org,actor,source,price,token,csrf in tenants.values():
                with closing(userconn('trade')) as c,c.transaction():
                    bind(c,role('jw_app_dev'),token)
                    for item,qty in [('001',120),('002',80),('003',20)]:
                        r=rpc(c,'naruv_valuation.inspect',source,item,'W1',csrf)
                        need(int(r['quantity'])==qty and Decimal(r['value_krw'])==qty*price*(2 if item=='003' else 1),'FINAL_STOCK_VALUE')
                    r=rpc(c,'naruv_valuation.audit_ledger',csrf)
                    need(r['status']=='RECONCILED' and Decimal(r['inventory_krw'])==240*price and Decimal(r['journal_inventory_krw'])==240*price and Decimal(r['wip_krw'])==0,'FINAL_LEDGER')
                with closing(connect(db)) as a:
                    for table in ('naruv_trade.documents','naruv_finance.bills','naruv_production.orders'):
                        need(one(a,sql.SQL('SELECT count(*) FROM {} WHERE org_id=%s').format(sql.Identifier(*table.split('.'))),(org,))==(20,),'PERSISTED_COUNT')
            result=dict(workers=4,tenants=2,batches=40,rpc=280,replays=40,journals=40,stocks=6,ledgers=2,elapsed_s=round(elapsed,3),p95_ms=round(times[37],3))
        except BaseException as e:
            print('HOSTED_WORKLOAD_BLOCKED',phase,type(e).__name__,getattr(e,'sqlstate',None),str(e) if type(e) is RuntimeError else safe_reason(e),flush=True)
        finally:
            if created:
                phase='CLEANUP'
                try:
                    baseline(admin)
                    need(one(admin,"SELECT oid FROM pg_database WHERE datname=%s",(db,))==(oid,),'CLEANUP_DB_OID')
                    for n in logins.values():
                        if one(admin,"SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=%s)",(n,))[0]:
                            admin.execute(sql.SQL('ALTER ROLE {} NOLOGIN PASSWORD NULL').format(sql.Identifier(n)))
                    admin.execute(sql.SQL('ALTER DATABASE {} ALLOW_CONNECTIONS false').format(sql.Identifier(db)))
                    admin.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(db)))
                    for n in names.values():
                        admin.execute(sql.SQL('DROP ROLE IF EXISTS {}').format(sql.Identifier(n)))
                    need(one(admin,"SELECT count(*) FROM pg_database WHERE datname=%s",(db,))==(0,),'RESIDUAL_DB')
                    need(one(admin,"SELECT count(*) FROM pg_roles WHERE rolname=ANY(%s)",(list(names.values()),))==(0,),'RESIDUAL_ROLES')
                    baseline(admin)
                    need(role_baseline(admin)==saved_roles,'ORIGINAL_ROLE_DRIFT')
                    print('ORIGINAL_QA_DATA_POLICY_ROLES_PASS',flush=True)
                    print('TEMP_DB_AND_ROLES_CLEANUP_PASS',flush=True)
                except BaseException as e:
                    print('CLEANUP_BLOCKED',db,oid,type(e).__name__,getattr(e,'sqlstate',None),flush=True)
                    result=None
    if result is None:return 1
    print('HOSTED_OPTIMIZED_ERP_WORKLOAD_PASS',json.dumps(result),flush=True)
    return 0
def safe_reason(e):
    msg=str(e).lower()
    for needle,code in [('query would be affected by row-level security policy','SESSION_RLS_OFF'),('new row violates row-level security policy','RLS_WRITE_DENIED'),('permission denied for','OBJECT_PRIVILEGE_DENIED'),('placeholder','PARAMETER_ERROR'),('econnrefused','BACKEND_REFUSED'),('password authentication failed','PASSWORD_ERROR'),('tenant or user not found','ROUTE_OR_USER_ERROR'),('certificate','TLS_ERROR'),('circuit breaker','PROTECTION_ACTIVE'),('timeout','TIMEOUT')]:
        if needle in msg:return code
    return 'UNCLASSIFIED'
def selftest():
    class Cursor:
        def fetchone(self): return (1,)
    class Fake:
        def execute(self,*a):
            self.args=a
            return Cursor()
    f=Fake()
    need(one(f,"SELECT 'x%'")== (1,) and len(f.args)==1,'SELFTEST_NO_BIND')
    need(one(f,"SELECT %s",(1,))==(1,) and len(f.args)==2,'SELFTEST_BIND')
    src=pinned(ROOT/'hosted-schema.sql',SCHEMA_PIN).decode()
    changed,new=optimized_source(src)
    out,names=transform(changed,'naruv_qa_workload_0123456789ab','nq_0123456789ab_')
    need(candidate_body(out)==new,'SELFTEST_CANDIDATE_TRANSFORM')
    need(len(names)==21 and out.count('ON DATABASE naruv_qa_workload_0123456789ab ')==10,'SELFTEST_TRANSFORM')
    need("current_database()<>'naruv_qa_workload_0123456789ab'" in out,'SELFTEST_DB_GUARD')
    pinned(ROOT/'ca.crt',CA_PIN)
    print('OFFLINE_OPTIMIZED_PREFLIGHT_SELFTEST_PASS',flush=True)
def main():
    if sys.argv[1:]==['--self-test']:
        selftest()
        return 0
    need(not sys.argv[1:],'UNEXPECTED_ARGUMENT')
    pinned(ROOT/'ca.crt',CA_PIN)
    src=pinned(ROOT/'hosted-schema.sql',SCHEMA_PIN).decode()
    for k in list(os.environ):
        if k.startswith('PG'):os.environ.pop(k,None)
    warnings.simplefilter('error',getpass.GetPassWarning)
    need(sys.stdin.isatty(),'TTY_REQUIRED')
    return run(getpass.getpass('QA DB Password: '),src)
if __name__=='__main__':
    def stop(*_):raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM,stop)
    try:sys.exit(main())
    except Exception as e:
        print('PREFLIGHT_BLOCKED',type(e).__name__,getattr(e,'sqlstate',None),str(e) if type(e) is RuntimeError else safe_reason(e))
        sys.exit(1)
