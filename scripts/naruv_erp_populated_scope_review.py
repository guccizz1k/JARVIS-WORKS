"""New populated-scope review only, using exact detached ERP source.
No live DB, real employee, production approval or external identity provider."""
import hashlib
import importlib.util
import os
from pathlib import Path
import secrets
import subprocess
import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb
from psycopg.conninfo import make_conninfo

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('prior_acl',HERE/'naruv_erp_acl_source_review.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
need=base.need
PROFILE='835b0d6b6210d0e6151d701848f9276f6f5a7be2'
EMPLOYEE='5d1cdff091b5f4769e6511ae41769ce48bb2d621'
def pinned(name,sha):
    p=base.ROOT/'db'/'review'/name
    need(subprocess.check_output(['git','hash-object',str(p)],text=True).strip()==sha,'POPULATED_DDL_PIN')
    return p.read_text()

def populate(fixture):
    from scripts.naruv_native_write_review_ci import NativeWrite
    from app import pg_quote_api_v92 as quote
    from fastapi.testclient import TestClient
    from app.naruv_hr_profile_envelope import seal_profile,open_profile,ProfileBlocked
    with psycopg.connect(fixture.root_dsn) as c:
        c.execute("INSERT INTO jw_dev.naruv_review_sources VALUES('ci-b','source-b','customer','rev-b',ARRAY[]::text[],true)")
        c.execute("SET LOCAL naruv.profile_ci='DISPOSABLE_ONLY'")
        c.execute(pinned('naruv_hr_profile_ci.sql',PROFILE))
    os.environ['JW_PG_QUOTE_V92']='ISOLATED_DEV_QUOTE_V92'
    need(quote.register_v92_quote_api(NativeWrite.app),'POPULATED_QUOTE_REGISTER')
    t=NativeWrite('test_csv_full_flow_and_exact_retry')
    key=secrets.token_bytes(32)
    profiles={}
    for who,org,src,price in [('A','ci-a','source-a',105),('B','ci-b','source-b',205)]:
        csrf=fixture.CSRF[who]
        def import_rows(sid,raw,entity):
            d=t.stage(sid,raw,src,entity,'csv',who)
            t.check(t.approve(d,sid,who),200)
            t.check(t.commit(d,sid,'commit-'+sid,who),200)
        import_rows('acl-more-items',b'sku,item_name,unit\n002,Bolt,EA\n003,Assembly,EA\n','item')
        import_rows('acl-customer',b'customer_id,customer_name,business_number\n0001,Imported Company,012-34-56789\n','customer')
        with psycopg.connect(fixture.TRADE_DSN) as c:
            c.execute('SET LOCAL ROLE jw_app_dev')
            c.execute("SELECT set_config('jw.session_hash',%s,true)",(base.session_hash(fixture,who),))
            def rpc(name,*args):
                q=sql.SQL('SELECT {}({})').format(sql.Identifier(*name.split('.')),sql.SQL(',').join(sql.Placeholder()*len(args)))
                return c.execute(q,args).fetchone()[0]
            def cmd(schema,key,rid,action,payload):
                return rpc(schema+'.command',key,rid,action,Jsonb(payload),True,csrf)
            for item in ('001','002'):
                rpc('naruv_valuation.receive',item,'stock-'+item,Jsonb(dict(source_id=src,warehouse_id='W1',quantity=20,unit_cost=price)),True,csrf)
            p=dict(kind='purchase',counterparty_id='ci-customer-'+who.lower(),source_id=src,item_id='001',warehouse_id='W1',quantity=3,unit_price=price,vat_mode='taxable')
            first=cmd('naruv_trade','acl-purchase','acl-open','open',p)
            need(cmd('naruv_trade','acl-purchase','acl-open','open',p)==first,'POPULATED_TRADE_RETRY')
            cmd('naruv_trade','acl-purchase','acl-fulfill','fulfill',dict(quantity=2))
            cmd('naruv_finance','acl-bill','acl-bill-request','bill',dict(doc_id='acl-purchase',fulfillment_id='acl-fulfill'))
            cmd('naruv_production','acl-bom','acl-define','define',dict(source_id=src,product_id='003',lines=[dict(material_id='001',per_unit=1),dict(material_id='002',per_unit=1)]))
            cmd('naruv_production','acl-job','acl-job-open','open',dict(bom_id='acl-bom',warehouse_id='W1',quantity=1))
            cmd('naruv_production','acl-job','acl-complete','complete',dict(quantity=1))
            rpc('naruv_draft.setup_worker','acl-worker',None,'acl-staff',None,None,None,True,csrf)
            rpc('naruv_draft.archive_worker','acl-worker','acl-archive',True,csrf)
            rpc('naruv_draft.admit_attendance','worker-1','2026-10','acl-attendance','2026-10-01',480,0,True,csrf)
            rev=rpc('naruv_draft.review_period','worker-1','2026-10',None,None,False,csrf)
            rpc('naruv_draft.amend_period','worker-1','2026-10','acl-amend',rev['review_sha256'],'attendance',Jsonb(dict(date='2026-10-01',regular=470,additional=0)),True,csrf)
            rpc('naruv_draft.record_statement_review','worker-1','2026-11','acl-statement','a'*64,'b'*64,'c'*64,True,csrf)
            raw=b'%PDF-synthetic-ACL'
            obs=[dict(field='document_kind',value='invoice',page=1),dict(field='subtotal',value=100,page=1),dict(field='vat',value=10,page=1),dict(field='gross_amount',value=110,page=1)]
            rpc('naruv_draft.admit_document','acl-doc','acl-admit','pdf',raw,Jsonb(obs),True,csrf)
            obs[1]['value']=200;obs[2]['value']=20;obs[3]['value']=220
            rpc('naruv_draft.revise_document','acl-doc','acl-revise','acl-admit',hashlib.sha256(raw).hexdigest(),Jsonb(obs),True,csrf)
            profile=dict(display_name='Synthetic '+who,work_email=who.lower()+'@example.invalid',employment_start='2026-01-01')
            context=dict(tenant=org,worker='worker-1',revision='acl-profile',key_id='ci-profile-key',key=key)
            envelope=seal_profile(**context,profile=profile)
            rpc('naruv_draft.profile_envelope','worker-1','acl-profile',Jsonb(envelope),None,csrf)
            saved=rpc('naruv_draft.profile_envelope','worker-1',None,None,None,csrf)
            need(saved['envelope']==envelope and open_profile(**context,envelope=saved['envelope'])==profile,'POPULATED_PROFILE_DECRYPT')
            profiles[who]=(context,envelope)
        # Existing quote API, then the exact reviewed conversion RPC.
        with TestClient(NativeWrite.app,base_url='https://testserver') as client:
            client.cookies.set('__Host-jw_session',fixture.TOKENS[who])
            response=client.post('/api/pg-stage/v92/quotes',json=dict(request_id='acl-quote',customer_id='ci-customer-'+who.lower(),title='ACL quote',vat_mode='taxable',items=[dict(name=name,quantity=1,unit_price=price) for name in ('Widget','Bolt')]),headers={'origin':'https://testserver','x-csrf-token':csrf})
            need(response.status_code==201,'POPULATED_QUOTE_HTTP_'+str(response.status_code))
            qid=response.json()['quote_id']
        with psycopg.connect(fixture.TRADE_DSN) as c:
            c.execute('SET LOCAL ROLE jw_app_dev')
            c.execute("SELECT set_config('jw.session_hash',%s,true)",(base.session_hash(fixture,who),))
            p=c.execute('SELECT naruv_quote_bundle.preview(%s,%s)',(qid,csrf)).fetchone()[0]
            mapping=[dict(quote_line_id=x['quote_line_id'],source_id=src,item_id='001' if x['name']=='Widget' else '002',warehouse_id='W1') for x in p['snapshot']['lines']]
            c.execute('SELECT naruv_quote_bundle.convert(%s,%s,%s,true,%s)',('acl-bundle','acl-convert',Jsonb(dict(quote_id=qid,snapshot_sha256=p['snapshot_sha256'],lines=mapping)),csrf))
    # Actual independent AES-GCM context substitution rejection.
    for who,other in [('A','B'),('B','A')]:
        context,_=profiles[who]
        try:open_profile(**context,envelope=profiles[other][1])
        except ProfileBlocked:pass
        else:raise RuntimeError('POPULATED_PROFILE_CROSS_TENANT_DECRYPT')
    with psycopg.connect(fixture.root_dsn) as c:
        for org in ('ci-a','ci-b'):
            c.execute("INSERT INTO naruv_draft.profile_retention VALUES(%s,'worker-1',now()+interval '30 days',true,%s,NULL)",(org,'e'*64))
        need(c.execute("SELECT count(*) FROM naruv_draft.profile_envelopes WHERE envelope::text LIKE '%Synthetic%' OR envelope::text LIKE '%example.invalid%'").fetchone()==(0,),'POPULATED_PROFILE_PLAINTEXT')
    base.EXPECTED.update({('naruv_draft','profile_envelopes'):'profile_scope',('naruv_draft','profile_revision_history'):'profile_history_scope',('naruv_draft','profile_retention'):'profile_retention_scope'})
    with psycopg.connect(fixture.root_dsn) as c:
        n=base.audit(c)
        missing=[]
        for s,t in base.EXPECTED:
            rows=dict(c.execute(sql.SQL("SELECT org_id,count(*) FROM {} GROUP BY org_id").format(sql.Identifier(s,t))).fetchall())
            if not rows.get('ci-a') or not rows.get('ci-b'):missing.append(s+'.'+t)
        need(not missing,'POPULATED_MISSING:'+','.join(missing))
    print('POPULATED_ERP_CATALOG_PASS tables='+str(len(base.EXPECTED))+' definer_functions='+str(n),flush=True)
    populated,both=base.tenant_reads(fixture)
    need(populated==both==42,'POPULATED_ALL_TABLES_REQUIRED')
    print('POPULATED_ERP_TENANT_PASS tables=42 read_checks=252 profile_cross_decrypt_denials=2',flush=True)

def employee(fixture):
    from app import naruv_employee_session_store_review as store
    from app.naruv_employee_access_review import AccessDenied
    passwords={x:secrets.token_urlsafe(32) for x in ('a','b')}
    with psycopg.connect(fixture.root_dsn) as c:
        c.execute("SET LOCAL naruv.employee_store_ci='DISPOSABLE_ONLY'")
        c.execute(pinned('naruv_employee_session_store_ci.sql',EMPLOYEE))
        for tenant,principal,worker in [('ci-a','e1','w1'),('ci-a','e2','w2'),('ci-b','e1','w1')]:
            c.execute('INSERT INTO naruv_employee_ci.identities VALUES(%s,%s,%s,1,true)',(tenant,principal,worker))
            c.execute("INSERT INTO naruv_employee_ci.entitlements VALUES(%s,%s,'r1',%s,%s,true)",(tenant,worker,'a'*64,'b'*64))
        for x,pw in passwords.items():
            c.execute(sql.SQL('ALTER ROLE {} LOGIN PASSWORD {}').format(sql.Identifier('naruv_employee_ci_'+x),sql.Literal(pw)))
        rows=c.execute("""SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class
              WHERE relnamespace='naruv_employee_ci'::regnamespace AND relkind='r'""").fetchall()
        need(set(rows)=={(t,True,True) for t in ('identities','entitlements','sessions')},'EMPLOYEE_RLS_SCOPE')
    def connect(x):
        return psycopg.connect(make_conninfo(fixture.root_dsn,user='naruv_employee_ci_'+x,password=passwords[x]),connect_timeout=4)
    def args(x,token):
        return dict(trusted_tenant='ci-'+x,trusted_principal='e1',receipt='r1',review_sha256='a'*64,render_sha256='b'*64,token=token)
    tokens={}
    for x in passwords:
        with connect(x) as c:
            c.execute("SET LOCAL naruv.employee_store_ci='DISPOSABLE_ONLY'")
            role='naruv_employee_ci_'+x
            need(c.execute('SELECT session_user,current_user').fetchone()==(role,role),'EMPLOYEE_DIRECT_LOGIN')
            tokens[x]=store.issue(c,trusted_tenant='ci-'+x,trusted_principal='e1',receipt='r1')
            need(store.access(c,**args(x,tokens[x]))['session_store_verified'] is True,'EMPLOYEE_ISSUE')
    denied=0
    for x,other in [('a','b'),('b','a')]:
        with connect(x) as c:
            c.execute("SET LOCAL naruv.employee_store_ci='DISPOSABLE_ONLY'")
            for t in ('identities','entitlements','sessions'):
                got=c.execute(sql.SQL('SELECT DISTINCT tenant FROM {}').format(sql.Identifier('naruv_employee_ci',t))).fetchall()
                need(got==[('ci-'+x,)],'EMPLOYEE_CROSS_TENANT_READ')
            for opts in (args(other,tokens[other]),args(x,tokens[other]),dict(args(x,tokens[x]),trusted_principal='e2')):
                try:
                    with c.transaction():store.access(c,**opts)
                except AccessDenied:denied+=1
                else:raise RuntimeError('EMPLOYEE_CROSS_SCOPE_ACCESS')
            for q in ('UPDATE naruv_employee_ci.sessions SET revoked=true','DELETE FROM naruv_employee_ci.sessions','TRUNCATE naruv_employee_ci.sessions',
                      'SET ROLE naruv_employee_ci_'+other):
                try:
                    with c.transaction():c.execute(q)
                except psycopg.errors.InsufficientPrivilege as e:need(e.sqlstate=='42501','EMPLOYEE_DENIAL_CODE');denied+=1
                else:raise RuntimeError('EMPLOYEE_UNAUTHORIZED_MUTATION')
    # Actual committed revocation followed by reactivation must never revive token.
    with psycopg.connect(fixture.root_dsn) as c:
        c.execute("UPDATE naruv_employee_ci.identities SET active=false WHERE tenant='ci-a' AND principal='e1'")
    with psycopg.connect(fixture.root_dsn) as c:
        c.execute("UPDATE naruv_employee_ci.identities SET active=true WHERE tenant='ci-a' AND principal='e1'")
    for x in passwords:
        with connect(x) as c:
            c.execute("SET LOCAL naruv.employee_store_ci='DISPOSABLE_ONLY'")
            if x=='a':
                try:store.access(c,**args(x,tokens[x]))
                except AccessDenied:denied+=1
                else:raise RuntimeError('EMPLOYEE_REACTIVATION')
            else:need(store.access(c,**args(x,tokens[x]))['session_store_verified'] is True,'EMPLOYEE_OTHER_TENANT_REVOKED')
    with psycopg.connect(fixture.root_dsn) as c:
        need(c.execute("SELECT tenant,revoked FROM naruv_employee_ci.sessions ORDER BY tenant").fetchall()==[('ci-a',True),('ci-b',False)],'EMPLOYEE_REVOKE_PERSISTENCE')
        c.execute('DROP SCHEMA naruv_employee_ci CASCADE')
        c.execute('DROP ROLE naruv_employee_ci_a,naruv_employee_ci_b')
    with psycopg.connect(fixture.root_dsn) as c:
        need(c.execute("SELECT to_regnamespace('naruv_employee_ci'),count(*) FROM pg_roles WHERE rolname IN ('naruv_employee_ci_a','naruv_employee_ci_b')").fetchone()==(None,0),'EMPLOYEE_RESIDUAL')
    print('EMPLOYEE_DIRECT_LOGIN_PASS tables=3 tenant_read_checks=6 denied='+str(denied)+' revocation=PASS cleanup=PASS',flush=True)

def main():
    base.preflight()
    fixture,_=base.setup()
    populate(fixture)
    employee(fixture)
    print('POPULATED_ERP_EMPLOYEE_REVIEW_PASS production_authorized=false gate5=BLOCKED',flush=True)
if __name__=='__main__':main()
