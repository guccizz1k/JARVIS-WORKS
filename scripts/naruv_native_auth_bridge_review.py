"""Exact native ERP engine + managed identity proof, disposable PG17 only.

Retains the original native guard, RLS and workflow functions. Inserts a
second identity check into the guard in the throwaway database only.
The two identity stores are intentionally both required, not a migration.
"""
import importlib.util
import hashlib
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
H='naruv_hosted_identity_review.'
MANAGED_PIN='9c449c805d272c73962ebb7deb549192faea6815'
IDENTITY_PIN='bd62a6fd968d28517f58063e33bef8d4fb760f36'
AUTH='naruv_hid_auth'
def pin(path,expected):
    need(subprocess.check_output(['git','hash-object',str(path)],text=True).strip()==expected,'BRIDGE_SOURCE_PIN')
    return path.read_text()

def install(fixture):
    root=HERE.parent/'db/review'
    raw=pin(root/'naruv_supabase_hosted_identity_foundation_rehearsal.sql',IDENTITY_PIN)
    managed=pin(root/'naruv_supabase_hosted_auth_tx_rehearsal.sql',MANAGED_PIN)
    start='CREATE ROLE naruv_hid_owner'
    end='SET LOCAL ROLE naruv_hid_auth;\nDO $t$ BEGIN'
    # Only the previously reviewed identity DDL, in a local bootstrap which
    # has already enforced the exact source and disposable DB boundary.
    need(raw.count(start)==1 and end in raw,'BRIDGE_IDENTITY_BOUNDARY')
    identity=raw[raw.index(start):raw.index(end)]
    identity=identity.replace("'actor-a'","'ci-ua'").replace("'actor-b'","'ci-ub'")
    begin='CREATE FUNCTION naruv_hosted_identity_review.lock_admin('
    finish='GRANT EXECUTE ON FUNCTION naruv_hosted_identity_review.lock_admin(text,text) TO naruv_htx_gateway;'
    need(managed.count(begin)==managed.count(finish)==1,'BRIDGE_LOCK_BOUNDARY')
    lock=managed[managed.index(begin):managed.index(finish)]
    password=secrets.token_urlsafe(32)
    with psycopg.connect(fixture.root_dsn) as c:
        need(c.execute("SELECT to_regnamespace('jw_dev') IS NOT NULL,to_regnamespace('naruv_hosted_identity_review') IS NULL").fetchone()==(True,True),'BRIDGE_FRESH')
        c.execute(identity)
        c.execute("SET LOCAL ROLE naruv_hid_owner; GRANT USAGE ON SCHEMA naruv_hosted_identity_review TO naruv_native_owner; GRANT CREATE ON SCHEMA naruv_hosted_identity_review TO naruv_hid_writer; RESET ROLE")
        c.execute('SET LOCAL ROLE naruv_hid_writer')
        c.execute(lock)
        c.execute('GRANT EXECUTE ON FUNCTION naruv_hosted_identity_review.lock_admin(text,text) TO naruv_native_owner')
        c.execute('RESET ROLE; SET LOCAL ROLE naruv_hid_reader; GRANT EXECUTE ON FUNCTION naruv_hosted_identity_review.stage_identity_v84() TO naruv_native_owner; RESET ROLE; SET LOCAL ROLE naruv_hid_owner; REVOKE CREATE ON SCHEMA naruv_hosted_identity_review FROM naruv_hid_writer; RESET ROLE')
        c.execute(sql.SQL('ALTER ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(AUTH),sql.Literal(password)))
        # Keep the original body, owner and grants. Original guard is invoker
        # and runs within the existing native SECURITY DEFINER business RPC.
        original=c.execute("SELECT pg_get_functiondef('naruv_native_review.guard(text,text)'::regprocedure)").fetchone()[0]
        marker=' generation:=naruv_auth_fence.lock_actor(a.actor_id);'
        need(original.count(marker)==1,'BRIDGE_NATIVE_GUARD_MARKER')
        extra="""
 IF naruv_hosted_identity_review.lock_admin(a.org_id,p_csrf) IS DISTINCT FROM a.org_id
 OR NOT EXISTS(SELECT 1 FROM naruv_hosted_identity_review.stage_identity_v84() z
   WHERE (z.actor_id,z.org_id,z.actor_role,z.csrf_token) IS NOT DISTINCT FROM
         (a.actor_id,a.org_id,a.actor_role,a.csrf_token))
 THEN RAISE EXCEPTION 'HOSTED_IDENTITY_MISMATCH' USING ERRCODE='42501'; END IF;
"""
        revised=original.replace(marker,extra+marker)
        c.execute(revised)
        saved=c.execute("SELECT pg_get_functiondef('naruv_native_review.guard(text,text)'::regprocedure)").fetchone()[0]
        need(extra.strip() in saved and saved.replace(extra,'')==original,'BRIDGE_ONLY_INTENDED_GUARD_CHANGE')
    return make_conninfo(fixture.root_dsn,user=AUTH,password=password)

def issue(a,actor,h,csrf):
    need(a.execute('SELECT '+H+'issue(%s,%s,%s,3600)',(actor,h,csrf)).fetchone()==(True,),'BRIDGE_ISSUE')
def change(a,actor,active,role):
    need(a.execute('SELECT '+H+'change_actor(%s,%s,%s)',(actor,active,role)).fetchone()==(True,),'BRIDGE_CHANGE')
def bind(c,h):
    c.execute('SET LOCAL ROLE jw_app_dev')
    c.execute("SELECT set_config('jw.session_hash',%s,true)",(h,))
def rpc(c,name,*args):
    q=sql.SQL('SELECT {}({})').format(sql.Identifier(*name.split('.')),sql.SQL(',').join(sql.Placeholder()*len(args)))
    return c.execute(q,args).fetchone()[0]
def cmd(c,schema,key,rid,action,payload,csrf):
    return rpc(c,schema+'.command',key,rid,action,Jsonb(payload),True,csrf)
def denied(c,name,args,code='42501'):
    try:
        with c.transaction():rpc(c,name,*args)
    except psycopg.Error as e:need(e.sqlstate==code,'BRIDGE_DENIAL_'+str(e.sqlstate)+'_'+code)
    else:raise RuntimeError('BRIDGE_UNEXPECTED_ACCEPT_'+name)
def snapshot(fixture):
    tables=[(s,t) for s,t in base.EXPECTED if s in ('naruv_inventory','naruv_trade','naruv_finance','naruv_accounting','naruv_production','naruv_valuation')]
    with psycopg.connect(fixture.root_dsn) as c:
        out=[]
        for s,t in sorted(tables):
            r=c.execute(sql.SQL("SELECT count(*),encode(sha256(convert_to(coalesce(string_agg(to_jsonb(x)::text,E'\\n' ORDER BY to_jsonb(x)::text),''),'UTF8')),'hex') FROM {} x").format(sql.Identifier(s,t))).fetchone()
            out.append((s,t,*r))
        return tuple(out)

def main():
    base.preflight()
    fixture,_=base.setup()
    auth_dsn=install(fixture)
    from scripts.naruv_native_write_review_ci import NativeWrite
    native=NativeWrite('test_csv_full_flow_and_exact_retry')
    with psycopg.connect(auth_dsn,autocommit=True) as a:
        need(a.execute('SELECT session_user,current_user').fetchone()==(AUTH,AUTH),'BRIDGE_AUTH_LOGIN')
        for who,actor in [('A','ci-ua'),('B','ci-ub')]:
            issue(a,actor,base.session_hash(fixture,who),fixture.CSRF[who])
        for who,org,source,price in [('A','ci-a','source-a',105),('B','ci-b','source-b',205)]:
            csrf=fixture.CSRF[who]
            # Real source import via existing HTTP handler, using newly gated native guard.
            d=native.stage('bridge-items',b'sku,item_name,unit\n002,Bolt,EA\n003,Assembly,EA\n',source,'item','csv',who)
            native.check(native.approve(d,'bridge-items',who),200)
            native.check(native.commit(d,'bridge-items','bridge-items-commit',who),200)
            with psycopg.connect(fixture.TRADE_DSN) as c:
                bind(c,base.session_hash(fixture,who))
                for item in ('001','002'):
                    rpc(c,'naruv_valuation.receive',item,'bridge-stock-'+item,Jsonb(dict(source_id=source,warehouse_id='W1',quantity=20,unit_cost=price)),True,csrf)
                p=dict(kind='purchase',counterparty_id='ci-customer-'+who.lower(),source_id=source,item_id='001',warehouse_id='W1',quantity=3,unit_price=price,vat_mode='taxable')
                first=cmd(c,'naruv_trade','bridge-purchase','bridge-open','open',p,csrf)
                need(cmd(c,'naruv_trade','bridge-purchase','bridge-open','open',p,csrf)==first,'BRIDGE_TRADE_REPLAY')
                cmd(c,'naruv_trade','bridge-purchase','bridge-fulfill','fulfill',dict(quantity=2),csrf)
                cmd(c,'naruv_finance','bridge-bill','bridge-bill-request','bill',dict(doc_id='bridge-purchase',fulfillment_id='bridge-fulfill'),csrf)
                cmd(c,'naruv_production','bridge-bom','bridge-define','define',dict(source_id=source,product_id='003',lines=[dict(material_id='001',per_unit=1),dict(material_id='002',per_unit=1)]),csrf)
                cmd(c,'naruv_production','bridge-job','bridge-job-open','open',dict(bom_id='bridge-bom',warehouse_id='W1',quantity=1),csrf)
                cmd(c,'naruv_production','bridge-job','bridge-complete','complete',dict(quantity=1),csrf)
                for item,qty in [('001',21),('002',19),('003',1)]:
                    stock=rpc(c,'naruv_valuation.inspect',source,item,'W1',csrf)
                    need(int(stock['quantity'])==qty,'BRIDGE_STOCK_'+item)
                journal=rpc(c,'naruv_accounting.inspect_bill','bridge-bill',csrf)
                need(journal['debit']==journal['credit'] and journal['journal_count']==1,'BRIDGE_BALANCED_JOURNAL')
                proof=rpc(c,'naruv_valuation.audit_ledger',csrf)
                need(proof['status']=='RECONCILED' and proof['inventory_krw']==proof['journal_inventory_krw'] and proof['wip_krw']=='0','BRIDGE_LEDGER')
        print('NATIVE_AUTH_BRIDGE_WORKFLOW_PASS tenants=2 stock_checks=6 journal_checks=2 reconciliations=2',flush=True)
        before=snapshot(fixture)
        # Same native endpoint under a wrong/missing hosted identity, incorrect
        # CSRF, revoked session, or role downgrade must not modify the ERP.
        targets=[
            ('naruv_valuation.receive',('001','denied-stock',Jsonb(dict(source_id='source-a',warehouse_id='W1',quantity=1,unit_cost=105)),True)),
            ('naruv_trade.command',('bridge-purchase','denied-fulfill','fulfill',Jsonb(dict(quantity=1)),True)),
            ('naruv_finance.command',('bridge-bill','denied-pay','pay',Jsonb(dict(amount=1)),True)),
            ('naruv_accounting.inspect_bill',('bridge-bill',)),
            ('naruv_production.command',('bridge-job','denied-complete','complete',Jsonb(dict(quantity=1)),True)),
            ('naruv_valuation.audit_ledger',()),
        ]
        def deny_all(who,h,csrf):
            with psycopg.connect(fixture.TRADE_DSN) as c:
                bind(c,h)
                for name,args in targets:denied(c,name,(*args,csrf))
        deny_all('A',base.session_hash(fixture,'A'),'wrong-csrf')
        deny_all('C',base.session_hash(fixture,'C'),fixture.CSRF['C'])
        # A valid original session mapped to a different hosted actor in same tenant.
        mismatch=hashlib.sha256(b'synthetic-bridge-mismatch').hexdigest()
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("INSERT INTO jw_dev.sessions(id,token_hash,user_id,expires_at,csrf_token,created_at) VALUES('bridge-mismatch',%s,'ci-ua',(now()+interval '1 hour')::text,%s,now()::text)",(mismatch,fixture.CSRF['A']))
        change(a,'member-a',True,'admin')
        issue(a,'member-a',mismatch,fixture.CSRF['A'])
        deny_all('A',mismatch,fixture.CSRF['A'])
        need(a.execute('SELECT '+H+'revoke(%s)',(base.session_hash(fixture,'A'),)).fetchone()==(True,),'BRIDGE_REVOKE')
        deny_all('A',base.session_hash(fixture,'A'),fixture.CSRF['A'])
        change(a,'ci-ub',True,'member')
        deny_all('B',base.session_hash(fixture,'B'),fixture.CSRF['B'])
        change(a,'ci-ub',True,'admin')
        deny_all('B',base.session_hash(fixture,'B'),fixture.CSRF['B'])
        need(snapshot(fixture)==before,'BRIDGE_DENIAL_MUTATION')
        print('NATIVE_AUTH_BRIDGE_DENIAL_PASS cases=36 unchanged_erp_tables='+str(len(before)),flush=True)
    print('NATIVE_AUTH_BRIDGE_REVIEW_PASS production_authorized=false gate5=BLOCKED',flush=True)
if __name__=='__main__':main()
