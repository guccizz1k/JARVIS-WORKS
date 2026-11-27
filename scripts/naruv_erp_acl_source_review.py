"""Source-pinned, disposable ERP authorization review. Not a production baseline."""
import hashlib
import os
from pathlib import Path
import subprocess
import psycopg
from psycopg import sql

SOURCE='aa8894305dda413127e2994064f456a966d5e3c2'
ROOT=Path(os.environ.get('NARUV_ERP_SOURCE_ROOT','/nonexistent'))
OWNER='naruv_native_owner'
STAGE='naruv_native_stage'
FENCE='naruv_quote_fence'
APP='jw_app_dev'
# Independently enumerated from the exact reviewed DDL, not the target catalog.
INVENTORY={
 'naruv_native_review':('native_owner_scope',('stages','approvals','records','receipts')),
 'naruv_customer_bridge':('crosswalk_owner_scope',('crosswalk',)),
 'naruv_inventory':('inventory_scope',('items','warehouses','balances','movements')),
 'naruv_trade':('trade_scope',('documents','events')),
 'naruv_finance':('finance_scope',('bills','events')),
 'naruv_accounting':('accounting_scope',('periods','journals','lines')),
 'naruv_bundle':('bundle_scope',('headers','lines','events')),
 'naruv_quote_bundle':('conversion_scope',('conversions',)),
 'naruv_production':('production_scope',('boms','components','orders','events')),
 'naruv_valuation':('valuation_scope',('balances','entries','cost_journals')),
 'naruv_draft':('draft_scope',('documents','staff','pay_periods','attendance')),
}
EXTRA={'document_admissions':'document_admission_scope','document_revisions':'revision_scope',
       'attendance_receipts':'attendance_receipt_scope','period_confirmations':'confirmation_scope',
       'setup_receipts':'setup_scope','staff_archivals':'archival_scope',
       'period_amendments':'amendment_scope','statement_review_receipts':'statement_receipt_scope'}
EXPECTED={(s,t):p for s,(p,ts) in INVENTORY.items() for t in ts}
EXPECTED.update({('naruv_draft',t):p for t,p in EXTRA.items()})
SCHEMAS=sorted(INVENTORY)
DDL=(
 ('customer_bridge','d3e05a25c9a8bd360484bb81289b922c1216f56c'),
 ('inventory','d59c9956b26c6e653cf5838b16d5bf92eb65cf03'),
 ('trade','aa6ead9243b5d31e4b6febfe2fd33a922b2bd6f4'),
 ('finance','34842fd847cbed4905676a8527db862617ecb39a'),
 ('accounting','952a2bd8f17e53ac7f432eae094a5e597f78ffeb'),
 ('bundle','711af9d0ee93f9697b80b3b879da63a6cb9e47e3'),
 ('quote_bundle','e6a919ea877195480aafacedf9f377c8f3d83bc0'),
 ('production','b379c5dd3eb3a511517de9c2f12d194fe38a7013'),
 ('valuation','0351c73151be51612d563afd7c4e8e8af7bbdf36'),
 ('draft','2d6f0e606f22d42566fb9cc5722c21223b35ebc5'),
 ('hr','7c2117c40416e3417cde85d6854b10dc0713f24c'),
)
def need(ok,code):
    if not ok:raise RuntimeError(code)

def preflight():
    need(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='guccizz1k/JARVIS-WORKS'
        and os.environ.get('NARUV_ERP_ACL_CI')=='SOURCE_PINNED_DISPOSABLE_ONLY','ERP_ACL_CI_ONLY')
    need(os.environ.get('JW_PG_CI_ROOT_DSN')=='postgresql://postgres:ci-only-ephemeral-test-password@127.0.0.1:5432/postgres','ERP_ACL_DSN')
    need(subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()==SOURCE,'ERP_ACL_SOURCE')
    for n,sha in [('native_write_review','65f5a873c03b7cbf50d0bc4eb5049c60a8f1bedb'),*DDL]:
        p=ROOT/'db'/'review'/('naruv_'+n+'_ci.sql')
        need(subprocess.check_output(['git','hash-object',str(p)],text=True).strip()==sha,'ERP_ACL_DDL_PIN_'+n)
    need(len(EXPECTED)==39,'ERP_ACL_EXPECTED_SCOPE')

def setup():
    from scripts.naruv_native_write_review_ci import NativeWrite,fixture
    from scripts.naruv_draft_ci import seed,seed_confirmation_proofs
    NativeWrite.setUpClass()
    for n,_ in DDL:
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute('SELECT set_config(%s,%s,true)',('naruv.'+n+'_ci','DISPOSABLE_ONLY'))
            c.execute((ROOT/'db'/'review'/('naruv_'+n+'_ci.sql')).read_text())
            if n=='draft':seed(c)
            if n=='hr':seed_confirmation_proofs(c)
    # Populate genuine native import path for two companies, same object ID.
    test=NativeWrite('test_csv_full_flow_and_exact_retry')
    for who,source in [('A','source-a'),('B','source-b')]:
        d=test.stage('acl-probe',source=source,who=who)
        test.check(test.approve(d,'acl-probe',who),200)
        test.check(test.commit(d,'acl-probe','acl-request',who),200)
    return fixture,NativeWrite.ingest_dsn

def audit(c):
    rows=c.execute("""SELECT n.nspname::text,t.relname::text,pg_get_userbyid(t.relowner),t.relrowsecurity,t.relforcerowsecurity
      FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
      WHERE n.nspname=ANY(%s) AND t.relkind IN ('r','p','v','m','f','S')""",(SCHEMAS,)).fetchall()
    need(set(rows)=={(s,t,OWNER,True,True) for s,t in EXPECTED},'ERP_ACL_TABLE_SCOPE_OWNER_FORCE_RLS')
    # Render an independently declared policy through PG's own deparser.
    c.execute('CREATE TEMP TABLE naruv_acl_policy_reference(org_id text) ON COMMIT DROP')
    c.execute("""CREATE POLICY ref ON pg_temp.naruv_acl_policy_reference TO naruv_native_owner
      USING (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))
      WITH CHECK (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))""")
    reference=c.execute("""SELECT pg_get_expr(polqual,polrelid),pg_get_expr(polwithcheck,polrelid)
      FROM pg_policy WHERE polrelid='pg_temp.naruv_acl_policy_reference'::regclass""").fetchone()
    c.execute('DROP TABLE pg_temp.naruv_acl_policy_reference')
    policies=c.execute("""SELECT schemaname::text,tablename::text,policyname::text,permissive,roles::text[],cmd,qual,with_check
      FROM pg_policies WHERE schemaname=ANY(%s)""",(SCHEMAS,)).fetchall()
    actual={(s,t,p,perm,tuple(rs),cmd,q,w) for s,t,p,perm,rs,cmd,q,w in policies}
    expected={(s,t,p,'PERMISSIVE',(OWNER,),'ALL',*reference) for (s,t),p in EXPECTED.items()}
    expected.add(('naruv_quote_bundle','conversions','conversion_fence_read','PERMISSIVE',(FENCE,),'SELECT','true',None))
    need(actual==expected,'ERP_ACL_POLICY_DRIFT')
    table_grants=c.execute("""SELECT n.nspname,t.relname,x.grantee
      FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
      CROSS JOIN LATERAL unnest(coalesce(t.relacl,acldefault('r',t.relowner))) a(item)
      CROSS JOIN LATERAL aclexplode(ARRAY[a.item]) x
      WHERE n.nspname=ANY(%s) AND t.relkind IN ('r','p') AND x.grantee<>t.relowner""",(SCHEMAS,)).fetchall()
    need(not table_grants,'ERP_ACL_DIRECT_TABLE_GRANT')
    column_grants=c.execute("""SELECT n.nspname::text,t.relname::text,a.attname::text,
       CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
       pg_get_userbyid(x.grantor),x.privilege_type,x.is_grantable
       FROM pg_attribute a JOIN pg_class t ON t.oid=a.attrelid JOIN pg_namespace n ON n.oid=t.relnamespace
       CROSS JOIN LATERAL unnest(a.attacl) u(item) CROSS JOIN LATERAL aclexplode(ARRAY[u.item]) x
       WHERE n.nspname=ANY(%s) AND a.attnum>0 AND NOT a.attisdropped""",(SCHEMAS,)).fetchall()
    need(column_grants==[('naruv_quote_bundle','conversions','quote_id',FENCE,OWNER,'SELECT',False)],'ERP_ACL_COLUMN_GRANT')
    flags=c.execute("""SELECT rolname::text,rolcanlogin,rolinherit,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication
      FROM pg_roles WHERE rolname=ANY(%s)""",([OWNER,STAGE,FENCE,'naruv_auth_fence_owner'],)).fetchall()
    need(set(flags)=={(r,False,False,False,False,False,False,False) for r in (OWNER,STAGE,FENCE,'naruv_auth_fence_owner')},'ERP_ACL_ROLE_FLAGS')
    memberships=c.execute("""SELECT a.rolname::text,b.rolname::text,m.admin_option,m.inherit_option,m.set_option
      FROM pg_auth_members m JOIN pg_roles a ON a.oid=m.member JOIN pg_roles b ON b.oid=m.roleid
      WHERE a.rolname=ANY(%s) OR b.rolname=ANY(%s)""",([OWNER,STAGE,FENCE,'naruv_auth_fence_owner'],)*2).fetchall()
    need(set(memberships)=={('naruv_ci_ingest',STAGE,False,False,True)},'ERP_ACL_ROLE_MEMBERSHIP')
    # All scoped SECURITY DEFINER entrypoints must retain pinned search_path and owner.
    funcs=c.execute("""SELECT n.nspname,p.proname,pg_get_userbyid(p.proowner),p.proconfig
      FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=ANY(%s) AND p.prosecdef""",(SCHEMAS,)).fetchall()
    need(bool(funcs) and all(r[2]==OWNER and r[3]==['search_path=pg_catalog'] for r in funcs),'ERP_ACL_DEFINER_CONFIG')
    public=c.execute("""SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      CROSS JOIN LATERAL unnest(coalesce(p.proacl,acldefault('f',p.proowner))) a(item)
      CROSS JOIN LATERAL aclexplode(ARRAY[a.item]) x
      WHERE n.nspname=ANY(%s) AND x.grantee=0 AND x.privilege_type='EXECUTE'""",(SCHEMAS,)).fetchone()
    need(public==(0,),'ERP_ACL_PUBLIC_ROUTINE')
    return len(funcs)

def session_hash(fixture,who):
    return hashlib.sha256(fixture.TOKENS[who].encode()).hexdigest() if who in fixture.TOKENS else 'f'*64

def tenant_reads(fixture):
    with psycopg.connect(fixture.root_dsn) as c:
        counts={}
        for s,t in EXPECTED:
            q=sql.SQL('SELECT org_id,count(*) FROM {} GROUP BY org_id').format(sql.Identifier(s,t))
            counts[(s,t)]=dict(c.execute(q).fetchall())
        populated=sum(1 for x in counts.values() if x)
        both=sum(1 for x in counts.values() if x.get('ci-a',0)>0 and x.get('ci-b',0)>0)
        need(both>=8,'ERP_ACL_FIXTURE_POPULATION')
        for who,org in [('A','ci-a'),('B','ci-b'),('unknown',None)]:
            with c.transaction(force_rollback=True):
                c.execute('SET LOCAL ROLE naruv_native_owner')
                c.execute("SELECT set_config('jw.session_hash',%s,true)",(session_hash(fixture,who),))
                for (s,t),expected in counts.items():
                    q=sql.SQL('SELECT org_id,count(*) FROM {} GROUP BY org_id').format(sql.Identifier(s,t))
                    actual=dict(c.execute(q).fetchall())
                    want={org:expected[org]} if org in expected else {}
                    need(actual==want,'ERP_ACL_TENANT_READ_'+s+'.'+t)
        # Revoke/expire one synthetic identity in the same rollback-only transaction.
        for change in ("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'",
                       "UPDATE jw_dev.sessions SET expires_at=(now()-interval '1 minute')::text WHERE id='A'",
                       "INSERT INTO jw_dev.staff_disabled VALUES('ci-ua')"):
            with c.transaction(force_rollback=True):
                c.execute(change)
                c.execute('SET LOCAL ROLE naruv_native_owner')
                c.execute("SELECT set_config('jw.session_hash',%s,true)",(session_hash(fixture,'A'),))
                for s,t in EXPECTED:
                    need(c.execute(sql.SQL('SELECT count(*) FROM {}').format(sql.Identifier(s,t))).fetchone()==(0,),'ERP_ACL_REVOKED_READ_'+s+'.'+t)
        # A real owner-policy positive write and a denied cross-tenant write, both synthetic.
        with c.transaction(force_rollback=True):
            c.execute('SET LOCAL ROLE naruv_native_owner')
            c.execute("SELECT set_config('jw.session_hash',%s,true)",(session_hash(fixture,'A'),))
            c.execute("INSERT INTO naruv_inventory.warehouses VALUES('ci-a','ACL-PROBE','probe',true)")
            need(c.execute("SELECT count(*) FROM naruv_inventory.warehouses WHERE warehouse_id='ACL-PROBE'").fetchone()==(1,),'ERP_ACL_POSITIVE_WRITE')
            try:
                with c.transaction():
                    c.execute("INSERT INTO naruv_inventory.warehouses VALUES('ci-b','ACL-PROBE','probe',true)")
            except psycopg.errors.InsufficientPrivilege as exc:need(exc.sqlstate=='42501','ERP_ACL_WRITE_CODE')
            else:raise RuntimeError('ERP_ACL_CROSS_TENANT_WRITE_ACCEPTED')
        need(c.execute("SELECT count(*) FROM naruv_inventory.warehouses WHERE warehouse_id='ACL-PROBE'").fetchone()==(0,),'ERP_ACL_FIXTURE_ROLLBACK')
    return populated,both

def runtime_denials(fixture,ingest_dsn):
    total=0
    for dsn,role in [(fixture.TRADE_DSN,APP),(ingest_dsn,STAGE)]:
        with psycopg.connect(dsn) as c:
            c.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(role)))
            c.execute("SELECT set_config('jw.session_hash',%s,true)",(session_hash(fixture,'A'),))
            for s,t in EXPECTED:
                ident=sql.Identifier(s,t)
                for q in (sql.SQL('SELECT 1 FROM {} LIMIT 1').format(ident),
                          sql.SQL('UPDATE {} SET org_id=org_id WHERE false').format(ident),
                          sql.SQL('DELETE FROM {} WHERE false').format(ident)):
                    try:
                        with c.transaction():c.execute(q)
                    except psycopg.errors.InsufficientPrivilege as exc:need(exc.sqlstate=='42501','ERP_ACL_RUNTIME_SQLSTATE')
                    else:raise RuntimeError('ERP_ACL_RUNTIME_DIRECT_ACCESS_'+s+'.'+t)
                    total+=1
    return total

def mutation_tests(fixture):
    cases=[
      ("GRANT SELECT ON naruv_valuation.entries TO jw_app_dev",'ERP_ACL_DIRECT_TABLE_GRANT'),
      ("GRANT SELECT(org_id) ON naruv_valuation.entries TO jw_app_dev",'ERP_ACL_COLUMN_GRANT'),
      ("ALTER TABLE naruv_valuation.entries NO FORCE ROW LEVEL SECURITY",'ERP_ACL_TABLE_SCOPE_OWNER_FORCE_RLS'),
      ("ALTER POLICY valuation_scope ON naruv_valuation.entries USING(true)",'ERP_ACL_POLICY_DRIFT'),
      ("GRANT naruv_native_owner TO jw_app_dev",'ERP_ACL_ROLE_MEMBERSHIP'),
      ("ALTER ROLE naruv_native_owner BYPASSRLS",'ERP_ACL_ROLE_FLAGS'),
    ]
    with psycopg.connect(fixture.root_dsn) as c:
        for q,code in cases:
            with c.transaction(force_rollback=True):
                c.execute(q)
                try:audit(c)
                except RuntimeError as exc:need(str(exc)==code,'ERP_ACL_MUTATION_WRONG_CODE')
                else:raise RuntimeError('ERP_ACL_MUTATION_NOT_DETECTED')
            audit(c)
    return len(cases)

def main():
    preflight()
    fixture,ingest_dsn=setup()
    with psycopg.connect(fixture.root_dsn) as c:n=audit(c)
    print('ERP_ACL_CATALOG_PASS tables='+str(len(EXPECTED))+' definer_functions='+str(n),flush=True)
    populated,both=tenant_reads(fixture)
    print('ERP_ACL_TENANT_READ_PASS populated='+str(populated)+' both_tenants='+str(both)+' read_checks='+str(len(EXPECTED)*6)+' write_rollback=PASS',flush=True)
    total=runtime_denials(fixture,ingest_dsn)
    print('ERP_ACL_RUNTIME_DENIAL_PASS sqlstate_42501='+str(total),flush=True)
    n=mutation_tests(fixture)
    print('ERP_ACL_MUTATION_ROLLBACK_PASS cases='+str(n),flush=True)
    print('ERP_ACL_SOURCE_REVIEW_PASS production_authorized=false gate5=BLOCKED',flush=True)

if __name__=='__main__':main()
