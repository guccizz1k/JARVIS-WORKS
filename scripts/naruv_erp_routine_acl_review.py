"""Exact native ERP routine and schema grant baseline, isolated source review.
Not the full jw_dev or hosted production authorization inventory."""
import importlib.util
from pathlib import Path
import subprocess
import psycopg
from psycopg import sql

spec=importlib.util.spec_from_file_location('prior_acl',Path(__file__).with_name('naruv_erp_acl_source_review.py'))
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
need=base.need
OWNER=base.OWNER
APP=base.APP
STAGE=base.STAGE
FENCE=base.FENCE
AUTH='naruv_auth_fence_owner'
SCHEMA_OWNER={s:OWNER for s in base.SCHEMAS}|{'naruv_auth_fence':AUTH,'naruv_quote_fence':FENCE}
# Reviewed explicit DDL grants, NOT a snapshot learned from the target database.
APP_ROUTINES={
'naruv_native_review': ['approve(text,text,text,text,boolean,text)','revoke(text,text,text,text,text)','commit_stage(text,text,text,text,text,text)','inspect(text,text,text)'],
'naruv_inventory':['post_movement(text,text,text,text,text,bigint,text)','read_stock(text,text,text,text)'],
'naruv_trade':['command(text,text,text,jsonb,boolean,text)','inspect(text,text)'],
'naruv_finance':['command(text,text,text,jsonb,boolean,text)','inspect(text,text)'],
'naruv_accounting':['close_period(text,boolean,text)','inspect_bill(text,text)'],
'naruv_bundle':['command(text,text,text,jsonb,boolean,text)','inspect(text,text)'],
'naruv_quote_bundle':['preview(text,text)','convert(text,text,jsonb,boolean,text)'],
'naruv_production':['command(text,text,text,jsonb,boolean,text)','requirements(text,jsonb,text)','inspect(text,text)'],
'naruv_valuation':['receive(text,text,jsonb,boolean,text)','inspect(text,text,text,text)','reconcile_bill(text,text)','return_bill(text,text,boolean,text)','return_quantity(text,text,bigint,boolean,text)','return_adjusted(text,text,bigint,boolean,text,boolean,text)','audit_ledger(text)','overview(text)'],
'naruv_draft':['document_source(text,text)','pay_source(text,text,text)','admit_document(text,text,text,bytea,jsonb,boolean,text)','revise_document(text,text,text,text,jsonb,boolean,text)','admit_attendance(text,text,text,text,int,int,boolean,text)','review_period(text,text,text,text,boolean,text)','setup_worker(text,text,text,text,bigint,int,boolean,text)','inspect_worker(text,text)','archive_worker(text,text,boolean,text)','list_workers(text,int,text)','amend_period(text,text,text,text,text,jsonb,boolean,text)','record_statement_review(text,text,text,text,text,text,boolean,text)','verify_statement_review(text,text,text,text,text,text,text)','profile_envelope(text,text,jsonb,text,text)','purge_profile(text,text,text,text)']}
STAGE_ROUTINES=['naruv_native_review.read_source(text,text,text)','naruv_native_review.store_stage(text,text,text,text,text,integer,text,text,text,text,text,text[],text,text)']
INTERNAL={
'naruv_native_review':'guard immutable validated_ids target_digest receipt_json',
'naruv_customer_bridge':'apply_customer',
'naruv_inventory':'import_item receipt post_movement_internal',
'naruv_trade':'reserved balance_guard snapshot command_bundle_internal',
'naruv_finance':'paid credited credit_sum returned_qty allocation snapshot adjusted_snapshot command_bundle_internal',
'naruv_accounting':'period_guard validate_journal post_finance',
'naruv_bundle':'child_id',
'naruv_quote_bundle':'snapshot allocate_vat',
'naruv_production':'ident qty plan snapshot',
'naruv_valuation':'expected_posting post_cost_journal validate_cost_journal apply check_movement trade_post production_post',
'naruv_draft':'validate_observations period_digest',
'naruv_auth_fence':'lock_actor auth_change',
'naruv_quote_fence':'freeze'}
# Expected schema ACL excludes the object owner, whose implicit authority is not a service grant.
SCHEMA_GRANTS={(s,APP,OWNER,'USAGE',False) for s in APP_ROUTINES}
SCHEMA_GRANTS|={('naruv_native_review',STAGE,OWNER,'USAGE',False),
               ('naruv_quote_bundle',FENCE,OWNER,'USAGE',False),
               ('naruv_auth_fence',OWNER,AUTH,'USAGE',False)}
ROUTINE_GRANTS=[(s+'.'+f,APP,OWNER) for s,fs in APP_ROUTINES.items() for f in fs]
ROUTINE_GRANTS += [(f,STAGE,OWNER) for f in STAGE_ROUTINES]+[('naruv_auth_fence.lock_actor(text)',OWNER,AUTH)]
EXPECTED_NAMES={(s,f.split('(')[0]) for s,fs in APP_ROUTINES.items() for f in fs}
EXPECTED_NAMES|={(s,f) for s,fs in INTERNAL.items() for f in fs.split()}
EXPECTED_NAMES|={tuple(f.split('(')[0].split('.')) for f in STAGE_ROUTINES}
def audit(c):
    schemas=list(SCHEMA_OWNER)
    rows=c.execute("""SELECT nspname::text,pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname=ANY(%s)""",(schemas,)).fetchall()
    need(dict(rows)==SCHEMA_OWNER,'ROUTINE_SCHEMA_OWNER')
    rows=c.execute("""SELECT n.nspname::text,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
       pg_get_userbyid(a.grantor),a.privilege_type,a.is_grantable
       FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a
       WHERE n.nspname=ANY(%s) AND a.grantee<>n.nspowner""",(schemas,)).fetchall()
    need(set(rows)==SCHEMA_GRANTS,'ROUTINE_SCHEMA_GRANTS')
    rows=c.execute("""SELECT p.oid,n.nspname::text,p.proname::text,pg_get_userbyid(p.proowner),p.proconfig,p.prokind
      FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=ANY(%s)""",(schemas,)).fetchall()
    need(len(rows)==len(EXPECTED_NAMES) and {(s,n) for _,s,n,_,_,_ in rows}==EXPECTED_NAMES,'ROUTINE_INVENTORY')
    need(all(owner==SCHEMA_OWNER[s] and config==['search_path=pg_catalog'] and kind=='f' for _,s,n,owner,config,kind in rows),'ROUTINE_OWNER_CONFIG')
    expected=set()
    for signature,grantee,grantor in ROUTINE_GRANTS:
        oid=c.execute('SELECT to_regprocedure(%s)::oid',(signature,)).fetchone()[0]
        need(oid is not None,'ROUTINE_SIGNATURE_MISSING:'+signature)
        expected.add((oid,grantee,grantor,'EXECUTE',False))
    observed=c.execute("""SELECT p.oid,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
      pg_get_userbyid(a.grantor),a.privilege_type,a.is_grantable
      FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
      WHERE n.nspname=ANY(%s) AND a.grantee<>p.proowner""",(schemas,)).fetchall()
    need(set(observed)==expected,'ROUTINE_EXECUTE_GRANTS')
    defaults=c.execute("""SELECT count(*) FROM pg_default_acl d JOIN pg_roles r ON r.oid=d.defaclrole
        LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace
        WHERE r.rolname=ANY(%s) OR n.nspname=ANY(%s)""",(list(set(SCHEMA_OWNER.values())|{APP,STAGE}),schemas)).fetchone()
    need(defaults==(0,),'ROUTINE_DEFAULT_GRANTS')
    # Direct privilege matrix includes inherited grants; compare to explicit expected edges.
    matrix=0
    for role in (APP,STAGE):
        grants={oid for oid,r,_,_,_ in expected if r==role}
        for oid,_,_,_,_,_ in rows:
            need(c.execute('SELECT has_function_privilege(%s,%s::oid,%s)',(role,oid,'EXECUTE')).fetchone()==(oid in grants,),'ROUTINE_EFFECTIVE_EXECUTE')
            matrix+=1
        for s in schemas:
            expected_usage=any(x[0]==s and x[1]==role for x in SCHEMA_GRANTS)
            need(c.execute('SELECT has_schema_privilege(%s,%s,%s),has_schema_privilege(%s,%s,%s)',(role,s,'USAGE',role,s,'CREATE')).fetchone()==(expected_usage,False),'ROUTINE_EFFECTIVE_SCHEMA')
            matrix+=2
    return len(rows),len(expected),matrix

def mutations(c):
    cases=[
      ('GRANT EXECUTE ON FUNCTION naruv_trade.command_bundle_internal(text,text,text,jsonb,boolean,text) TO jw_app_dev','ROUTINE_EXECUTE_GRANTS'),
      ('REVOKE EXECUTE ON FUNCTION naruv_trade.inspect(text,text) FROM jw_app_dev','ROUTINE_EXECUTE_GRANTS'),
      ('GRANT EXECUTE ON FUNCTION naruv_trade.inspect(text,text) TO jw_app_dev WITH GRANT OPTION','ROUTINE_EXECUTE_GRANTS'),
      ('GRANT EXECUTE ON FUNCTION naruv_inventory.read_stock(text,text,text,text) TO PUBLIC','ROUTINE_EXECUTE_GRANTS'),
      ('GRANT CREATE ON SCHEMA naruv_inventory TO jw_app_dev','ROUTINE_SCHEMA_GRANTS'),
      ('GRANT USAGE ON SCHEMA naruv_auth_fence TO jw_app_dev','ROUTINE_SCHEMA_GRANTS'),
      ('ALTER FUNCTION naruv_trade.inspect(text,text) SET search_path=public','ROUTINE_OWNER_CONFIG'),
      ('CREATE FUNCTION naruv_inventory.unexpected() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$','ROUTINE_INVENTORY'),
      ('ALTER DEFAULT PRIVILEGES FOR ROLE naruv_native_owner GRANT EXECUTE ON FUNCTIONS TO jw_app_dev','ROUTINE_DEFAULT_GRANTS'),
    ]
    for q,code in cases:
        with c.transaction(force_rollback=True):
            c.execute(q)
            try:audit(c)
            except RuntimeError as e:need(str(e)==code,'ROUTINE_MUTATION_WRONG_CODE:'+str(e))
            else:raise RuntimeError('ROUTINE_MUTATION_MISSED:'+code)
        audit(c)
    return len(cases)

def runtime(fixture,ingest):
    cases=[(fixture.TRADE_DSN,APP,[
         "SELECT naruv_trade.command_bundle_internal(NULL,NULL,NULL,NULL,NULL,NULL)",
         "SELECT naruv_inventory.post_movement_internal(NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
         "SELECT naruv_native_review.guard(NULL,NULL)",
         "SELECT naruv_auth_fence.lock_actor(NULL)"]),
       (ingest,STAGE,[
         "SELECT naruv_native_review.approve(NULL,NULL,NULL,NULL,NULL,NULL)",
         "SELECT naruv_trade.inspect(NULL,NULL)",
         "SELECT naruv_native_review.guard(NULL,NULL)"])]
    count=0
    for dsn,role,queries in cases:
        with psycopg.connect(dsn) as c:
            c.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(role)))
            for q in queries:
                try:
                    with c.transaction():c.execute(q)
                except psycopg.errors.InsufficientPrivilege as e:need(e.sqlstate=='42501','ROUTINE_RUNTIME_CODE')
                else:raise RuntimeError('ROUTINE_RUNTIME_EXECUTE_ALLOWED')
                count+=1
    return count

def main():
    base.preflight()
    fixture,ingest=base.setup()
    profile=base.ROOT/'db/review/naruv_hr_profile_ci.sql'
    need(subprocess.check_output(['git','hash-object',str(profile)],text=True).strip()=='835b0d6b6210d0e6151d701848f9276f6f5a7be2','ROUTINE_PROFILE_PIN')
    with psycopg.connect(fixture.root_dsn) as c:
        c.execute("SET LOCAL naruv.profile_ci='DISPOSABLE_ONLY'")
        c.execute(profile.read_text())
    with psycopg.connect(fixture.root_dsn) as c:
        n,g,m=audit(c)
        print(f'ROUTINE_ACL_PASS schemas={len(SCHEMA_OWNER)} routines={n} explicit_grants={g} effective_checks={m}',flush=True)
        k=mutations(c)
        print(f'ROUTINE_DRIFT_ROLLBACK_PASS cases={k}',flush=True)
    print(f'ROUTINE_RUNTIME_DENIAL_PASS cases={runtime(fixture,ingest)} sqlstate=42501',flush=True)
    print('ROUTINE_ACL_REVIEW_PASS production_authorized=false gate5=BLOCKED',flush=True)
if __name__=='__main__':main()
