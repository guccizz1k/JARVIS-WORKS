"""Source-pinned disposable jw_dev fixture authorization audit and hardening rehearsal.
No production migration. The fixture's postgres-owned identity helpers are not
an approved production role/ownership design."""
import importlib.util
from pathlib import Path
import subprocess
import hashlib
import psycopg
from psycopg import sql

spec=importlib.util.spec_from_file_location('prior_acl',Path(__file__).with_name('naruv_erp_acl_source_review.py'))
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
need=base.need
APP=base.APP; OWNER=base.OWNER; STAGE=base.STAGE
TABLES=set('organizations users sessions messenger_companies messenger_connections messenger_messages messenger_attachments messenger_edits messenger_read_positions customers quotes quote_items audit_logs naruv_review_sources staff_disabled'.split())
SENSITIVE=TABLES-{'customers','quotes','quote_items','audit_logs','naruv_review_sources'}
SIGNATURES=['current_org_from_session()','current_actor_from_session_v82()','stage_identity_v84()',
 'search_messenger_companies_v90(text,integer,integer)','v90_start_chat(text)',
 'v90_send_text(text,text,text,text,text,bytea)','v90_mark_read(text,bigint)',
 'v90_edit_text(text,text,bigint)','v90_sync_messages(text,bigint,integer)',
 'v90_sync_edits(text,timestamptz,text,integer)']
PINS={'ci_v90_ephemeral_pg_schema.sql':'63acd53abef949c900352aceed58f20cfb41fd15',
'ci_qa_001_jw_dev_secure_messenger_directory.sql':'0caf711a7e019b8c61b68f3998903136bfa234b8',
'ci_qa_002_jw_dev_messenger_rpc.sql':'7e32926704608b3793e3227ecf488a49fd355c92',
'ci_qa_006_commit_order_cursor_guard_candidate.sql':'080d159dee2b6cca8ffc847b1f76eec21ced86e1',
'ci_v92_quote_ephemeral.sql':'02966428b805290327358045187da38b4e239b0f',
'jw_dev_v84_stage_identity.sql':'9539bd516216bf6e92ee6f78910afd5fe7cf9d14'}
PATCH="""
REVOKE ALL ON FUNCTION jw_dev.current_org_from_session(),jw_dev.current_actor_from_session_v82() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION jw_dev.current_org_from_session(),jw_dev.current_actor_from_session_v82() TO jw_app_dev;
ALTER TABLE jw_dev.staff_disabled ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.staff_disabled FORCE ROW LEVEL SECURITY;
"""
def effective(c,role,sig):
    return c.execute('SELECT has_function_privilege(%s,%s,%s)',(role,'jw_dev.'+sig,'EXECUTE')).fetchone()[0]

def audit(c):
    rows=c.execute("""SELECT relname::text,relrowsecurity,relforcerowsecurity,pg_get_userbyid(relowner)
        FROM pg_class WHERE relnamespace='jw_dev'::regnamespace AND relkind IN ('r','p')""").fetchall()
    need(set(rows)=={(t,True,True,'postgres') for t in TABLES},'JWDEV_TABLE_FORCE_RLS')
    rows=c.execute("""SELECT nspname::text,pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='jw_dev'""").fetchall()
    need(rows==[('jw_dev','postgres')],'JWDEV_SCHEMA_OWNER')
    grants=c.execute("""SELECT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
        pg_get_userbyid(a.grantor),a.privilege_type,a.is_grantable
        FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a
        WHERE n.nspname='jw_dev' AND a.grantee<>n.nspowner""").fetchall()
    need(set(grants)=={(r,'postgres','USAGE',False) for r in (APP,OWNER,STAGE)},'JWDEV_SCHEMA_GRANTS')
    funcs=c.execute("""SELECT p.oid,p.proname::text,p.prosecdef,p.proconfig,pg_get_userbyid(p.proowner)
         FROM pg_proc p WHERE p.pronamespace='jw_dev'::regnamespace""").fetchall()
    need(len(funcs)==len(SIGNATURES) and all(r[2] and r[3]==['search_path=pg_catalog'] and r[4]=='postgres' for r in funcs),'JWDEV_FUNCTION_SCOPE')
    expected=set()
    for sig in SIGNATURES:
        oid=c.execute('SELECT to_regprocedure(%s)::oid',('jw_dev.'+sig,)).fetchone()[0]
        need(oid is not None,'JWDEV_SIGNATURE')
        roles={APP}
        if sig.startswith(('current_org','stage_identity')):roles.add(OWNER)
        if sig.startswith('stage_identity'):roles.add(STAGE)
        expected|={(oid,r,'postgres','EXECUTE',False) for r in roles}
    grants=c.execute("""SELECT p.oid,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
       pg_get_userbyid(a.grantor),a.privilege_type,a.is_grantable
       FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
       WHERE p.pronamespace='jw_dev'::regnamespace AND a.grantee<>p.proowner""").fetchall()
    need(set(grants)==expected,'JWDEV_FUNCTION_GRANTS')
    wanted={(t,APP,p) for t,ps in {'customers':['SELECT'],'quotes':['SELECT','INSERT'],'quote_items':['SELECT','INSERT'],'audit_logs':['INSERT'],'naruv_review_sources':['SELECT']}.items() for p in ps}
    wanted|={(t,OWNER,'SELECT') for t in ('customers','quotes','quote_items','naruv_review_sources')}
    grants=c.execute("""SELECT t.relname::text,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
       a.privilege_type,pg_get_userbyid(a.grantor),a.is_grantable
       FROM pg_class t CROSS JOIN LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a
       WHERE t.relnamespace='jw_dev'::regnamespace AND t.relkind='r' AND a.grantee<>t.relowner""").fetchall()
    need(set(grants)=={(*x,'postgres',False) for x in wanted},'JWDEV_TABLE_GRANTS')
    wanted_cols={(t,k,OWNER,p,'postgres',False) for t,ks,p in [
        ('customers','id org_id name business_number contact_name email phone created_at','INSERT'),
        ('customers','org_id id','REFERENCES'),
        ('audit_logs','id org_id actor_id entity_type entity_id action detail created_at','INSERT'),
        ('naruv_review_sources','revision existing_ids','UPDATE'),
        ('quotes','id','REFERENCES'),('quote_items','id','REFERENCES')] for k in ks.split()}
    cols=c.execute("""SELECT t.relname::text,c.attname::text,
       CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,
       pg_get_userbyid(a.grantor),a.is_grantable
       FROM pg_attribute c JOIN pg_class t ON t.oid=c.attrelid
       CROSS JOIN LATERAL aclexplode(c.attacl) a
       WHERE t.relnamespace='jw_dev'::regnamespace AND c.attnum>0 AND NOT c.attisdropped""").fetchall()
    need(set(cols)==wanted_cols,'JWDEV_COLUMN_GRANTS')
    seq=c.execute("""SELECT relname::text,pg_get_userbyid(relowner),relacl IS NULL
       FROM pg_class WHERE relnamespace='jw_dev'::regnamespace AND relkind='S'""").fetchall()
    need(seq==[('messenger_seq_v90','postgres',True)],'JWDEV_SEQUENCE_GRANTS')
    names={'ci_customers_tenant','ci_quote_select','ci_quote_insert','ci_quote_item_select','ci_quote_item_insert',
       'ci_audit_insert','naruv_review_source_tenant','naruv_native_owner_source','naruv_ci_customer_insert',
       'naruv_ci_customer_audit','naruv_trade_quote_read','naruv_trade_quote_item_read','naruv_trade_customer_read'}
    policies=c.execute("SELECT policyname::text FROM pg_policies WHERE schemaname='jw_dev'").fetchall()
    need(len(policies)==len(names) and {x[0] for x in policies}==names,'JWDEV_POLICY_INVENTORY')
    for role in ('anon','authenticated','service_role','jw_auth_stage_v85'):
        for sig in SIGNATURES:need(not effective(c,role,sig),'JWDEV_UNEXPECTED_EFFECTIVE_EXECUTE')
    return len(TABLES),len(funcs),len(wanted_cols),len(names)

def verify_behavior(fixture,ingest):
    count=0
    for dsn,role in ((fixture.TRADE_DSN,APP),(ingest,STAGE)):
        with psycopg.connect(dsn) as c:
            c.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(role)))
            for table in sorted(SENSITIVE):
                for q in (sql.SQL('SELECT 1 FROM {} LIMIT 1').format(sql.Identifier('jw_dev',table)),
                          sql.SQL('DELETE FROM {} WHERE false').format(sql.Identifier('jw_dev',table))):
                    try:
                        with c.transaction():c.execute(q)
                    except psycopg.errors.InsufficientPrivilege as e:need(e.sqlstate=='42501','JWDEV_SQLSTATE')
                    else:raise RuntimeError('JWDEV_SENSITIVE_DIRECT_ACCESS')
                    count+=1
            c.execute("SELECT set_config('jw.session_hash',%s,true)",(base.session_hash(fixture,'A'),))
            need(c.execute('SELECT org_id FROM jw_dev.stage_identity_v84()').fetchone()==('ci-a',),'JWDEV_STAGE_IDENTITY')
            if role==APP:
                need(c.execute('SELECT jw_dev.current_org_from_session(),jw_dev.current_actor_from_session_v82()').fetchone()==('ci-a','ci-ua'),'JWDEV_HELPER_POSITIVE')
                need(c.execute('SELECT DISTINCT org_id FROM jw_dev.customers').fetchall()==[('ci-a',)],'JWDEV_TENANT_CUSTOMER')
                need(c.execute('SELECT DISTINCT org_id FROM jw_dev.naruv_review_sources').fetchall()==[('ci-a',)],'JWDEV_TENANT_SOURCE')
            else:
                for sig in ('current_org_from_session()','current_actor_from_session_v82()'):
                    try:
                        with c.transaction():c.execute('SELECT jw_dev.'+sig)
                    except psycopg.errors.InsufficientPrivilege as e:need(e.sqlstate=='42501','JWDEV_HELPER_DENIAL_CODE');count+=1
                    else:raise RuntimeError('JWDEV_HELPER_DIRECT_EXECUTE')
    # Existing messenger path still works after reducing helper grants.
    chat=fixture.PgGateway().query(base.session_hash(fixture,'A'),"SELECT * FROM jw_dev.v90_start_chat(%s)",('ci-b',))[0]['connection_id']
    fixture.PgGateway().query(base.session_hash(fixture,'A'),"SELECT * FROM jw_dev.v90_send_text(%s,%s,%s)",(chat,'jwdev-acl-probe','synthetic'))
    for who in ('A','B'):
        rows=fixture.PgGateway().query(base.session_hash(fixture,who),"SELECT * FROM jw_dev.v90_sync_messages(%s,%s,%s)",(chat,0,100))
        need(any(r['body']=='synthetic' for r in rows),'JWDEV_MESSAGE_VISIBLE')
    try:fixture.PgGateway().query(base.session_hash(fixture,'C'),"SELECT * FROM jw_dev.v90_sync_messages(%s,%s,%s)",(chat,0,100))
    except psycopg.errors.InsufficientPrivilege:count+=1
    else:raise RuntimeError('JWDEV_MESSENGER_SCOPE')
    return count

def main():
    base.preflight()
    for name,sha in PINS.items():
        need(subprocess.check_output(['git','hash-object',str(base.ROOT/'db/review'/name)],text=True).strip()==sha,'JWDEV_SOURCE_PIN')
    fixture,ingest=base.setup()
    with psycopg.connect(fixture.root_dsn) as c:
        # Reproduce baseline shortcomings, rather than claim they exist in production.
        need(all(effective(c,STAGE,sig) for sig in SIGNATURES[:2]),'JWDEV_EXPECTED_BASE_PUBLIC_HELPERS')
        need(c.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='jw_dev.staff_disabled'::regclass").fetchone()==(False,False),'JWDEV_EXPECTED_BASE_STAFF_RLS')
        print('JWDEV_BASELINE_GAPS_REPRODUCED helpers=2 missing_force_rls_tables=1',flush=True)
        c.execute(PATCH)
        t,f,cols,p=audit(c)
        print(f'JWDEV_CATALOG_PASS tables={t} functions={f} column_grants={cols} policies={p}',flush=True)
        for q,code in [
          ('GRANT EXECUTE ON FUNCTION jw_dev.current_org_from_session() TO PUBLIC','JWDEV_FUNCTION_GRANTS'),
          ('GRANT SELECT ON jw_dev.sessions TO jw_app_dev','JWDEV_TABLE_GRANTS'),
          ('GRANT UPDATE(token_hash) ON jw_dev.sessions TO jw_app_dev','JWDEV_COLUMN_GRANTS'),
          ('ALTER TABLE jw_dev.staff_disabled NO FORCE ROW LEVEL SECURITY','JWDEV_TABLE_FORCE_RLS'),
          ('GRANT CREATE ON SCHEMA jw_dev TO jw_app_dev','JWDEV_SCHEMA_GRANTS')]:
            with c.transaction(force_rollback=True):
                c.execute(q)
                try:audit(c)
                except RuntimeError as e:need(str(e)==code,'JWDEV_MUTATION_WRONG_CODE:'+str(e))
                else:raise RuntimeError('JWDEV_MUTATION_MISSED')
            audit(c)
        print('JWDEV_MUTATION_ROLLBACK_PASS cases=5',flush=True)
    print(f'JWDEV_RUNTIME_PASS denials={verify_behavior(fixture,ingest)} messenger=PASS tenant_reads=PASS',flush=True)
    print('JWDEV_REVIEW_PASS production_authorized=false gate5=BLOCKED',flush=True)
if __name__=='__main__':main()
