BEGIN;
SET LOCAL statement_timeout='20s';
SET LOCAL lock_timeout='2s';
SET LOCAL search_path=pg_catalog,pg_temp;
DO $g$ BEGIN
 IF current_user<>'postgres' OR session_user<>'postgres' OR current_database()<>'postgres'
 OR current_setting('server_version_num')::int<>170012
 OR to_regclass('naruv_qa_probe.fixture') IS NULL OR (SELECT count(*) FROM naruv_qa_probe.fixture)<>2
 OR to_regprocedure('jw_dev.v85_auth_issue_session(text,text,text,bigint,text)') IS NULL
 OR to_regprocedure('naruv_valuation.audit_ledger(text)') IS NULL
 OR EXISTS(SELECT 1 FROM jw_dev.organizations WHERE id IN ('qa-prod-a','qa-prod-b','qa-prod-c'))
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('jw_ci_trade','naruv_ci_ingest','naruv_v85_cutover_ci') AND rolcanlogin)
 THEN RAISE EXCEPTION 'HOSTED_NATIVE_SMOKE_SCOPE'; END IF;
END $g$;
INSERT INTO jw_dev.organizations(id,name,created_at) VALUES
 ('qa-prod-a','Synthetic QA A',clock_timestamp()::text),('qa-prod-b','Synthetic QA B',clock_timestamp()::text),('qa-prod-c','Synthetic QA C',clock_timestamp()::text);
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES
 ('qa-prod-ua','qa-prod-a','qa-prod-a@invalid.test','synthetic-unused','QA A','admin',clock_timestamp()::text),
 ('qa-prod-ub','qa-prod-b','qa-prod-b@invalid.test','synthetic-unused','QA B','admin',clock_timestamp()::text),
 ('qa-prod-uc','qa-prod-c','qa-prod-c@invalid.test','synthetic-unused','QA C','admin',clock_timestamp()::text);
INSERT INTO jw_dev.messenger_companies(org_id,business_number) VALUES
 ('qa-prod-a','synthetic-prod-a'),('qa-prod-b','synthetic-prod-b'),('qa-prod-c','synthetic-prod-c');
SET LOCAL ROLE naruv_hid_owner;
CREATE POLICY qa_seed_org_rollback ON naruv_hosted_identity_review.organizations FOR INSERT TO naruv_hid_owner WITH CHECK (id IN ('qa-prod-a','qa-prod-b','qa-prod-c'));
CREATE POLICY qa_seed_actor_rollback ON naruv_hosted_identity_review.users FOR INSERT TO naruv_hid_owner WITH CHECK ((id,org_id) IN (('qa-prod-ua','qa-prod-a'),('qa-prod-ub','qa-prod-b'),('qa-prod-uc','qa-prod-c')));
INSERT INTO naruv_hosted_identity_review.organizations(id,name) VALUES
 ('qa-prod-a','Synthetic QA A'),('qa-prod-b','Synthetic QA B'),('qa-prod-c','Synthetic QA C');
INSERT INTO naruv_hosted_identity_review.users(id,org_id,actor_role,active,epoch) VALUES
 ('qa-prod-ua','qa-prod-a','admin',true,0),('qa-prod-ub','qa-prod-b','admin',true,0),('qa-prod-uc','qa-prod-c','admin',true,0);
DROP POLICY qa_seed_org_rollback ON naruv_hosted_identity_review.organizations;
DROP POLICY qa_seed_actor_rollback ON naruv_hosted_identity_review.users;
RESET ROLE;
SET LOCAL ROLE jw_auth_stage_v85;
DO $t$ BEGIN
 IF jw_dev.v85_auth_issue_session('qa-prod-ua',repeat('a',64),repeat('c',32),NULL,NULL) IS NULL
 OR jw_dev.v85_auth_issue_session('qa-prod-ub',repeat('b',64),repeat('d',32),NULL,NULL) IS NULL
 OR jw_dev.v85_auth_issue_session('qa-prod-uc',repeat('e',64),repeat('f',32),NULL,NULL) IS NULL
 THEN RAISE EXCEPTION 'HOSTED_ISSUE'; END IF;
 IF NOT jw_dev.v85_auth_check_csrf(repeat('a',64),repeat('c',32)) OR jw_dev.v85_auth_check_csrf(repeat('a',64),repeat('d',32)) THEN RAISE EXCEPTION 'HOSTED_CSRF'; END IF;
 BEGIN PERFORM jw_dev.v85_issue_native_ci(NULL,NULL,NULL,NULL,NULL); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $t$;
RESET ROLE;
INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES ('qa-prod-ca','qa-prod-a','Synthetic vendor A',clock_timestamp()::text),('qa-prod-cb','qa-prod-b','Synthetic vendor B',clock_timestamp()::text);
SET LOCAL ROLE naruv_native_owner;
DO $r$ DECLARE x record; org text; actor text; stamp timestamptz:=clock_timestamp(); mon date:=date_trunc('month',stamp AT TIME ZONE 'Asia/Seoul')::date; rows_text text:='[{"name":"Bolt","unit":"EA"}]'; digest text; n int:=0; mat_mid text; out_mid text; sub bigint; vat_amt bigint; total_amt bigint; BEGIN
 digest:=encode(sha256(convert_to(rows_text,'UTF8')),'hex');
 FOR x IN SELECT * FROM (VALUES ('a',repeat('a',64),105::bigint),('b',repeat('b',64),205::bigint)) v(w,h,price) LOOP
   org:='qa-prod-'||x.w; actor:='qa-prod-u'||x.w;
   sub:=2*x.price; vat_amt:=sub/10; total_amt:=sub+vat_amt;
   PERFORM set_config('jw.session_hash',x.h,true);
   SET CONSTRAINTS ALL DEFERRED;
   INSERT INTO naruv_accounting.periods(org_id,period_start) VALUES(org,mon);
   INSERT INTO naruv_inventory.warehouses VALUES(org,'W1','Synthetic warehouse',true);
   INSERT INTO naruv_native_review.stages(org_id,stage_id,actor_id,session_binding_sha256,auth_epoch,source_id,entity,file_format,raw_sha256,byte_count,stage_sha256,canonical_sha256,rows_sha256,snapshot_sha256,expected_revision,expected_ids,rows_canonical,created_at,expires_at)
     VALUES(org,'stage-fixture',actor,repeat('1',64),0,'source','item','csv',repeat('2',64),1,repeat('3',64),digest,digest,repeat('4',64),'fixture',ARRAY[]::text[],rows_text,stamp,stamp+interval '1 hour');
   INSERT INTO naruv_native_review.records(org_id,source_id,entity,source_record_id,stage_id,data) VALUES(org,'source','item','001','stage-fixture','{"name":"Bolt","unit":"EA"}'::jsonb);
   INSERT INTO naruv_trade.documents(org_id,doc_id,actor_id,kind,counterparty_id,source_id,item_id,warehouse_id,quantity,unit_price,vat_mode,fulfilled,state,created_at)
     VALUES(org,'purchase',actor,'purchase','qa-prod-c'||x.w,'source','001','W1',2,x.price,'taxable',2,'DONE',stamp);
   INSERT INTO naruv_inventory.balances VALUES(org,'source','001','W1',2);
   INSERT INTO naruv_inventory.movements VALUES(org,'movement',actor,'source','001',NULL,'W1',2,NULL,2,stamp);
   INSERT INTO naruv_trade.events VALUES(org,'fulfill','purchase',actor,'fulfill','{"quantity":2}'::jsonb,'movement','{}'::jsonb,stamp);

   INSERT INTO naruv_native_review.records(org_id,source_id,entity,source_record_id,stage_id,data) VALUES(org,'source','item','002','stage-fixture','{"name":"Assembly","unit":"EA"}'::jsonb);
   INSERT INTO naruv_production.boms VALUES(org,'bom','source','002',actor,stamp);
   INSERT INTO naruv_production.components VALUES(org,'bom','source','001',1);
   INSERT INTO naruv_production.orders VALUES(org,'job','bom','W1',actor,1,1,'DONE',stamp);
   mat_mid:='doc:'||encode(sha256(convert_to(jsonb_build_array('production','complete','material','001')::text,'UTF8')),'hex');
   out_mid:='doc:'||encode(sha256(convert_to(jsonb_build_array('production','complete','output','002')::text,'UTF8')),'hex');
   UPDATE naruv_inventory.balances SET quantity=1 WHERE org_id=org AND source_id='source' AND normalized_id='001' AND warehouse_id='W1';
   INSERT INTO naruv_inventory.balances VALUES(org,'source','002','W1',1);
   INSERT INTO naruv_inventory.movements VALUES(org,mat_mid,actor,'source','001','W1',NULL,1,1,NULL,stamp),(org,out_mid,actor,'source','002',NULL,'W1',1,NULL,1,stamp);
   INSERT INTO naruv_production.events VALUES(org,'complete','bom','job',actor,'complete','{"quantity":1}'::jsonb,'{}'::jsonb,stamp);
   IF (SELECT count(*) FROM naruv_valuation.balances WHERE org_id=org AND source_id='source' AND warehouse_id='W1' AND quantity=1 AND value_krw=x.price AND item_id IN ('001','002'))<>2 THEN RAISE EXCEPTION 'PROD_VALUE'; END IF; n:=n+1;
   IF (SELECT count(*) FROM naruv_valuation.entries WHERE org_id=org AND movement_id=mat_mid AND kind='material' AND amount_krw=x.price)<>1 THEN RAISE EXCEPTION 'PROD_MATERIAL'; END IF; n:=n+1;
   IF (SELECT count(*) FROM naruv_valuation.entries WHERE org_id=org AND movement_id=out_mid AND kind='output' AND amount_krw=x.price)<>1 THEN RAISE EXCEPTION 'PROD_OUTPUT'; END IF; n:=n+1;
   IF (SELECT count(*) FROM naruv_valuation.cost_journals WHERE org_id=org AND ((movement_id=mat_mid AND debit_account='WIP' AND credit_account='INVENTORY') OR (movement_id=out_mid AND debit_account='INVENTORY' AND credit_account='WIP')) AND amount_krw=x.price)<>2 THEN RAISE EXCEPTION 'PROD_JOURNAL'; END IF; n:=n+1;
   IF (SELECT sum(value_krw) FROM naruv_valuation.balances WHERE org_id=org)<>sub THEN RAISE EXCEPTION 'PROD_CONSERVATION'; END IF; n:=n+1;
   IF (SELECT coalesce(sum(CASE WHEN debit_account='WIP' THEN amount_krw ELSE 0 END)-sum(CASE WHEN credit_account='WIP' THEN amount_krw ELSE 0 END),0) FROM naruv_valuation.cost_journals WHERE org_id=org)<>0 THEN RAISE EXCEPTION 'PROD_WIP'; END IF; n:=n+1;
   SET CONSTRAINTS ALL IMMEDIATE; n:=n+1;
 END LOOP;
 IF n<>14 THEN RAISE EXCEPTION 'CHECK_COUNT'; END IF;
END $r$;
RESET ROLE;
SELECT 'HOSTED_PRODUCTION_COST_CHAIN_PASS' AS verdict,2 AS tenants,14 AS assertions,false AS independent_rpc,false AS committed_workload;
ROLLBACK;