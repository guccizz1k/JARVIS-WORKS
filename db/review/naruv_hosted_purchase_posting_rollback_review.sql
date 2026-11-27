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
 OR EXISTS(SELECT 1 FROM jw_dev.organizations WHERE id IN ('qa-flow-a','qa-flow-b','qa-flow-c'))
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('jw_ci_trade','naruv_ci_ingest','naruv_v85_cutover_ci') AND rolcanlogin)
 THEN RAISE EXCEPTION 'HOSTED_NATIVE_SMOKE_SCOPE'; END IF;
END $g$;
INSERT INTO jw_dev.organizations(id,name,created_at) VALUES
 ('qa-flow-a','Synthetic QA A',clock_timestamp()::text),('qa-flow-b','Synthetic QA B',clock_timestamp()::text),('qa-flow-c','Synthetic QA C',clock_timestamp()::text);
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES
 ('qa-flow-ua','qa-flow-a','qa-flow-a@invalid.test','synthetic-unused','QA A','admin',clock_timestamp()::text),
 ('qa-flow-ub','qa-flow-b','qa-flow-b@invalid.test','synthetic-unused','QA B','admin',clock_timestamp()::text),
 ('qa-flow-uc','qa-flow-c','qa-flow-c@invalid.test','synthetic-unused','QA C','admin',clock_timestamp()::text);
INSERT INTO jw_dev.messenger_companies(org_id,business_number) VALUES
 ('qa-flow-a','synthetic-flow-a'),('qa-flow-b','synthetic-flow-b'),('qa-flow-c','synthetic-flow-c');
SET LOCAL ROLE naruv_hid_owner;
CREATE POLICY qa_seed_org_rollback ON naruv_hosted_identity_review.organizations FOR INSERT TO naruv_hid_owner WITH CHECK (id IN ('qa-flow-a','qa-flow-b','qa-flow-c'));
CREATE POLICY qa_seed_actor_rollback ON naruv_hosted_identity_review.users FOR INSERT TO naruv_hid_owner WITH CHECK ((id,org_id) IN (('qa-flow-ua','qa-flow-a'),('qa-flow-ub','qa-flow-b'),('qa-flow-uc','qa-flow-c')));
INSERT INTO naruv_hosted_identity_review.organizations(id,name) VALUES
 ('qa-flow-a','Synthetic QA A'),('qa-flow-b','Synthetic QA B'),('qa-flow-c','Synthetic QA C');
INSERT INTO naruv_hosted_identity_review.users(id,org_id,actor_role,active,epoch) VALUES
 ('qa-flow-ua','qa-flow-a','admin',true,0),('qa-flow-ub','qa-flow-b','admin',true,0),('qa-flow-uc','qa-flow-c','admin',true,0);
DROP POLICY qa_seed_org_rollback ON naruv_hosted_identity_review.organizations;
DROP POLICY qa_seed_actor_rollback ON naruv_hosted_identity_review.users;
RESET ROLE;
SET LOCAL ROLE jw_auth_stage_v85;
DO $t$ BEGIN
 IF jw_dev.v85_auth_issue_session('qa-flow-ua',repeat('a',64),repeat('c',32),NULL,NULL) IS NULL
 OR jw_dev.v85_auth_issue_session('qa-flow-ub',repeat('b',64),repeat('d',32),NULL,NULL) IS NULL
 OR jw_dev.v85_auth_issue_session('qa-flow-uc',repeat('e',64),repeat('f',32),NULL,NULL) IS NULL
 THEN RAISE EXCEPTION 'HOSTED_ISSUE'; END IF;
 IF NOT jw_dev.v85_auth_check_csrf(repeat('a',64),repeat('c',32)) OR jw_dev.v85_auth_check_csrf(repeat('a',64),repeat('d',32)) THEN RAISE EXCEPTION 'HOSTED_CSRF'; END IF;
 BEGIN PERFORM jw_dev.v85_issue_native_ci(NULL,NULL,NULL,NULL,NULL); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $t$;
RESET ROLE;
INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES ('qa-flow-ca','qa-flow-a','Synthetic vendor A',clock_timestamp()::text),('qa-flow-cb','qa-flow-b','Synthetic vendor B',clock_timestamp()::text);
SET LOCAL ROLE naruv_native_owner;
DO $r$ DECLARE x record; org text; actor text; stamp timestamptz:=clock_timestamp(); mon date:=date_trunc('month',stamp AT TIME ZONE 'Asia/Seoul')::date; rows_text text:='[{"name":"Bolt","unit":"EA"}]'; digest text; n int:=0; sub bigint; vat_amt bigint; total_amt bigint; BEGIN
 digest:=encode(sha256(convert_to(rows_text,'UTF8')),'hex');
 FOR x IN SELECT * FROM (VALUES ('a',repeat('a',64),105::bigint),('b',repeat('b',64),205::bigint)) v(w,h,price) LOOP
   org:='qa-flow-'||x.w; actor:='qa-flow-u'||x.w;
   sub:=2*x.price; vat_amt:=sub/10; total_amt:=sub+vat_amt;
   PERFORM set_config('jw.session_hash',x.h,true);
   SET CONSTRAINTS ALL DEFERRED;
   INSERT INTO naruv_accounting.periods(org_id,period_start) VALUES(org,mon);
   INSERT INTO naruv_inventory.warehouses VALUES(org,'W1','Synthetic warehouse',true);
   INSERT INTO naruv_native_review.stages(org_id,stage_id,actor_id,session_binding_sha256,auth_epoch,source_id,entity,file_format,raw_sha256,byte_count,stage_sha256,canonical_sha256,rows_sha256,snapshot_sha256,expected_revision,expected_ids,rows_canonical,created_at,expires_at)
     VALUES(org,'stage-fixture',actor,repeat('1',64),0,'source','item','csv',repeat('2',64),1,repeat('3',64),digest,digest,repeat('4',64),'fixture',ARRAY[]::text[],rows_text,stamp,stamp+interval '1 hour');
   INSERT INTO naruv_native_review.records(org_id,source_id,entity,source_record_id,stage_id,data) VALUES(org,'source','item','001','stage-fixture','{"name":"Bolt","unit":"EA"}'::jsonb);
   IF (SELECT count(*) FROM naruv_inventory.items WHERE org_id=org AND source_id='source' AND normalized_id='001' AND name='Bolt')<>1 THEN RAISE EXCEPTION 'IMPORT_TRIGGER'; END IF; n:=n+1;
   INSERT INTO naruv_trade.documents(org_id,doc_id,actor_id,kind,counterparty_id,source_id,item_id,warehouse_id,quantity,unit_price,vat_mode,fulfilled,state,created_at)
     VALUES(org,'purchase',actor,'purchase','qa-flow-c'||x.w,'source','001','W1',2,x.price,'taxable',2,'DONE',stamp);
   INSERT INTO naruv_inventory.balances VALUES(org,'source','001','W1',2);
   INSERT INTO naruv_inventory.movements VALUES(org,'movement',actor,'source','001',NULL,'W1',2,NULL,2,stamp);
   INSERT INTO naruv_trade.events VALUES(org,'fulfill','purchase',actor,'fulfill','{"quantity":2}'::jsonb,'movement','{}'::jsonb,stamp);
   IF (SELECT count(*) FROM naruv_valuation.balances WHERE org_id=org AND source_id='source' AND item_id='001' AND warehouse_id='W1' AND quantity=2 AND value_krw=sub)<>1 THEN RAISE EXCEPTION 'VALUATION_BALANCE'; END IF; n:=n+1;
   IF (SELECT count(*) FROM naruv_valuation.entries WHERE org_id=org AND movement_id='movement' AND kind='purchase' AND amount_krw=sub)<>1 THEN RAISE EXCEPTION 'VALUATION_ENTRY'; END IF; n:=n+1;
   IF (SELECT count(*) FROM naruv_valuation.cost_journals WHERE org_id=org AND movement_id='movement' AND debit_account='INVENTORY' AND credit_account='PURCHASE_CLEARING' AND amount_krw=sub)<>1 THEN RAISE EXCEPTION 'COST_JOURNAL'; END IF; n:=n+1;
   INSERT INTO naruv_finance.bills(org_id,bill_id,doc_id,fulfillment_id,kind,actor_id,quantity,subtotal,vat,created_at) VALUES(org,'bill','purchase','fulfill','purchase',actor,2,sub,vat_amt,stamp);
   INSERT INTO naruv_finance.events VALUES(org,'bill-event','bill',actor,'bill','{}',0,NULL,NULL,'{}',stamp);
   INSERT INTO naruv_finance.events VALUES(org,'pay-event','bill',actor,'pay','{}',total_amt,'pay-ref',NULL,'{}',stamp);
   INSERT INTO naruv_finance.events VALUES(org,'reverse-event','bill',actor,'reverse','{}',total_amt,NULL,'pay-event','{}',stamp);
   IF (SELECT count(*) FROM naruv_accounting.journals WHERE org_id=org AND bill_id='bill')<>3 THEN RAISE EXCEPTION 'JOURNAL_COUNT'; END IF; n:=n+1;
   IF (SELECT count(*) FROM (SELECT event_id FROM naruv_accounting.lines WHERE org_id=org GROUP BY event_id HAVING sum(debit)=total_amt AND sum(credit)=total_amt) z)<>3 THEN RAISE EXCEPTION 'UNBALANCED'; END IF; n:=n+1;
   IF (SELECT count(*) FROM naruv_accounting.lines WHERE org_id=org AND event_id='bill-event' AND ((account='AP' AND credit=total_amt) OR (account='PURCHASE_CLEARING' AND debit=sub) OR (account='VAT_INPUT' AND debit=vat_amt)))<>3 THEN RAISE EXCEPTION 'BILL_ACCOUNTS'; END IF; n:=n+1;
   IF EXISTS(SELECT 1 FROM naruv_accounting.lines p LEFT JOIN naruv_accounting.lines r ON r.org_id=p.org_id AND r.event_id='reverse-event' AND r.line_no=p.line_no WHERE p.org_id=org AND p.event_id='pay-event' AND (r.account,r.debit,r.credit) IS DISTINCT FROM (p.account,p.credit,p.debit)) THEN RAISE EXCEPTION 'REVERSAL'; END IF; n:=n+1;
   SET CONSTRAINTS ALL IMMEDIATE; n:=n+1;
 END LOOP;
 IF n<>18 THEN RAISE EXCEPTION 'CHECK_COUNT'; END IF;
END $r$;
RESET ROLE;
SELECT 'HOSTED_PURCHASE_POSTING_TRIGGER_CHAIN_PASS' AS verdict,2 AS tenants,18 AS assertions,false AS independent_rpc,false AS committed_workload;
ROLLBACK;