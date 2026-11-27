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
 OR EXISTS(SELECT 1 FROM jw_dev.organizations WHERE id IN ('qa-rls-a','qa-rls-b','qa-rls-c'))
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('jw_ci_trade','naruv_ci_ingest','naruv_v85_cutover_ci') AND rolcanlogin)
 THEN RAISE EXCEPTION 'HOSTED_NATIVE_SMOKE_SCOPE'; END IF;
END $g$;
INSERT INTO jw_dev.organizations(id,name,created_at) VALUES
 ('qa-rls-a','Synthetic QA A',clock_timestamp()::text),('qa-rls-b','Synthetic QA B',clock_timestamp()::text),('qa-rls-c','Synthetic QA C',clock_timestamp()::text);
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES
 ('qa-rls-ua','qa-rls-a','qa-rls-a@invalid.test','synthetic-unused','QA A','admin',clock_timestamp()::text),
 ('qa-rls-ub','qa-rls-b','qa-rls-b@invalid.test','synthetic-unused','QA B','admin',clock_timestamp()::text),
 ('qa-rls-uc','qa-rls-c','qa-rls-c@invalid.test','synthetic-unused','QA C','admin',clock_timestamp()::text);
INSERT INTO jw_dev.messenger_companies(org_id,business_number) VALUES
 ('qa-rls-a','synthetic-rls-a'),('qa-rls-b','synthetic-rls-b'),('qa-rls-c','synthetic-rls-c');
SET LOCAL ROLE naruv_hid_owner;
CREATE POLICY qa_seed_org_rollback ON naruv_hosted_identity_review.organizations FOR INSERT TO naruv_hid_owner WITH CHECK (id IN ('qa-rls-a','qa-rls-b','qa-rls-c'));
CREATE POLICY qa_seed_actor_rollback ON naruv_hosted_identity_review.users FOR INSERT TO naruv_hid_owner WITH CHECK ((id,org_id) IN (('qa-rls-ua','qa-rls-a'),('qa-rls-ub','qa-rls-b'),('qa-rls-uc','qa-rls-c')));
INSERT INTO naruv_hosted_identity_review.organizations(id,name) VALUES
 ('qa-rls-a','Synthetic QA A'),('qa-rls-b','Synthetic QA B'),('qa-rls-c','Synthetic QA C');
INSERT INTO naruv_hosted_identity_review.users(id,org_id,actor_role,active,epoch) VALUES
 ('qa-rls-ua','qa-rls-a','admin',true,0),('qa-rls-ub','qa-rls-b','admin',true,0),('qa-rls-uc','qa-rls-c','admin',true,0);
DROP POLICY qa_seed_org_rollback ON naruv_hosted_identity_review.organizations;
DROP POLICY qa_seed_actor_rollback ON naruv_hosted_identity_review.users;
RESET ROLE;
SET LOCAL ROLE jw_auth_stage_v85;
DO $t$ BEGIN
 IF jw_dev.v85_auth_issue_session('qa-rls-ua',repeat('a',64),repeat('c',32),NULL,NULL) IS NULL
 OR jw_dev.v85_auth_issue_session('qa-rls-ub',repeat('b',64),repeat('d',32),NULL,NULL) IS NULL
 OR jw_dev.v85_auth_issue_session('qa-rls-uc',repeat('e',64),repeat('f',32),NULL,NULL) IS NULL
 THEN RAISE EXCEPTION 'HOSTED_ISSUE'; END IF;
 IF NOT jw_dev.v85_auth_check_csrf(repeat('a',64),repeat('c',32)) OR jw_dev.v85_auth_check_csrf(repeat('a',64),repeat('d',32)) THEN RAISE EXCEPTION 'HOSTED_CSRF'; END IF;
 BEGIN PERFORM jw_dev.v85_issue_native_ci(NULL,NULL,NULL,NULL,NULL); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $t$;
RESET ROLE;
SET LOCAL ROLE naruv_native_owner;
DO $r$ DECLARE who text; h text; tenant text; n int:=0; affected int; wanted int; BEGIN
 FOR who,h IN SELECT * FROM (VALUES ('a',repeat('a',64)),('b',repeat('b',64))) v(w,hash) LOOP
   tenant:='qa-rls-'||who;
   PERFORM set_config('jw.session_hash',h,true);
   INSERT INTO naruv_inventory.warehouses(org_id,warehouse_id,name,active) VALUES(tenant,'QA-SAME-WH','Synthetic '||who,true);
   INSERT INTO naruv_accounting.periods(org_id,period_start) VALUES(tenant,DATE '2026-11-01');
 END LOOP;
 FOR who,h IN SELECT * FROM (VALUES ('a',repeat('a',64)),('b',repeat('b',64)),('c',repeat('e',64)),('unknown',repeat('9',64))) v(w,hash) LOOP
   tenant:='qa-rls-'||who;
   wanted:=CASE WHEN who IN ('a','b') THEN 1 ELSE 0 END;
   PERFORM set_config('jw.session_hash',h,true);
   IF (SELECT count(*) FROM naruv_inventory.warehouses WHERE warehouse_id='QA-SAME-WH')<>wanted THEN RAISE EXCEPTION 'WAREHOUSE_VISIBLE_COUNT'; END IF;
   IF EXISTS(SELECT 1 FROM naruv_inventory.warehouses WHERE warehouse_id='QA-SAME-WH' AND org_id<>tenant) THEN RAISE EXCEPTION 'WAREHOUSE_CROSS_READ'; END IF;
   IF (SELECT count(*) FROM naruv_accounting.periods WHERE org_id IN ('qa-rls-a','qa-rls-b'))<>wanted THEN RAISE EXCEPTION 'PERIOD_VISIBLE_COUNT'; END IF;
   IF EXISTS(SELECT 1 FROM naruv_accounting.periods WHERE org_id IN ('qa-rls-a','qa-rls-b') AND org_id<>tenant) THEN RAISE EXCEPTION 'PERIOD_CROSS_READ'; END IF;
   n:=n+4;
 END LOOP;
 PERFORM set_config('jw.session_hash',repeat('a',64),true);
 BEGIN INSERT INTO naruv_inventory.warehouses VALUES('qa-rls-b','QA-CROSS','Denied',true); RAISE EXCEPTION 'CROSS_INSERT_ACCEPTED'; EXCEPTION WHEN insufficient_privilege THEN n:=n+1; END;
 BEGIN INSERT INTO naruv_accounting.periods(org_id,period_start) VALUES('qa-rls-b',DATE '2026-12-01'); RAISE EXCEPTION 'CROSS_PERIOD_ACCEPTED'; EXCEPTION WHEN insufficient_privilege THEN n:=n+1; END;
 UPDATE naruv_inventory.warehouses SET name='Unauthorized' WHERE org_id='qa-rls-b' AND warehouse_id='QA-SAME-WH';
 GET DIAGNOSTICS affected=ROW_COUNT; IF affected<>0 THEN RAISE EXCEPTION 'CROSS_UPDATE'; END IF; n:=n+1;
 DELETE FROM naruv_inventory.warehouses WHERE org_id='qa-rls-b' AND warehouse_id='QA-SAME-WH';
 GET DIAGNOSTICS affected=ROW_COUNT; IF affected<>0 THEN RAISE EXCEPTION 'CROSS_DELETE'; END IF; n:=n+1;
 BEGIN UPDATE naruv_inventory.warehouses SET org_id='qa-rls-c' WHERE org_id='qa-rls-a' AND warehouse_id='QA-SAME-WH'; RAISE EXCEPTION 'CROSS_MOVE_ACCEPTED'; EXCEPTION WHEN insufficient_privilege THEN n:=n+1; END;
 PERFORM set_config('jw.session_hash',repeat('b',64),true);
 IF (SELECT name FROM naruv_inventory.warehouses WHERE warehouse_id='QA-SAME-WH') IS DISTINCT FROM 'Synthetic b' THEN RAISE EXCEPTION 'OTHER_TENANT_CHANGED'; END IF; n:=n+1;
 IF n<>22 THEN RAISE EXCEPTION 'COUNT'; END IF;
END $r$;
RESET ROLE;
SET LOCAL ROLE jw_auth_stage_v85;
DO $r$ BEGIN IF NOT jw_dev.v85_auth_revoke_session(repeat('a',64)) THEN RAISE EXCEPTION 'REVOKE'; END IF; END $r$;
RESET ROLE;
SET LOCAL ROLE naruv_native_owner;
DO $r$ BEGIN
 PERFORM set_config('jw.session_hash',repeat('a',64),true);
 IF EXISTS(SELECT 1 FROM naruv_inventory.warehouses WHERE warehouse_id='QA-SAME-WH') OR EXISTS(SELECT 1 FROM naruv_accounting.periods WHERE org_id IN ('qa-rls-a','qa-rls-b')) THEN RAISE EXCEPTION 'REVOKED_VISIBLE'; END IF;
 PERFORM set_config('jw.session_hash',repeat('b',64),true);
 IF (SELECT count(*) FROM naruv_inventory.warehouses WHERE warehouse_id='QA-SAME-WH')<>1 OR (SELECT count(*) FROM naruv_accounting.periods WHERE org_id='qa-rls-b')<>1 THEN RAISE EXCEPTION 'OTHER_TENANT_REVOKED'; END IF;
END $r$;
RESET ROLE;
SET CONSTRAINTS ALL IMMEDIATE;
SELECT 'HOSTED_POPULATED_RLS_REVIEW_PASS' AS verdict,2 AS populated_tables,2 AS populated_tenants,22 AS isolation_assertions,4 AS revocation_assertions,false AS independent_login,false AS committed_workload;
ROLLBACK;