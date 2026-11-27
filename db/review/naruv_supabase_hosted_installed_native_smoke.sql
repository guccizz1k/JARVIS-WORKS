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
 OR EXISTS(SELECT 1 FROM jw_dev.organizations WHERE id IN ('qa-hosted-a','qa-hosted-b','qa-hosted-c'))
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('jw_ci_trade','naruv_ci_ingest','naruv_v85_cutover_ci') AND rolcanlogin)
 THEN RAISE EXCEPTION 'HOSTED_NATIVE_SMOKE_SCOPE'; END IF;
END $g$;
INSERT INTO jw_dev.organizations(id,name,created_at) VALUES
 ('qa-hosted-a','Synthetic QA A',clock_timestamp()::text),('qa-hosted-b','Synthetic QA B',clock_timestamp()::text),('qa-hosted-c','Synthetic QA C',clock_timestamp()::text);
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES
 ('qa-hosted-ua','qa-hosted-a','qa-a@invalid.test','synthetic-unused','QA A','admin',clock_timestamp()::text),
 ('qa-hosted-ub','qa-hosted-b','qa-b@invalid.test','synthetic-unused','QA B','admin',clock_timestamp()::text),
 ('qa-hosted-uc','qa-hosted-c','qa-c@invalid.test','synthetic-unused','QA C','admin',clock_timestamp()::text);
INSERT INTO jw_dev.messenger_companies(org_id,business_number) VALUES
 ('qa-hosted-a','synthetic-qa-a'),('qa-hosted-b','synthetic-qa-b'),('qa-hosted-c','synthetic-qa-c');
SET LOCAL ROLE naruv_hid_owner;
CREATE POLICY qa_seed_org_rollback ON naruv_hosted_identity_review.organizations FOR INSERT TO naruv_hid_owner WITH CHECK (id IN ('qa-hosted-a','qa-hosted-b','qa-hosted-c'));
CREATE POLICY qa_seed_actor_rollback ON naruv_hosted_identity_review.users FOR INSERT TO naruv_hid_owner WITH CHECK ((id,org_id) IN (('qa-hosted-ua','qa-hosted-a'),('qa-hosted-ub','qa-hosted-b'),('qa-hosted-uc','qa-hosted-c')));
INSERT INTO naruv_hosted_identity_review.organizations(id,name) VALUES
 ('qa-hosted-a','Synthetic QA A'),('qa-hosted-b','Synthetic QA B'),('qa-hosted-c','Synthetic QA C');
INSERT INTO naruv_hosted_identity_review.users(id,org_id,actor_role,active,epoch) VALUES
 ('qa-hosted-ua','qa-hosted-a','admin',true,0),('qa-hosted-ub','qa-hosted-b','admin',true,0),('qa-hosted-uc','qa-hosted-c','admin',true,0);
DROP POLICY qa_seed_org_rollback ON naruv_hosted_identity_review.organizations;
DROP POLICY qa_seed_actor_rollback ON naruv_hosted_identity_review.users;
RESET ROLE;
SET LOCAL ROLE jw_auth_stage_v85;
DO $t$ BEGIN
 IF jw_dev.v85_auth_issue_session('qa-hosted-ua',repeat('a',64),repeat('c',32),NULL,NULL) IS NULL
 OR jw_dev.v85_auth_issue_session('qa-hosted-ub',repeat('b',64),repeat('d',32),NULL,NULL) IS NULL
 OR jw_dev.v85_auth_issue_session('qa-hosted-uc',repeat('e',64),repeat('f',32),NULL,NULL) IS NULL
 THEN RAISE EXCEPTION 'HOSTED_ISSUE'; END IF;
 IF NOT jw_dev.v85_auth_check_csrf(repeat('a',64),repeat('c',32)) OR jw_dev.v85_auth_check_csrf(repeat('a',64),repeat('d',32)) THEN RAISE EXCEPTION 'HOSTED_CSRF'; END IF;
 BEGIN PERFORM jw_dev.v85_issue_native_ci(NULL,NULL,NULL,NULL,NULL); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $t$;
RESET ROLE;
SET LOCAL ROLE jw_app_dev;
DO $t$ DECLARE chat text; m record; retry record; BEGIN
 PERFORM set_config('jw.session_hash',repeat('a',64),true);
 IF (SELECT count(*) FROM jw_dev.stage_identity_v84() WHERE org_id='qa-hosted-a' AND actor_id='qa-hosted-ua')<>1 THEN RAISE EXCEPTION 'HOSTED_IDENTITY'; END IF;
 chat:=jw_dev.v90_start_chat('qa-hosted-b');
 SELECT * INTO m FROM jw_dev.v90_send_text(chat,'qa-native-msg-001','synthetic native message',NULL,NULL,NULL);
 IF m.replayed OR m.message_id IS NULL THEN RAISE EXCEPTION 'HOSTED_SEND'; END IF;
 SELECT * INTO retry FROM jw_dev.v90_send_text(chat,'qa-native-msg-001','synthetic native message',NULL,NULL,NULL);
 IF NOT retry.replayed OR (retry.message_id,retry.message_cursor) IS DISTINCT FROM (m.message_id,m.message_cursor) THEN RAISE EXCEPTION 'HOSTED_REPLAY'; END IF;
 IF jw_dev.v90_edit_text(m.message_id,'edited synthetic message',1)<>2 THEN RAISE EXCEPTION 'HOSTED_EDIT'; END IF;
 PERFORM set_config('naruv.qa_chat',chat,true);
 PERFORM set_config('naruv.qa_message',m.message_id,true);
 PERFORM set_config('naruv.qa_cursor',m.message_cursor::text,true);
 BEGIN PERFORM body FROM jw_dev.messenger_messages; RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 -- Management connection MUST NOT be allowed to impersonate an independent ERP login.
 BEGIN PERFORM naruv_valuation.audit_ledger(repeat('c',32)); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $t$;
DO $t$ DECLARE chat text:=current_setting('naruv.qa_chat'); message text:=current_setting('naruv.qa_message'); cursor_id bigint:=current_setting('naruv.qa_cursor')::bigint; BEGIN
 PERFORM set_config('jw.session_hash',repeat('b',64),true);
 IF (SELECT count(*) FROM jw_dev.v90_sync_messages(chat,0,100) WHERE message_id=message AND body='edited synthetic message' AND version=2)<>1 THEN RAISE EXCEPTION 'HOSTED_SYNC'; END IF;
 IF jw_dev.v90_mark_read(chat,cursor_id)<>cursor_id THEN RAISE EXCEPTION 'HOSTED_CURSOR'; END IF;
 BEGIN PERFORM jw_dev.v90_edit_text(message,'unauthorized',2); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 PERFORM set_config('jw.session_hash',repeat('e',64),true);
 BEGIN PERFORM * FROM jw_dev.v90_sync_messages(chat,0,100); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM jw_dev.v90_send_text(chat,'qa-native-msg-002','unauthorized',NULL,NULL,NULL); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $t$;
RESET ROLE;
SET LOCAL ROLE jw_auth_stage_v85;
DO $t$ BEGIN
 IF NOT jw_dev.v85_auth_revoke_session(repeat('a',64)) OR jw_dev.v85_auth_check_csrf(repeat('a',64),repeat('c',32)) OR NOT jw_dev.v85_auth_check_csrf(repeat('b',64),repeat('d',32)) THEN RAISE EXCEPTION 'HOSTED_REVOKE'; END IF;
END $t$;
RESET ROLE;
SET LOCAL ROLE jw_app_dev;
DO $t$ BEGIN
 PERFORM set_config('jw.session_hash',repeat('a',64),true);
 IF EXISTS(SELECT 1 FROM jw_dev.stage_identity_v84()) THEN RAISE EXCEPTION 'HOSTED_REVOKED_IDENTITY'; END IF;
 BEGIN PERFORM jw_dev.v90_send_text(current_setting('naruv.qa_chat'),'qa-native-msg-003','revoked',NULL,NULL,NULL); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $t$;
RESET ROLE;
SET CONSTRAINTS ALL IMMEDIATE;
SELECT 'HOSTED_INSTALLED_NATIVE_AUTH_MESSENGER_REVIEW_PASS' AS result,3 AS synthetic_tenants,3 AS issued_sessions,1 AS exact_replay,1 AS edited_message,1 AS read_cursor,7 AS denied_operations,1 AS revoked_session,false AS actual_independent_login,false AS production_authorized;
ROLLBACK;