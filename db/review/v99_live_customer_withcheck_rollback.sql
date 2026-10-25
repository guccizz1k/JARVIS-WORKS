-- V9.9: real jw_dev RLS WITH CHECK tested in one rolled-back dev-only transaction.
-- No production schema write/DDL, no COMMIT, no passwords/real users.
BEGIN;
SET LOCAL statement_timeout='10s';
SET LOCAL lock_timeout='1000ms';
DO $guard$
BEGIN
 IF current_database()<>'postgres' OR
 (SELECT count(*) FROM jw_dev.organizations)<>0
 THEN RAISE EXCEPTION 'V99 rejects nonempty or unexpected development database';
 END IF;
END $guard$;
INSERT INTO jw_dev.organizations(id,name,created_at) VALUES
('jw-v99-withcheck-a','Test A',now()::text),('jw-v99-withcheck-b','Test B',now()::text);
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES
('jw-v99-withcheck-ua','jw-v99-withcheck-a','v99check-a@invalid.test','synthetic-only','A','admin',now()::text);
INSERT INTO jw_dev.sessions(token_hash,user_id,expires_at,csrf_token,created_at) VALUES
('jw-v99-withcheck-hash-a','jw-v99-withcheck-ua',(now()+interval '1 hour')::text,'synthetic',now()::text);
SET LOCAL ROLE jw_app_dev;
SELECT set_config('jw.session_hash','jw-v99-withcheck-hash-a',true);
DO $deny$
DECLARE state TEXT; blocked BOOLEAN:=false;
BEGIN
BEGIN
INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES
('jw-v99-withcheck-forge','jw-v99-withcheck-b','Forbidden customer',now()::text);
EXCEPTION WHEN SQLSTATE '42501' THEN
GET STACKED DIAGNOSTICS state=RETURNED_SQLSTATE;
blocked:=(state='42501');
END;
IF NOT blocked THEN RAISE EXCEPTION 'V99 foreign tenant customer INSERT was not rejected by RLS'; END IF;
END $deny$;
RESET ROLE;
ROLLBACK;
SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM jw_dev.organizations WHERE id LIKE 'jw-v99-withcheck-%')
AND NOT EXISTS (SELECT 1 FROM jw_dev.customers WHERE id LIKE 'jw-v99-withcheck-%')
THEN 'PASS_CROSS_ORG_CUSTOMER_INSERT_RLS_DENIED_AND_ROLLED_BACK'
ELSE 'FAIL_RESIDUAL_FIXTURE' END AS verdict;
