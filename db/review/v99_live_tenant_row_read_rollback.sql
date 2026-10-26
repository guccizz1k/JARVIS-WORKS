-- V9.9 REAL Supabase jw_dev review ONLY (actual DEV project rvymwwzclagvljnofyss).
-- No COMMIT, no DDL, no secrets, no customer rows copied.
-- Run only against the verified-empty dev schema with authorized owner approval.
-- Never run on main/live production; always inspect the rollback and residual check.
BEGIN;
SET LOCAL statement_timeout='15s';
SET LOCAL lock_timeout='1000ms';
DO $guard$
BEGIN
 IF current_database()<>'postgres' OR
    (SELECT count(*) FROM jw_dev.organizations)<>0 OR
    (SELECT count(*) FROM jw_dev.users)<>0 OR
    (SELECT count(*) FROM jw_dev.messenger_messages)<>0
 THEN RAISE EXCEPTION 'V99 fixture must only run on empty isolated dev state';
 END IF;
END $guard$;
INSERT INTO jw_dev.organizations(id,name,created_at) VALUES
('jw-v99-ext-a','V99 Synthetic A',now()::text),
('jw-v99-ext-b','V99 Synthetic B',now()::text),
('jw-v99-ext-c','V99 Synthetic C',now()::text);
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES
('jw-v99-ext-ua','jw-v99-ext-a','v99-a2@invalid.test','synthetic-no-password','A','admin',now()::text),
('jw-v99-ext-ub','jw-v99-ext-b','v99-b2@invalid.test','synthetic-no-password','B','admin',now()::text),
('jw-v99-ext-uc','jw-v99-ext-c','v99-c2@invalid.test','synthetic-no-password','C','admin',now()::text);
INSERT INTO jw_dev.sessions(token_hash,user_id,expires_at,csrf_token,created_at) VALUES
('jw-v99-ext-hash-a','jw-v99-ext-ua',(now()+interval '1 hour')::text,'synthetic',now()::text),
('jw-v99-ext-hash-b','jw-v99-ext-ub',(now()+interval '1 hour')::text,'synthetic',now()::text),
('jw-v99-ext-hash-c','jw-v99-ext-uc',(now()+interval '1 hour')::text,'synthetic',now()::text);
INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES
('jw-v99-ext-ca','jw-v99-ext-a','Synthetic A',now()::text),
('jw-v99-ext-cb','jw-v99-ext-b','Synthetic B',now()::text);
INSERT INTO jw_dev.quotes(id,org_id,customer_id,customer_name_snapshot,doc_no,title,status,vat_mode,created_at,updated_at) VALUES
('jw-v99-ext-qa','jw-v99-ext-a','jw-v99-ext-ca','Synthetic A','V99-A','Synthetic A','draft','taxable',now()::text,now()::text),
('jw-v99-ext-qb','jw-v99-ext-b','jw-v99-ext-cb','Synthetic B','V99-B','Synthetic B','draft','taxable',now()::text,now()::text);
INSERT INTO jw_dev.orders(id,org_id,customer_id,quote_id,customer_name_snapshot,doc_no,title,status,review_state,vat_mode,due_date,created_at,updated_at) VALUES
('jw-v99-ext-oa','jw-v99-ext-a','jw-v99-ext-ca','jw-v99-ext-qa','Synthetic A','V99-OA','Synthetic A','received','clean','taxable','',now()::text,now()::text),
('jw-v99-ext-ob','jw-v99-ext-b','jw-v99-ext-cb','jw-v99-ext-qb','Synthetic B','V99-OB','Synthetic B','received','clean','taxable','',now()::text,now()::text);
INSERT INTO jw_dev.messenger_companies(org_id,business_number,verified_at,verification_kind) VALUES
('jw-v99-ext-a','1111111111',now()::text,'demo'),
('jw-v99-ext-b','2222222222',now()::text,'demo'),
('jw-v99-ext-c','3333333333',now()::text,'demo');
INSERT INTO jw_dev.messenger_connections(id,org_a,org_b,requester_org,status,created_at) VALUES
('jw-v99-ext-conn-ab','jw-v99-ext-a','jw-v99-ext-b','jw-v99-ext-a','active',now()::text),
('jw-v99-ext-conn-bc','jw-v99-ext-b','jw-v99-ext-c','jw-v99-ext-b','active',now()::text);
INSERT INTO jw_dev.messenger_messages(id,connection_id,sender_org,sender_user,kind,body,request_id,created_at) VALUES
('jw-v99-ext-msg-ab','jw-v99-ext-conn-ab','jw-v99-ext-a','jw-v99-ext-ua','text','synthetic AB','jw-v99-ext-request-ab',now()::text),
('jw-v99-ext-msg-bc','jw-v99-ext-conn-bc','jw-v99-ext-b','jw-v99-ext-ub','text','synthetic BC','jw-v99-ext-request-bc',now()::text);
SET LOCAL ROLE jw_app_dev;
SELECT set_config('jw.session_hash','jw-v99-ext-hash-a',true);
DO $rls$
DECLARE v INTEGER[];
BEGIN
SELECT ARRAY[
(SELECT count(*)::int FROM jw_dev.customers WHERE id LIKE 'jw-v99-ext-%'),
(SELECT count(*)::int FROM jw_dev.quotes WHERE id LIKE 'jw-v99-ext-%'),
(SELECT count(*)::int FROM jw_dev.orders WHERE id LIKE 'jw-v99-ext-%'),
(SELECT count(*)::int FROM jw_dev.messenger_messages WHERE id LIKE 'jw-v99-ext-%')
] INTO v;
IF v IS DISTINCT FROM ARRAY[1,1,1,1]::integer[] THEN
 RAISE EXCEPTION 'V99 RLS isolation failed for a';
END IF;
END $rls$;
SELECT set_config('jw.session_hash','jw-v99-ext-hash-b',true);
DO $rls$
DECLARE v INTEGER[];
BEGIN
SELECT ARRAY[
(SELECT count(*)::int FROM jw_dev.customers WHERE id LIKE 'jw-v99-ext-%'),
(SELECT count(*)::int FROM jw_dev.quotes WHERE id LIKE 'jw-v99-ext-%'),
(SELECT count(*)::int FROM jw_dev.orders WHERE id LIKE 'jw-v99-ext-%'),
(SELECT count(*)::int FROM jw_dev.messenger_messages WHERE id LIKE 'jw-v99-ext-%')
] INTO v;
IF v IS DISTINCT FROM ARRAY[1,1,1,2]::integer[] THEN
 RAISE EXCEPTION 'V99 RLS isolation failed for b';
END IF;
END $rls$;
SELECT set_config('jw.session_hash','jw-v99-ext-hash-c',true);
DO $rls$
DECLARE v INTEGER[];
BEGIN
SELECT ARRAY[
(SELECT count(*)::int FROM jw_dev.customers WHERE id LIKE 'jw-v99-ext-%'),
(SELECT count(*)::int FROM jw_dev.quotes WHERE id LIKE 'jw-v99-ext-%'),
(SELECT count(*)::int FROM jw_dev.orders WHERE id LIKE 'jw-v99-ext-%'),
(SELECT count(*)::int FROM jw_dev.messenger_messages WHERE id LIKE 'jw-v99-ext-%')
] INTO v;
IF v IS DISTINCT FROM ARRAY[0,0,0,1]::integer[] THEN
 RAISE EXCEPTION 'V99 RLS isolation failed for c';
END IF;
END $rls$;
SELECT set_config('jw.session_hash','jw-v99-ext-hash-unknown',true);
DO $rls$
DECLARE v INTEGER[];
BEGIN
SELECT ARRAY[
(SELECT count(*)::int FROM jw_dev.customers WHERE id LIKE 'jw-v99-ext-%'),
(SELECT count(*)::int FROM jw_dev.quotes WHERE id LIKE 'jw-v99-ext-%'),
(SELECT count(*)::int FROM jw_dev.orders WHERE id LIKE 'jw-v99-ext-%'),
(SELECT count(*)::int FROM jw_dev.messenger_messages WHERE id LIKE 'jw-v99-ext-%')
] INTO v;
IF v IS DISTINCT FROM ARRAY[0,0,0,0]::integer[] THEN
 RAISE EXCEPTION 'V99 RLS isolation failed for unknown';
END IF;
END $rls$;
RESET ROLE;
ROLLBACK;
SELECT CASE WHEN EXISTS (SELECT 1 FROM jw_dev.organizations WHERE id LIKE 'jw-v99-ext-%')
OR EXISTS (SELECT 1 FROM jw_dev.orders WHERE id LIKE 'jw-v99-ext-%')
OR EXISTS (SELECT 1 FROM jw_dev.messenger_messages WHERE id LIKE 'jw-v99-ext-%')
THEN 'FAIL_RESIDUAL_FIXTURES'
ELSE 'PASS_A_B_C_CUSTOMER_QUOTE_ORDER_MESSAGE_AND_ROLLBACK'
END AS verdict;
