-- REVIEW ONLY. Real owner-approved DEV PostgreSQL17, synthetic fixture; never execute in production.
-- V9.9 REAL Supabase jw_dev review ONLY (actual DEV project rvymwwzclagvljnofyss).
-- No COMMIT, no DDL, no secrets, no customer rows copied.
-- Run only against the verified-empty dev schema with authorized owner approval.
-- Never run on main/live production; always inspect the rollback and residual check.
BEGIN;

-- V13.1 real PG17 financial review extension: immutable synthetic transaction, no COMMIT.
DO $extra_empty_guard$
BEGIN
 IF (SELECT count(*) FROM jw_dev.invoices)<>0
 OR (SELECT count(*) FROM jw_dev.payments)<>0
 OR (SELECT count(*) FROM jw_dev.audit_logs)<>0
 THEN RAISE EXCEPTION 'FINANCE_REVIEW_MUST_START_EMPTY'; END IF;
END $extra_empty_guard$;

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

-- Continue existing A/B/C fixture, reverting to admin solely for creating synthetic fixture rows.
RESET ROLE;
INSERT INTO jw_dev.quote_items(id,quote_id,name,quantity,unit_price,position) VALUES
('jw-v131-qi-a','jw-v99-ext-qa','A fixture item',2,1000,0),
('jw-v131-qi-b','jw-v99-ext-qb','B fixture item',1,9000,0);
INSERT INTO jw_dev.order_items(id,order_id,source_quote_item_id,name,quantity,unit_price,position) VALUES
('jw-v131-oi-a','jw-v99-ext-oa','jw-v131-qi-a','A fixture item',2,1000,0),
('jw-v131-oi-b','jw-v99-ext-ob','jw-v131-qi-b','B fixture item',1,9000,0);
DO $no_early_invoice$
DECLARE denied boolean:=false;
BEGIN
 BEGIN
  INSERT INTO jw_dev.invoices(id,org_id,order_id,customer_id,customer_name_snapshot,doc_no,status,vat_mode,due_date,created_at)
  VALUES('jw-v131-early','jw-v99-ext-a','jw-v99-ext-oa','jw-v99-ext-ca','Synthetic A','JW131-EARLY','issued','taxable','',clock_timestamp()::text);
 EXCEPTION WHEN SQLSTATE '23514' THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'EARLY_INVOICE_ACCEPTED'; END IF;
END $no_early_invoice$;
UPDATE jw_dev.orders SET status='processing',updated_at=clock_timestamp()::text WHERE id IN ('jw-v99-ext-oa','jw-v99-ext-ob');
UPDATE jw_dev.orders SET status='fulfilled',updated_at=clock_timestamp()::text WHERE id IN ('jw-v99-ext-oa','jw-v99-ext-ob');
INSERT INTO jw_dev.invoices(id,org_id,order_id,customer_id,customer_name_snapshot,doc_no,status,vat_mode,due_date,created_at) VALUES
('jw-v131-ia','jw-v99-ext-a','jw-v99-ext-oa','jw-v99-ext-ca','Synthetic A','JW131-IA','issued','taxable','',clock_timestamp()::text),
('jw-v131-ib','jw-v99-ext-b','jw-v99-ext-ob','jw-v99-ext-cb','Synthetic B','JW131-IB','issued','taxable','',clock_timestamp()::text);
INSERT INTO jw_dev.invoice_items(id,invoice_id,source_order_item_id,name,quantity,unit_price,position) VALUES
('jw-v131-ii-a','jw-v131-ia','jw-v131-oi-a','A fixture item',2,1000,0),
('jw-v131-ii-b','jw-v131-ib','jw-v131-oi-b','B fixture item',1,9000,0);
SET LOCAL ROLE jw_app_dev;
DO $finance$
DECLARE first_payment text; replay_payment text; b_payment text; last_payment text; n int; active_amount bigint; denied boolean;
BEGIN
 IF pg_catalog.has_function_privilege('jw_app_dev','jw_dev.financial_state_v83(text)','EXECUTE') THEN
  RAISE EXCEPTION 'FINANCE_INTERNAL_STATE_PUBLICLY_CALLABLE'; END IF;
 PERFORM pg_catalog.set_config('jw.session_hash','jw-v99-ext-hash-a',true);
 IF (SELECT count(*) FROM jw_dev.invoices WHERE id LIKE 'jw-v131-%')<>1 THEN
  RAISE EXCEPTION 'A_INVOICE_ISOLATION_FAILED'; END IF;
 SELECT jw_dev.record_payment_v83('jw-v131-ia',1000,current_date,'jw131-a-ref1','synthetic') INTO first_payment;
 SELECT jw_dev.record_payment_v83('jw-v131-ia',1000,current_date,'jw131-a-ref1','synthetic') INTO replay_payment;
 IF first_payment IS NULL OR replay_payment IS DISTINCT FROM first_payment THEN
  RAISE EXCEPTION 'PAYMENT_REPLAY_NOT_IDEMPOTENT'; END IF;
 IF (SELECT count(*) FROM jw_dev.payments WHERE invoice_id='jw-v131-ia')<>1 THEN
  RAISE EXCEPTION 'DUPLICATE_PAYMENT'; END IF;
 denied:=false;
 BEGIN
  PERFORM jw_dev.record_payment_v83('jw-v131-ia',2000,current_date,'jw131-a-overpay','synthetic');
 EXCEPTION WHEN SQLSTATE '23514' THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'OVERPAYMENT_ACCEPTED'; END IF;
 denied:=false;
 BEGIN
  PERFORM jw_dev.record_payment_v83('jw-v131-ib',1000,current_date,'jw131-a-forged','synthetic');
 EXCEPTION WHEN SQLSTATE '42501' THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FOREIGN_INVOICE_PAYMENT_ACCEPTED'; END IF;
 PERFORM pg_catalog.set_config('jw.session_hash','jw-v99-ext-hash-b',true);
 IF (SELECT count(*) FROM jw_dev.invoices WHERE id LIKE 'jw-v131-%')<>1 THEN
  RAISE EXCEPTION 'B_INVOICE_ISOLATION_FAILED'; END IF;
 SELECT jw_dev.record_payment_v83('jw-v131-ib',9900,current_date,'jw131-b-ref1','synthetic') INTO b_payment;
 IF b_payment IS NULL OR (SELECT count(*) FROM jw_dev.payments WHERE id=first_payment)<>0 THEN
  RAISE EXCEPTION 'B_PAYMENT_ISOLATION_FAILED'; END IF;
 PERFORM pg_catalog.set_config('jw.session_hash','jw-v99-ext-hash-c',true);
 IF (SELECT count(*) FROM jw_dev.invoices WHERE id LIKE 'jw-v131-%')<>0 THEN
  RAISE EXCEPTION 'C_INVOICE_ISOLATION_FAILED'; END IF;
 denied:=false;
 BEGIN
  PERFORM jw_dev.record_payment_v83('jw-v131-ia',1000,current_date,'jw131-c-forged','synthetic');
 EXCEPTION WHEN SQLSTATE '42501' THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'C_FOREIGN_PAYMENT_ACCEPTED'; END IF;
 PERFORM pg_catalog.set_config('jw.session_hash','jw-v99-ext-hash-unknown',true);
 denied:=false;
 BEGIN
  PERFORM jw_dev.record_payment_v83('jw-v131-ia',1000,current_date,'jw131-unknown','synthetic');
 EXCEPTION WHEN SQLSTATE '42501' THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'UNKNOWN_SESSION_PAYMENT_ACCEPTED'; END IF;
 PERFORM pg_catalog.set_config('jw.session_hash','jw-v99-ext-hash-a',true);
 IF (SELECT count(*) FROM jw_dev.payments WHERE id=b_payment)<>0 THEN
  RAISE EXCEPTION 'A_PAYMENT_ISOLATION_FAILED'; END IF;
 IF jw_dev.reverse_payment_v83('jw-v131-ia',first_payment) IS DISTINCT FROM TRUE THEN
  RAISE EXCEPTION 'PAYMENT_REVERSAL_NOT_APPLIED'; END IF;
 IF (SELECT count(*) FROM jw_dev.payments WHERE invoice_id='jw-v131-ia' AND reversed_at IS NULL)<>0 THEN
  RAISE EXCEPTION 'REVERSED_PAYMENT_ACTIVE'; END IF;
 denied:=false;
 BEGIN
  PERFORM jw_dev.record_payment_v83('jw-v131-ia',1000,current_date,'jw131-a-ref1','synthetic');
 EXCEPTION WHEN SQLSTATE '23514' THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'REVERSED_KEY_REUSED'; END IF;
 SELECT jw_dev.record_payment_v83('jw-v131-ia',2200,current_date,'jw131-a-final','synthetic') INTO last_payment;
 IF last_payment IS NULL THEN RAISE EXCEPTION 'FINAL_PAYMENT_NOT_APPLIED'; END IF;
 SELECT COALESCE(sum(amount),0)::bigint INTO active_amount FROM jw_dev.payments
 WHERE invoice_id='jw-v131-ia' AND reversed_at IS NULL;
 IF active_amount<>2200 THEN RAISE EXCEPTION 'ACTIVE_BALANCE_MISMATCH'; END IF;
END $finance$;
RESET ROLE;
ROLLBACK;
SELECT CASE WHEN EXISTS (SELECT 1 FROM jw_dev.organizations WHERE id LIKE 'jw-v99-ext-%')
OR EXISTS (SELECT 1 FROM jw_dev.orders WHERE id LIKE 'jw-v99-ext-%')
OR EXISTS (SELECT 1 FROM jw_dev.messenger_messages WHERE id LIKE 'jw-v99-ext-%')
OR EXISTS (SELECT 1 FROM jw_dev.invoices WHERE id LIKE 'jw-v131-%')
OR EXISTS (SELECT 1 FROM jw_dev.payments WHERE reference LIKE 'jw131-%')
OR EXISTS (SELECT 1 FROM jw_dev.audit_logs WHERE entity_id LIKE 'jw-v131-%')
THEN 'FAIL_RESIDUAL_FIXTURES'
ELSE 'PASS_REAL_V131_ABC_FINANCE_RLS_PAYMENT_REVERSAL_ROLLBACK'
END AS verdict;
