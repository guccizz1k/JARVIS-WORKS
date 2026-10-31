-- V17.7 REAL Supabase DEV (43 FORCE RLS, 62 policies) rollback-only acceptance.
-- Never execute against production. No lasting finance, company or audit rows.
-- Restricted jw_app_dev posts normal linked records; owner checks audit READ
-- only after RESET ROLE. Payment function is not proof of bank settlement.
BEGIN;
SET LOCAL lock_timeout='1500ms';
SET LOCAL statement_timeout='30s';
DO $guard$
BEGIN
 IF current_database()<>'postgres'
 OR (SELECT count(*) FROM pg_policies WHERE schemaname='jw_dev')<>62
 OR (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
     WHERE n.nspname='jw_dev' AND c.relkind='r'
       AND c.relrowsecurity AND c.relforcerowsecurity)<>43
 OR EXISTS(SELECT 1 FROM jw_dev.organizations)
 OR EXISTS(SELECT 1 FROM jw_dev.sessions)
 OR EXISTS(SELECT 1 FROM jw_dev.quotes)
 OR EXISTS(SELECT 1 FROM jw_dev.orders)
 OR EXISTS(SELECT 1 FROM jw_dev.invoices)
 OR EXISTS(SELECT 1 FROM jw_dev.payments)
 OR EXISTS(SELECT 1 FROM jw_dev.audit_logs)
 THEN RAISE EXCEPTION 'BLOCKED_V177_NONEMPTY_OR_WRONG_DATABASE'; END IF;
END $guard$;
INSERT INTO jw_dev.organizations(id,name,created_at)
 VALUES('jw-v177-orga','V177 Synthetic A',now()::text),
 ('jw-v177-orgb','V177 Synthetic B',now()::text);
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at)
 VALUES('jw-v177-ua','jw-v177-orga','v177-a@invalid.test','synthetic','Admin A','admin',now()::text),
 ('jw-v177-ub','jw-v177-orgb','v177-b@invalid.test','synthetic','Admin B','admin',now()::text);
INSERT INTO jw_dev.sessions(token_hash,user_id,expires_at,csrf_token,created_at)
 VALUES('83aa26c07d7521f829c9ccba6696f865405ad114f455657fbb61b49c49f89bef',
 'jw-v177-ua',(now()+interval '30 minutes')::text,'v177-synthetic-csrf',now()::text);
INSERT INTO jw_dev.customers(id,org_id,name,created_at)
 VALUES('jw-v177-ca','jw-v177-orga','Synthetic A',now()::text),
 ('jw-v177-cb','jw-v177-orgb','Synthetic B',now()::text);
INSERT INTO jw_dev.quotes(id,org_id,customer_id,customer_name_snapshot,
 doc_no,title,status,vat_mode,created_at,updated_at)
 VALUES(repeat('a',32),'jw-v177-orga','jw-v177-ca','Synthetic A',
 'V177-Q-A','Finance A','draft','taxable',now()::text,now()::text),
 (repeat('b',32),'jw-v177-orgb','jw-v177-cb','Synthetic B',
 'V177-Q-B','Finance B','draft','taxable',now()::text,now()::text);
INSERT INTO jw_dev.quote_items(id,quote_id,name,quantity,unit_price,position)
 VALUES(repeat('c',32),repeat('a',32),'Item A',2,3500,0),
 (repeat('d',32),repeat('b',32),'Item B',2,3500,0);
SET LOCAL ROLE jw_app_dev;
SELECT pg_catalog.set_config('jw.session_hash',
 '83aa26c07d7521f829c9ccba6696f865405ad114f455657fbb61b49c49f89bef',true);
DO $restricted$
DECLARE org text;actor text;first_payment text;replay_payment text;
 denied boolean:=false;
BEGIN
 SELECT org_id,actor_id INTO org,actor FROM jw_dev.stage_identity_v84();
 IF org<>'jw-v177-orga' OR actor<>'jw-v177-ua'
 THEN RAISE EXCEPTION 'FAIL_V177_WRONG_RESTRICTED_IDENTITY'; END IF;
 INSERT INTO jw_dev.quote_review_receipts_v128
 (id,org_id,actor_id,quote_id,source_sha256,created_epoch)
 VALUES(repeat('e',32),org,actor,repeat('a',32),
 repeat('f',64),extract(epoch from now())::bigint);
 INSERT INTO jw_dev.order_drafts_v127
 (id,org_id,customer_id,quote_id,customer_name_snapshot,doc_no,title,
 status,review_state,vat_mode,due_date,created_at,updated_at,
 order_date,source_import_id,source_document_meta)
 VALUES(repeat('1',32),org,'jw-v177-ca',repeat('a',32),
 'Synthetic A','V177-OD-A','Finance A','draft','preview_acknowledged',
 'taxable','',now()::text,now()::text,now()::date::text,
 'v177:isolated-review','{"internal_only":true}');
 INSERT INTO jw_dev.order_draft_items_v127
 (id,order_id,source_quote_item_id,name,quantity,unit_price,position)
 VALUES(repeat('2',32),repeat('1',32),repeat('c',32),'Item A',2,3500,0);
 INSERT INTO jw_dev.orders
 (id,org_id,customer_id,quote_id,customer_name_snapshot,
 doc_no,title,status,review_state,vat_mode,due_date,
 created_at,updated_at,order_date,source_import_id,source_document_meta)
 VALUES(repeat('3',32),org,'jw-v177-ca',repeat('a',32),
 'Synthetic A','V177-O-A','Finance A','received','acknowledged',
 'taxable','',now()::text,now()::text,now()::date::text,
 'v177:isolated-order','{"physical_delivery_verified":false}');
 INSERT INTO jw_dev.order_items
 (id,order_id,source_quote_item_id,name,quantity,unit_price,position)
 VALUES(repeat('4',32),repeat('3',32),repeat('c',32),'Item A',2,3500,0);
 UPDATE jw_dev.orders SET status='processing',updated_at=now()::text
 WHERE id=repeat('3',32);
 UPDATE jw_dev.orders SET status='fulfilled',updated_at=now()::text
 WHERE id=repeat('3',32);
 INSERT INTO jw_dev.invoices
 (id,org_id,order_id,customer_id,customer_name_snapshot,doc_no,
 status,vat_mode,due_date,created_at)
 VALUES(repeat('5',32),org,repeat('3',32),'jw-v177-ca',
 'Synthetic A','V177-I-A','issued','taxable','',now()::text);
 INSERT INTO jw_dev.invoice_items
 (id,invoice_id,source_order_item_id,name,quantity,unit_price,position)
 VALUES(repeat('6',32),repeat('5',32),repeat('4',32),'Item A',2,3500,0);
 SELECT jw_dev.record_payment_v83(
 repeat('5',32),7700,CURRENT_DATE,'V177_TEST_PAYMENT_001','SYNTHETIC_NOT_BANK_SETTLEMENT'
 ) INTO first_payment;
 IF first_payment IS NULL THEN RAISE EXCEPTION 'FAIL_V177_PAYMENT_NULL'; END IF;
 SELECT jw_dev.record_payment_v83(
 repeat('5',32),7700,CURRENT_DATE,'V177_TEST_PAYMENT_001','SYNTHETIC_NOT_BANK_SETTLEMENT'
 ) INTO replay_payment;
 IF replay_payment<>first_payment THEN RAISE EXCEPTION 'FAIL_V177_DOUBLE_PAYMENT'; END IF;
 BEGIN
 PERFORM jw_dev.record_payment_v83(
 repeat('5',32),1,CURRENT_DATE,'V177_TEST_PAYMENT_002','SYNTHETIC_NOT_BANK_SETTLEMENT');
 EXCEPTION WHEN check_violation THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL_V177_OVERPAYMENT_ACCEPTED'; END IF;
 IF (SELECT count(*) FROM jw_dev.payments WHERE invoice_id=repeat('5',32))<>1
 OR (SELECT count(*) FROM jw_dev.invoice_items WHERE invoice_id=repeat('5',32))<>1
 OR (SELECT count(*) FROM jw_dev.orders WHERE id=repeat('3',32) AND status='fulfilled')<>1
 THEN RAISE EXCEPTION 'FAIL_V177_RESTRICTED_LINEAGE'; END IF;
 -- Intentionally DO NOT SELECT audit_logs under jw_app_dev; audit is INSERT-only.
END $restricted$;
RESET ROLE;
DO $owner_verify$
DECLARE payment_id text;
BEGIN
 SELECT id INTO payment_id FROM jw_dev.payments
 WHERE invoice_id=repeat('5',32) AND reference='V177_TEST_PAYMENT_001';
 IF payment_id IS NULL OR
 (SELECT count(*) FROM jw_dev.audit_logs
 WHERE entity_id=payment_id AND action='create')<>1
 OR (SELECT count(*) FROM jw_dev.payments)<>1
 OR (SELECT count(*) FROM jw_dev.invoices)<>1
 OR (SELECT count(*) FROM jw_dev.orders)<>1
 THEN RAISE EXCEPTION 'FAIL_V177_OWNER_INDEPENDENT_AUDIT'; END IF;
END $owner_verify$;
ROLLBACK;
SELECT 'PASS_V177_REAL_DEV_ADMIN_RESTRICTED_QUOTE_ORDER_INVOICE_PAYMENT_RPC_IDEMPOTENT_ROLLBACK' AS verdict;
