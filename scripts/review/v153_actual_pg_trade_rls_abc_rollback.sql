-- V15.3 restricted trade role REAL PG test, requires wrapped BEGIN/ROLLBACK
-- and V15.2 DDL plus prior V15.1 synthetic assertion fixtures.
-- NEVER COMMIT, never invoke customer-facing APIs.
INSERT INTO jw_dev.organizations(id,name,created_at) VALUES
 (repeat('a',32),'V153 Synthetic A',now()::text),
 (repeat('b',32),'V153 Synthetic B',now()::text);
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES
 (repeat('3',32),repeat('a',32),'v153-a@invalid.test','invalid-synthetic-only','User A','admin',now()::text),
 (repeat('4',32),repeat('b',32),'v153-b@invalid.test','invalid-synthetic-only','User B','admin',now()::text);
INSERT INTO jw_dev.sessions(token_hash,user_id,expires_at,csrf_token,created_at) VALUES
 ('jw-v153-a',repeat('3',32),(now()+interval '30 minutes')::text,'synthetic',now()::text),
 ('jw-v153-b',repeat('4',32),(now()+interval '30 minutes')::text,'synthetic',now()::text);
INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES
 (repeat('1',32),repeat('a',32),'V153 Customer A',now()::text),
 (repeat('2',32),repeat('b',32),'V153 Customer B',now()::text);
INSERT INTO jw_dev.quotes
 (id,org_id,customer_id,customer_name_snapshot,doc_no,title,status,
  vat_mode,created_at,updated_at)
 VALUES
 (repeat('e',32),repeat('a',32),repeat('1',32),'Synthetic A','V153QA','Review A','draft','taxable',now()::text,now()::text),
 (repeat('f',32),repeat('b',32),repeat('2',32),'Synthetic B','V153QB','Review B','draft','taxable',now()::text,now()::text);
INSERT INTO jw_dev.orders
 (id,org_id,customer_id,quote_id,customer_name_snapshot,doc_no,title,status,
  review_state,vat_mode,due_date,created_at,updated_at)
 VALUES
 (repeat('c',32),repeat('a',32),repeat('1',32),repeat('e',32),'Synthetic A','V153OA','Review A','fulfilled','acknowledged','taxable','',now()::text,now()::text),
 (repeat('d',32),repeat('b',32),repeat('2',32),repeat('f',32),'Synthetic B','V153OB','Review B','fulfilled','acknowledged','taxable','',now()::text,now()::text);
INSERT INTO jw_dev.order_items
 (id,order_id,name,quantity,unit_price,position)
 VALUES
 (repeat('5',32),repeat('c',32),'A synthetic',2,3500,0),
 (repeat('6',32),repeat('d',32),'B synthetic',2,3500,0);

SET LOCAL ROLE jw_app_dev;
SELECT pg_catalog.set_config('jw.session_hash','jw-v153-a',true);
DO $a$
BEGIN
 IF current_user <> 'jw_app_dev'
 OR jw_dev.current_org_from_session() <> repeat('a',32)
 OR (SELECT count(*) FROM jw_dev.stage_identity_v84() WHERE actor_role='admin')<>1
 THEN RAISE EXCEPTION 'FAIL_V153_A_SESSION'; END IF;
END $a$;

INSERT INTO jw_dev.review_delivery_receipts_v151
 (order_id,org_id,source_sha256,evidence_sha256,
  dispatch_document_sha256,recipient_document_sha256,
  dispatch_actor,recipient_actor,subtotal_krw,vat_krw,total_krw)
 VALUES(repeat('c',32),repeat('a',32),repeat('1',64),repeat('2',64),
        repeat('3',64),repeat('4',64),repeat('5',32),repeat('6',32),
        7000,700,7700);
INSERT INTO jw_dev.review_delivery_nonces_v151
 (nonce,order_id,purpose,issuer,proof_sha256)
 VALUES
 (repeat('7',32),repeat('c',32),'dispatch','synthetic-a-dispatch',repeat('8',64)),
 (repeat('9',32),repeat('c',32),'receipt','synthetic-a-receipt',repeat('a',64));
INSERT INTO jw_dev.review_delivery_items_v151
 (order_id,source_item_id,position,quantity,unit_price_krw)
 VALUES(repeat('c',32),repeat('5',32),0,2,3500);

DO $a_read$
BEGIN
 IF (SELECT count(*) FROM jw_dev.review_delivery_receipts_v151)<>1 OR
 (SELECT count(*) FROM jw_dev.review_delivery_nonces_v151)<>2 OR
 (SELECT count(*) FROM jw_dev.review_delivery_items_v151)<>1
 THEN RAISE EXCEPTION 'FAIL_V153_A_CANNOT_READ_WRITES'; END IF;
END $a_read$;

SELECT pg_catalog.set_config('jw.session_hash','jw-v153-b',true);
DO $b$
DECLARE refused boolean:=false;
BEGIN
 IF jw_dev.current_org_from_session()<>repeat('b',32)
 OR (SELECT count(*) FROM jw_dev.review_delivery_receipts_v151)<>0
 OR (SELECT count(*) FROM jw_dev.review_delivery_items_v151)<>0
 OR (SELECT count(*) FROM jw_dev.review_delivery_nonces_v151)<>0
 THEN RAISE EXCEPTION 'FAIL_V153_B_CROSS_TENANT_READ'; END IF;

 BEGIN
  INSERT INTO jw_dev.review_delivery_receipts_v151
   (order_id,org_id,source_sha256,evidence_sha256,
    dispatch_document_sha256,recipient_document_sha256,
    dispatch_actor,recipient_actor,subtotal_krw,vat_krw,total_krw)
  VALUES(repeat('d',32),repeat('a',32),repeat('1',64),repeat('b',64),
         repeat('3',64),repeat('4',64),repeat('5',32),repeat('6',32),
         7000,700,7700);
 EXCEPTION WHEN insufficient_privilege OR check_violation THEN refused:=true;
 END;
 IF NOT refused THEN RAISE EXCEPTION 'FAIL_V153_B_CROSS_TENANT_INSERT'; END IF;
END $b$;

INSERT INTO jw_dev.review_delivery_receipts_v151
 (order_id,org_id,source_sha256,evidence_sha256,
  dispatch_document_sha256,recipient_document_sha256,
  dispatch_actor,recipient_actor,subtotal_krw,vat_krw,total_krw)
 VALUES(repeat('d',32),repeat('b',32),repeat('b',64),repeat('c',64),
        repeat('3',64),repeat('4',64),repeat('5',32),repeat('6',32),
        7000,700,7700);

SELECT pg_catalog.set_config('jw.session_hash','jw-v153-unknown',true);
DO $unknown$
DECLARE refused boolean:=false;
BEGIN
 IF jw_dev.current_org_from_session() IS NOT NULL
 OR EXISTS (SELECT 1 FROM jw_dev.review_delivery_receipts_v151)
 THEN RAISE EXCEPTION 'FAIL_V153_UNKNOWN_SESSION_READ'; END IF;
 BEGIN
  INSERT INTO jw_dev.review_delivery_receipts_v151
   (order_id,org_id,source_sha256,evidence_sha256,
    dispatch_document_sha256,recipient_document_sha256,
    dispatch_actor,recipient_actor,subtotal_krw,vat_krw,total_krw)
  VALUES(repeat('f',32),repeat('b',32),repeat('a',64),repeat('d',64),
         repeat('3',64),repeat('4',64),repeat('5',32),repeat('6',32),
         7000,700,7700);
 EXCEPTION WHEN insufficient_privilege OR check_violation OR foreign_key_violation
 THEN refused:=true;
 END;
 IF NOT refused THEN RAISE EXCEPTION 'FAIL_V153_UNKNOWN_SESSION_INSERT'; END IF;
END $unknown$;
RESET ROLE;

DO $catalog$
DECLARE n int;
BEGIN
 SELECT count(*) INTO n FROM pg_policies WHERE schemaname='jw_dev'
  AND policyname LIKE 'v153_%';
 IF n<>6 THEN RAISE EXCEPTION 'FAIL_V153_POLICY_COUNT_%',n; END IF;
 SELECT count(*) INTO n FROM information_schema.role_table_grants
  WHERE table_schema='jw_dev' AND table_name LIKE 'review_%_v151'
   AND grantee IN ('PUBLIC','anon','authenticated');
 IF n<>0 THEN RAISE EXCEPTION 'FAIL_V153_PUBLIC_REVIEW_GRANTS_%',n; END IF;
 SELECT count(*) INTO n FROM pg_policies WHERE schemaname='jw_dev'
  AND tablename IN ('review_signup_requests_v151','review_signup_nonces_v151');
 IF n<>0 THEN RAISE EXCEPTION 'FAIL_V153_SIGNUP_POLICY_EXPOSED_%',n; END IF;
END $catalog$;
