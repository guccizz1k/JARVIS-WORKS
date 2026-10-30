-- V15.1 TEST-ONLY ASSERTIONS, must be run BETWEEN BEGIN; + reviewed DDL + ROLLBACK;.
-- Synthetic data only; requires an empty authorized DEV schema, no COMMIT.
-- The test intentionally exercises normal ledger data, no real approval.
INSERT INTO jw_dev.organizations(id,name,created_at)
 VALUES('jw-v151-org','V151 synthetic company',now()::text);
INSERT INTO jw_dev.customers(id,org_id,name,created_at)
 VALUES('jw-v151-customer','jw-v151-org','V151 synthetic customer',now()::text);
INSERT INTO jw_dev.quotes(id,org_id,customer_id,customer_name_snapshot,
 doc_no,title,status,vat_mode,created_at,updated_at)
 VALUES('jw-v151-quote','jw-v151-org','jw-v151-customer',
 'V151 synthetic customer','V151-Q','Synthetic only','draft','taxable',
 now()::text,now()::text);
INSERT INTO jw_dev.orders(id,org_id,customer_id,quote_id,
 customer_name_snapshot,doc_no,title,status,review_state,vat_mode,
 due_date,created_at,updated_at)
 VALUES('jw-v151-order','jw-v151-org','jw-v151-customer','jw-v151-quote',
 'V151 synthetic customer','V151-O','Synthetic only','fulfilled',
 'acknowledged','taxable','',now()::text,now()::text);
INSERT INTO jw_dev.order_items(id,order_id,name,quantity,unit_price,position)
 VALUES('jw-v151-item','jw-v151-order','Synthetic item',2,3500,0);

INSERT INTO jw_dev.review_signup_requests_v151
  (request_id,company_name,email,business_number,intent_sha256)
 VALUES(repeat('a',32),'Synthetic Vendor','owner@invalid.test','1234567890',repeat('b',64));
INSERT INTO jw_dev.review_signup_nonces_v151
  (nonce,request_id,purpose,issuer,envelope_sha256,issued_at,expires_at)
 VALUES
 (repeat('c',32),repeat('a',32),'email_control','synthetic-email-test',
  repeat('d',64),now(),now()+interval '5 minutes'),
 (repeat('e',32),repeat('a',32),'business_control','synthetic-business-test',
  repeat('f',64),now(),now()+interval '5 minutes');

INSERT INTO jw_dev.review_delivery_receipts_v151
 (order_id,org_id,source_sha256,evidence_sha256,
  dispatch_document_sha256,recipient_document_sha256,
  dispatch_actor,recipient_actor,subtotal_krw,vat_krw,total_krw)
 VALUES('jw-v151-order','jw-v151-org',repeat('1',64),repeat('2',64),
 repeat('3',64),repeat('4',64),repeat('5',32),repeat('6',32),7000,700,7700);
INSERT INTO jw_dev.review_delivery_nonces_v151
 (nonce,order_id,purpose,issuer,proof_sha256)
 VALUES(repeat('7',32),'jw-v151-order','dispatch','synthetic-dispatch',repeat('8',64)),
       (repeat('9',32),'jw-v151-order','receipt','synthetic-receipt',repeat('a',64));
INSERT INTO jw_dev.review_delivery_items_v151
 (order_id,source_item_id,position,quantity,unit_price_krw)
 VALUES('jw-v151-order','jw-v151-item',0,2,3500);

DO $v151_assert$
DECLARE denied boolean;
BEGIN
 -- Attempts to reuse the same email/business or nonce must not succeed.
 denied:=false;
 BEGIN
  INSERT INTO jw_dev.review_signup_requests_v151
    (request_id,company_name,email,business_number,intent_sha256)
   VALUES(repeat('b',32),'Other Co','owner@invalid.test','9999999999',repeat('c',64));
 EXCEPTION WHEN unique_violation THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL_V151_DUPLICATE_EMAIL'; END IF;

 denied:=false;
 BEGIN
  INSERT INTO jw_dev.review_signup_requests_v151
    (request_id,company_name,email,business_number,intent_sha256)
   VALUES(repeat('b',32),'Other Co','other@invalid.test','1234567890',repeat('c',64));
 EXCEPTION WHEN unique_violation THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL_V151_DUPLICATE_BUSINESS'; END IF;

 denied:=false;
 BEGIN
  INSERT INTO jw_dev.review_signup_nonces_v151
    (nonce,request_id,purpose,issuer,envelope_sha256,issued_at,expires_at)
   VALUES(repeat('c',32),repeat('a',32),'business_control','synthetic',
          repeat('b',64),now(),now()+interval '1 minute');
 EXCEPTION WHEN unique_violation THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL_V151_NONCE_REPLAY'; END IF;

 denied:=false;
 BEGIN
  UPDATE jw_dev.review_signup_requests_v151 SET status='APPROVED'
   WHERE request_id=repeat('a',32);
 EXCEPTION WHEN check_violation OR insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL_V151_UNAUTHORIZED_SIGNUP_APPROVAL'; END IF;

 denied:=false;
 BEGIN
  UPDATE jw_dev.review_delivery_receipts_v151
   SET physical_delivery_verified=true WHERE order_id='jw-v151-order';
 EXCEPTION WHEN check_violation OR insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL_V151_PHYSICAL_DELIVERY_FORGED'; END IF;

 denied:=false;
 BEGIN
  UPDATE jw_dev.review_delivery_receipts_v151
   SET invoice_posted=true WHERE order_id='jw-v151-order';
 EXCEPTION WHEN check_violation OR insufficient_privilege THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL_V151_FINANCE_POSTING_FORGED'; END IF;

 denied:=false;
 BEGIN
  INSERT INTO jw_dev.review_delivery_nonces_v151
   (nonce,order_id,purpose,issuer,proof_sha256)
   VALUES(repeat('7',32),'jw-v151-order','receipt','synthetic',repeat('e',64));
 EXCEPTION WHEN unique_violation THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL_V151_DELIVERY_NONCE_REPLAY'; END IF;

 denied:=false;
 BEGIN
  INSERT INTO jw_dev.review_delivery_items_v151
   (order_id,source_item_id,position,quantity,unit_price_krw)
   VALUES('jw-v151-order','jw-v151-item',1,2,3500);
 EXCEPTION WHEN unique_violation OR check_violation THEN denied:=true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'FAIL_V151_DELIVERY_LINE_DUPLICATE'; END IF;

 IF (SELECT count(*) FROM jw_dev.review_signup_requests_v151)<>1
 OR (SELECT count(*) FROM jw_dev.review_signup_nonces_v151)<>2
 OR (SELECT count(*) FROM jw_dev.review_delivery_receipts_v151)<>1
 OR (SELECT count(*) FROM jw_dev.review_delivery_nonces_v151)<>2
 OR (SELECT count(*) FROM jw_dev.review_delivery_items_v151)<>1
 THEN RAISE EXCEPTION 'FAIL_V151_INVALID_TEST_LEFT_PARTIAL_DATA'; END IF;
END $v151_assert$;

DO $v151_source_assert$
DECLARE rejected boolean;
BEGIN
 rejected:=false;
 BEGIN
  INSERT INTO jw_dev.review_delivery_receipts_v151
    (order_id,org_id,source_sha256,evidence_sha256,
     dispatch_document_sha256,recipient_document_sha256,
     dispatch_actor,recipient_actor,subtotal_krw,vat_krw,total_krw)
   VALUES('jw-v151-order','jw-v151-foreign',repeat('1',64),repeat('b',64),
          repeat('3',64),repeat('4',64),repeat('5',32),repeat('6',32),
          7000,700,7700);
 EXCEPTION WHEN check_violation THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL_V151_FOREIGN_TENANT_ORDER'; END IF;

 rejected:=false;
 BEGIN
  INSERT INTO jw_dev.review_delivery_items_v151
    (order_id,source_item_id,position,quantity,unit_price_krw)
   VALUES('jw-v151-order','jw-v151-item',1,2,3500);
 EXCEPTION WHEN check_violation THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL_V151_WRONG_SOURCE_POSITION'; END IF;

 rejected:=false;
 BEGIN
  INSERT INTO jw_dev.review_delivery_items_v151
    (order_id,source_item_id,position,quantity,unit_price_krw)
   VALUES('jw-v151-order','jw-v151-item',0,3,3500);
 EXCEPTION WHEN check_violation THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL_V151_WRONG_SOURCE_QUANTITY'; END IF;

 rejected:=false;
 BEGIN
  INSERT INTO jw_dev.review_delivery_items_v151
    (order_id,source_item_id,position,quantity,unit_price_krw)
   VALUES('jw-v151-order','jw-v151-item',0,2,99999);
 EXCEPTION WHEN check_violation THEN rejected:=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL_V151_WRONG_SOURCE_PRICE'; END IF;

 IF EXISTS(
  SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname='jw_dev' AND p.proname IN
         ('v151_order_source_guard','v151_line_source_guard')
     AND (p.prosecdef OR EXISTS(
       SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
        WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
     ))
 ) THEN RAISE EXCEPTION 'FAIL_V151_PUBLIC_OR_DEFINER_TRIGGER'; END IF;
END $v151_source_assert$;


DO $v152_immutable$
DECLARE tab_name text; assign_expr text; refused boolean;
BEGIN
 FOR tab_name, assign_expr IN
 SELECT t, a FROM (VALUES
  ('review_signup_requests_v151','status=status'),
  ('review_signup_nonces_v151','purpose=purpose'),
  ('review_delivery_receipts_v151','org_id=org_id'),
  ('review_delivery_nonces_v151','purpose=purpose'),
  ('review_delivery_items_v151','position=position')
 ) AS source(t,a)
 LOOP
  refused:=false;
  BEGIN
   EXECUTE format('UPDATE jw_dev.%I SET %s', tab_name, assign_expr);
  EXCEPTION WHEN SQLSTATE '42501' THEN refused:=true;
  END;
  IF NOT refused THEN
   RAISE EXCEPTION 'FAIL_V152_EVIDENCE_UPDATE_ACCEPTED:%',tab_name;
  END IF;

  refused:=false;
  BEGIN
   EXECUTE format('DELETE FROM jw_dev.%I', tab_name);
  EXCEPTION WHEN SQLSTATE '42501' THEN refused:=true;
  END;
  IF NOT refused THEN
   RAISE EXCEPTION 'FAIL_V152_EVIDENCE_DELETE_ACCEPTED:%',tab_name;
  END IF;
 END LOOP;

 IF EXISTS(
   SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='jw_dev' AND p.proname='v152_reject_evidence_mutation'
      AND (p.prosecdef OR EXISTS (
       SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
       WHERE a.grantee=0 AND a.privilege_type='EXECUTE'
      ))
 ) THEN RAISE EXCEPTION 'FAIL_V152_MUTATION_TRIGGER_PRIVILEGE'; END IF;
END $v152_immutable$;
