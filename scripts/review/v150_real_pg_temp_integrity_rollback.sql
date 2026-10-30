-- V15.0 REAL PostgreSQL 17 constraint and atomic rollback verification ONLY.
-- ISOLATED DEV / EMPTY real jw_dev precondition. Creates TEMP tables in ONE
-- explicit transaction and ROLLBACK. Does NOT add any persistent product schema.
-- Does NOT claim external signatures, real business identity, physical delivery,
-- restricted-role INSERT or independent hosted/E2E signoff.
BEGIN;
SET LOCAL statement_timeout = '20s';
SET LOCAL lock_timeout = '1s';
DO $preflight$
BEGIN
 IF current_database() <> 'postgres'
    OR EXISTS(SELECT 1 FROM jw_dev.organizations)
    OR EXISTS(SELECT 1 FROM jw_dev.users)
    OR EXISTS(SELECT 1 FROM jw_dev.orders)
    OR EXISTS(SELECT 1 FROM jw_dev.invoices)
    OR EXISTS(SELECT 1 FROM jw_dev.payments)
    OR EXISTS(SELECT 1 FROM jw_dev.messenger_messages)
    OR EXISTS(SELECT 1 FROM jw_dev.audit_logs)
 THEN RAISE EXCEPTION 'V150_REQUIRES_EMPTY_ISOLATED_DEV'; END IF;
END $preflight$;

CREATE TEMP TABLE jw_v150_review_enrollment (
 request_id text PRIMARY KEY CHECK(request_id ~ '^[0-9a-f]{32}$'),
 email text NOT NULL UNIQUE CHECK(
   email = lower(btrim(email)) AND email ~ '^[a-z0-9][a-z0-9._+-]*@[a-z0-9.-]+[.][a-z]{2,}$'),
 business_number text NOT NULL UNIQUE CHECK(business_number ~ '^[0-9]{10}$'),
 digest text NOT NULL UNIQUE CHECK(digest ~ '^[0-9a-f]{64}$'),
 status text NOT NULL CHECK(status='PENDING_HUMAN_REVIEW')
) ON COMMIT DROP;

CREATE TEMP TABLE jw_v150_review_nonces (
 nonce text PRIMARY KEY CHECK(nonce ~ '^[0-9a-f]{32}$'),
 request_id text NOT NULL REFERENCES jw_v150_review_enrollment(request_id),
 purpose text NOT NULL CHECK(purpose IN ('email','business')),
 UNIQUE(request_id,purpose)
) ON COMMIT DROP;

CREATE TEMP TABLE jw_v150_review_delivery (
 order_id text PRIMARY KEY CHECK(order_id ~ '^[0-9a-f]{32}$'),
 org_id text NOT NULL CHECK(org_id ~ '^[0-9a-f]{32}$'),
 source_sha text NOT NULL CHECK(source_sha ~ '^[0-9a-f]{64}$'),
 dispatch_document_sha text NOT NULL CHECK(dispatch_document_sha ~ '^[0-9a-f]{64}$'),
 recipient_document_sha text NOT NULL CHECK(recipient_document_sha ~ '^[0-9a-f]{64}$'),
 dispatch_actor text NOT NULL CHECK(dispatch_actor ~ '^[0-9a-f]{32}$'),
 recipient_actor text NOT NULL CHECK(recipient_actor ~ '^[0-9a-f]{32}$'),
 dispatch_nonce text NOT NULL UNIQUE CHECK(dispatch_nonce ~ '^[0-9a-f]{32}$'),
 recipient_nonce text NOT NULL UNIQUE CHECK(recipient_nonce ~ '^[0-9a-f]{32}$'),
 source_total bigint NOT NULL CHECK(source_total>0),
 dispatch_total bigint NOT NULL,
 recipient_total bigint NOT NULL,
 status text NOT NULL CHECK(status='PENDING_HUMAN_REVIEW'),
 CHECK(dispatch_actor<>recipient_actor),
 CHECK(dispatch_nonce<>recipient_nonce),
 CHECK(source_total=dispatch_total AND dispatch_total=recipient_total),
 UNIQUE(org_id,order_id)
) ON COMMIT DROP;

CREATE TEMP TABLE jw_v150_review_delivery_items (
 order_id text NOT NULL REFERENCES jw_v150_review_delivery(order_id),
 source_item_id text NOT NULL,
 source_qty bigint NOT NULL CHECK(source_qty BETWEEN 1 AND 100000),
 dispatch_qty bigint NOT NULL CHECK(dispatch_qty=source_qty),
 receipt_qty bigint NOT NULL CHECK(receipt_qty=source_qty),
 PRIMARY KEY(order_id,source_item_id)
) ON COMMIT DROP;

DO $verify$
DECLARE
 rejected boolean;
 e_count bigint;
 nonce_count bigint;
 d_count bigint;
 item_count bigint;
BEGIN
 INSERT INTO jw_v150_review_enrollment
 VALUES(repeat('a',32),'owner@example.test','1234567890',repeat('f',64),'PENDING_HUMAN_REVIEW');
 INSERT INTO jw_v150_review_nonces VALUES
 (repeat('b',32),repeat('a',32),'email'),
 (repeat('c',32),repeat('a',32),'business');

 -- UNIQUE normalized email across different entity IDs and business numbers.
 rejected := false;
 BEGIN
  INSERT INTO jw_v150_review_enrollment
  VALUES(repeat('d',32),'owner@example.test','9999999999',repeat('e',64),'PENDING_HUMAN_REVIEW');
 EXCEPTION WHEN unique_violation THEN rejected := true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL_DUPLICATE_EMAIL_ACCEPTED'; END IF;

 rejected := false;
 BEGIN
  INSERT INTO jw_v150_review_enrollment
  VALUES(repeat('d',32),'other@example.test','1234567890',repeat('e',64),'PENDING_HUMAN_REVIEW');
 EXCEPTION WHEN unique_violation THEN rejected := true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL_DUPLICATE_BUSINESS_ACCEPTED'; END IF;

 -- Proof nonce reuse must abort the entire reservation batch (PG subtransaction).
 rejected := false;
 BEGIN
  INSERT INTO jw_v150_review_enrollment
  VALUES(repeat('d',32),'other@example.test','9999999999',repeat('e',64),'PENDING_HUMAN_REVIEW');
  INSERT INTO jw_v150_review_nonces VALUES(repeat('1',32),repeat('d',32),'email');
  INSERT INTO jw_v150_review_nonces VALUES(repeat('b',32),repeat('d',32),'business');
 EXCEPTION WHEN unique_violation THEN rejected := true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL_REPLAYED_NONCE_ACCEPTED'; END IF;

 -- No automatic business activation states, even in reference schema.
 rejected := false;
 BEGIN
  INSERT INTO jw_v150_review_enrollment
  VALUES(repeat('d',32),'other@example.test','9999999999',repeat('e',64),'APPROVED');
 EXCEPTION WHEN check_violation THEN rejected := true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL_AUTO_ACTIVATION_ACCEPTED'; END IF;

 SELECT count(*) INTO e_count FROM jw_v150_review_enrollment;
 SELECT count(*) INTO nonce_count FROM jw_v150_review_nonces;
 IF e_count<>1 OR nonce_count<>2 THEN
  RAISE EXCEPTION 'FAIL_PARTIAL_ENROLLMENT_ROLLBACK_%_%',e_count,nonce_count;
 END IF;

 -- Proof of *model* constraints, not external human attestation.
 INSERT INTO jw_v150_review_delivery VALUES(
  repeat('1',32),repeat('2',32),repeat('3',64),
  repeat('4',64),repeat('5',64),repeat('6',32),repeat('7',32),
  repeat('8',32),repeat('9',32),7000,7000,7000,'PENDING_HUMAN_REVIEW');
 INSERT INTO jw_v150_review_delivery_items VALUES
  (repeat('1',32),'item-1',2,2,2),
  (repeat('1',32),'item-2',1,1,1);

 -- Order-idempotency: second review cannot be inserted under a new company.
 rejected := false;
 BEGIN
  INSERT INTO jw_v150_review_delivery VALUES(
   repeat('1',32),repeat('a',32),repeat('3',64),
   repeat('4',64),repeat('5',64),repeat('6',32),repeat('7',32),
   repeat('b',32),repeat('c',32),7000,7000,7000,'PENDING_HUMAN_REVIEW');
 EXCEPTION WHEN unique_violation THEN rejected := true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL_CROSS_ORG_ORDER_REPLAY_ACCEPTED'; END IF;

 -- Signed quantity needs to equal both dispatched and received quantity.
 rejected := false;
 BEGIN
  INSERT INTO jw_v150_review_delivery_items VALUES(repeat('1',32),'item-3',3,3,2);
 EXCEPTION WHEN check_violation THEN rejected := true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL_DELIVERY_QUANTITY_MISMATCH_ACCEPTED'; END IF;

 rejected := false;
 BEGIN
  INSERT INTO jw_v150_review_delivery_items VALUES(repeat('1',32),'item-1',2,2,2);
 EXCEPTION WHEN unique_violation THEN rejected := true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL_DUPLICATE_ITEM_ACCEPTED'; END IF;

 rejected := false;
 BEGIN
  INSERT INTO jw_v150_review_delivery VALUES(
   repeat('a',32),repeat('2',32),repeat('3',64),
   repeat('4',64),repeat('5',64),repeat('6',32),repeat('6',32),
   repeat('b',32),repeat('c',32),7000,7000,7000,'PENDING_HUMAN_REVIEW');
 EXCEPTION WHEN check_violation THEN rejected := true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL_SAME_SIGNER_ACCEPTED'; END IF;

 rejected := false;
 BEGIN
  INSERT INTO jw_v150_review_delivery VALUES(
   repeat('a',32),repeat('2',32),repeat('3',64),
   repeat('4',64),repeat('5',64),repeat('6',32),repeat('7',32),
   repeat('b',32),repeat('b',32),7000,7000,7000,'PENDING_HUMAN_REVIEW');
 EXCEPTION WHEN check_violation THEN rejected := true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL_SAME_RECEIPT_NONCE_ACCEPTED'; END IF;

 rejected := false;
 BEGIN
  INSERT INTO jw_v150_review_delivery VALUES(
   repeat('a',32),repeat('2',32),repeat('3',64),
   repeat('4',64),repeat('5',64),repeat('6',32),repeat('7',32),
   repeat('b',32),repeat('c',32),7000,7001,7000,'PENDING_HUMAN_REVIEW');
 EXCEPTION WHEN check_violation THEN rejected := true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'FAIL_PAYMENT_AMOUNT_DIVERGENCE_ACCEPTED'; END IF;

 SELECT count(*) INTO d_count FROM jw_v150_review_delivery;
 SELECT count(*) INTO item_count FROM jw_v150_review_delivery_items;
 IF d_count<>1 OR item_count<>2 THEN
  RAISE EXCEPTION 'FAIL_PARTIAL_DELIVERY_ROLLBACK_%_%',d_count,item_count;
 END IF;
END $verify$;

-- Roll back *everything*, including temporary schema objects.
ROLLBACK;
SELECT CASE WHEN
 NOT EXISTS(SELECT 1 FROM jw_dev.organizations) AND
 NOT EXISTS(SELECT 1 FROM jw_dev.users) AND
 NOT EXISTS(SELECT 1 FROM jw_dev.orders) AND
 NOT EXISTS(SELECT 1 FROM jw_dev.invoices) AND
 NOT EXISTS(SELECT 1 FROM jw_dev.payments) AND
 NOT EXISTS(SELECT 1 FROM jw_dev.messenger_messages) AND
 NOT EXISTS(SELECT 1 FROM jw_dev.audit_logs) AND
 to_regclass('pg_temp.jw_v150_review_enrollment') IS NULL AND
 to_regclass('pg_temp.jw_v150_review_delivery') IS NULL
 THEN 'PASS_REAL_PG17_V150_TEMP_CONSTRAINTS_AND_ATOMIC_ROLLBACK'
 ELSE 'FAIL_V150_RESIDUAL_OR_UNEXPECTED_DATA'
END AS verdict;
