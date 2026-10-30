-- V15.5 exact GET-status SQL under real PG17 restricted role, rollback only.
-- Requires V15.1/2 DDL + V15.3 A/B/member + V15.4 audit fixtures in
-- ONE preflighted BEGIN; this file does not COMMIT or change permanent schema.
SET LOCAL ROLE jw_app_dev;
SELECT pg_catalog.set_config('jw.session_hash','jw-v153-a',true);
DO $a$
DECLARE c bigint; state text;
BEGIN
 SELECT count(*) INTO c FROM jw_dev.review_delivery_receipts_v151
 WHERE order_id=repeat('c',32) AND org_id=repeat('a',32);
 IF c<>1 THEN RAISE EXCEPTION 'FAIL_V155_ADMIN_A_STATUS_READ'; END IF;
 SELECT status INTO state FROM jw_dev.review_delivery_receipts_v151
 WHERE order_id=repeat('c',32) AND org_id=repeat('a',32);
 IF state<>'PENDING_HUMAN_REVIEW'
 THEN RAISE EXCEPTION 'FAIL_V155_UNEXPECTED_APPROVAL_STATE'; END IF;
END $a$;

SELECT pg_catalog.set_config('jw.session_hash','jw-v153-b',true);
DO $b$
DECLARE c bigint;
BEGIN
 SELECT count(*) INTO c FROM jw_dev.review_delivery_receipts_v151
 WHERE order_id=repeat('c',32) AND org_id=repeat('b',32);
 IF c<>0 THEN RAISE EXCEPTION 'FAIL_V155_ADMIN_B_READS_A'; END IF;
 SELECT count(*) INTO c FROM jw_dev.review_delivery_receipts_v151
 WHERE order_id=repeat('d',32) AND org_id=repeat('b',32);
 IF c<>1 THEN RAISE EXCEPTION 'FAIL_V155_ADMIN_B_OWN_STATUS'; END IF;
END $b$;

SELECT pg_catalog.set_config('jw.session_hash','jw-v153-member',true);
DO $member$
DECLARE c bigint;
BEGIN
 SELECT count(*) INTO c FROM jw_dev.review_delivery_receipts_v151;
 IF c<>0 THEN RAISE EXCEPTION 'FAIL_V155_MEMBER_READS_PRIVATE_RECEIPTS'; END IF;
END $member$;

SELECT pg_catalog.set_config('jw.session_hash','jw-v153-invalid',true);
DO $invalid$
BEGIN
 IF EXISTS (SELECT 1 FROM jw_dev.review_delivery_receipts_v151)
 THEN RAISE EXCEPTION 'FAIL_V155_UNKNOWN_SESSION_READS_PRIVATE_RECEIPTS'; END IF;
END $invalid$;
RESET ROLE;
