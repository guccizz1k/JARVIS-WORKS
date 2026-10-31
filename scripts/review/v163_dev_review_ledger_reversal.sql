-- V163 reversible DEV schema changes: manually run ONLY after independent review.
-- SAFE PRECONDITION: NO rows in newly-created V151 tables. Never use on PROD.
DO $pre$ BEGIN
IF to_regclass('jw_dev.review_delivery_receipts_v151') IS NULL OR
   EXISTS(SELECT 1 FROM jw_dev.review_delivery_receipts_v151) OR
   EXISTS(SELECT 1 FROM jw_dev.review_delivery_nonces_v151) OR
   EXISTS(SELECT 1 FROM jw_dev.review_delivery_items_v151) OR
   EXISTS(SELECT 1 FROM jw_dev.review_signup_requests_v151) OR
   EXISTS(SELECT 1 FROM jw_dev.review_signup_nonces_v151)
THEN RAISE EXCEPTION 'V163_ROLLBACK_REFUSED_DATA_PRESENT_OR_MISSING'; END IF;
END $pre$;
DROP POLICY v159_order_read ON jw_dev.orders;
DROP POLICY v159_line_read ON jw_dev.order_items;
DROP POLICY v159_invoice_read ON jw_dev.invoices;
DROP POLICY v159_audit_insert ON jw_dev.audit_logs;
DROP TABLE jw_dev.review_delivery_items_v151,
           jw_dev.review_delivery_nonces_v151,
           jw_dev.review_delivery_receipts_v151,
           jw_dev.review_signup_nonces_v151,
           jw_dev.review_signup_requests_v151;
DROP FUNCTION jw_dev.v151_order_source_guard();
DROP FUNCTION jw_dev.v151_line_source_guard();
DROP FUNCTION jw_dev.v152_reject_evidence_mutation();
REVOKE SELECT ON jw_dev.orders,jw_dev.order_items,jw_dev.invoices
 FROM jw_delivery_writer_v159;
REVOKE INSERT ON jw_dev.audit_logs FROM jw_delivery_writer_v159;
REVOKE EXECUTE ON FUNCTION jw_dev.stage_identity_v84(),
 jw_dev.current_org_from_session(),jw_dev.current_actor_from_session_v82()
 FROM jw_delivery_writer_v159;
REVOKE USAGE ON SCHEMA jw_dev FROM jw_delivery_writer_v159;
DROP ROLE jw_delivery_writer_v159;
DO $check$ BEGIN
IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='jw_dev' AND c.relkind='r')<>35 OR
 (SELECT count(*) FROM pg_policies WHERE schemaname='jw_dev')<>40
THEN RAISE EXCEPTION 'V163_ROLLBACK_POSTCONDITION_FAILED'; END IF;
END $check$;
