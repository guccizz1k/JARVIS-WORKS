-- V16.8 REVIEW-ONLY candidate: NEVER auto-apply, never production.
-- Requires explicitly approved isolated DEV DB session and independent PG17 RLS regression.
-- No table data edits, grants, role changes, or main/production deployment.
BEGIN;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '15s';
DO $$
BEGIN
  IF current_setting('jw.v168_review_approval', true) IS DISTINCT FROM 'DEV_ONLY_V168_EXPLICIT' THEN
    RAISE EXCEPTION 'BLOCKED: V168 isolated DEV policy change not approved';
  END IF;
  IF (SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='jw_dev' AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity) <> 40 THEN
    RAISE EXCEPTION 'BLOCKED: V168 expected exactly 40 FORCE RLS tables';
  END IF;
  IF (SELECT COUNT(*) FROM pg_policies WHERE schemaname='jw_dev' AND policyname IN
      ('jw_stage_read_automation_statements_v60','jw_stage_read_evidence_lines_v66','jw_stage_read_evidence_links_v65','jw_stage_read_evidence_records_v64','jw_stage_read_invoice_adjustment_decisions_v69','jw_stage_read_invoice_adjustments_v69','jw_stage_read_payments','jw_stage_read_reconciliation_reviews_v67','v153_delivery_line_select','v159_item_read','v153_delivery_nonce_select','v159_nonce_read','v159_receipt_insert')) <> 13 THEN
    RAISE EXCEPTION 'BLOCKED: V168 source policy inventory differs';
  END IF;
END $$;

ALTER POLICY jw_stage_read_automation_statements_v60 ON jw_dev.automation_statements_v60
  USING (org_id = jw_dev.current_org_from_session() AND EXISTS (SELECT 1 FROM jw_dev.orders o WHERE o.id = automation_statements_v60.order_id AND o.org_id = automation_statements_v60.org_id));

ALTER POLICY jw_stage_read_evidence_lines_v66 ON jw_dev.evidence_lines_v66
  USING (org_id = jw_dev.current_org_from_session() AND EXISTS (SELECT 1 FROM jw_dev.evidence_records_v64 r WHERE r.id = evidence_lines_v66.record_id AND r.org_id = evidence_lines_v66.org_id));

ALTER POLICY jw_stage_read_evidence_links_v65 ON jw_dev.evidence_links_v65
  USING (org_id = jw_dev.current_org_from_session() AND EXISTS (SELECT 1 FROM jw_dev.evidence_records_v64 r WHERE r.id = evidence_links_v65.record_id AND r.org_id = evidence_links_v65.org_id));

ALTER POLICY jw_stage_read_evidence_records_v64 ON jw_dev.evidence_records_v64
  USING (org_id = jw_dev.current_org_from_session() AND EXISTS (SELECT 1 FROM jw_dev.evidence_previews_v64 p WHERE p.id = evidence_records_v64.preview_id AND p.org_id = evidence_records_v64.org_id));

ALTER POLICY jw_stage_read_invoice_adjustment_decisions_v69 ON jw_dev.invoice_adjustment_decisions_v69
  USING (org_id = jw_dev.current_org_from_session() AND EXISTS (SELECT 1 FROM jw_dev.invoice_adjustments_v69 a WHERE a.id = invoice_adjustment_decisions_v69.adjustment_id AND a.org_id = invoice_adjustment_decisions_v69.org_id));

ALTER POLICY jw_stage_read_invoice_adjustments_v69 ON jw_dev.invoice_adjustments_v69
  USING (org_id = jw_dev.current_org_from_session() AND EXISTS (SELECT 1 FROM jw_dev.invoices i WHERE i.id = invoice_adjustments_v69.invoice_id AND i.org_id = invoice_adjustments_v69.org_id));

ALTER POLICY jw_stage_read_payments ON jw_dev.payments
  USING (org_id = jw_dev.current_org_from_session() AND EXISTS (SELECT 1 FROM jw_dev.invoices i WHERE i.id = payments.invoice_id AND i.org_id = payments.org_id));

ALTER POLICY jw_stage_read_reconciliation_reviews_v67 ON jw_dev.reconciliation_reviews_v67
  USING (org_id = jw_dev.current_org_from_session() AND EXISTS (SELECT 1 FROM jw_dev.evidence_records_v64 r WHERE r.id = reconciliation_reviews_v67.record_id AND r.org_id = reconciliation_reviews_v67.org_id));

ALTER POLICY v153_delivery_line_select ON jw_dev.review_delivery_items_v151
  USING (EXISTS (SELECT 1 FROM jw_dev.review_delivery_receipts_v151 r WHERE r.order_id = review_delivery_items_v151.order_id AND r.org_id = jw_dev.current_org_from_session()));

ALTER POLICY v159_item_read ON jw_dev.review_delivery_items_v151
  USING (EXISTS (SELECT 1 FROM jw_dev.review_delivery_receipts_v151 r WHERE r.order_id = review_delivery_items_v151.order_id AND r.org_id = jw_dev.current_org_from_session()));

ALTER POLICY v153_delivery_nonce_select ON jw_dev.review_delivery_nonces_v151
  USING (EXISTS (SELECT 1 FROM jw_dev.review_delivery_receipts_v151 r WHERE r.order_id = review_delivery_nonces_v151.order_id AND r.org_id = jw_dev.current_org_from_session()));

ALTER POLICY v159_nonce_read ON jw_dev.review_delivery_nonces_v151
  USING (EXISTS (SELECT 1 FROM jw_dev.review_delivery_receipts_v151 r WHERE r.order_id = review_delivery_nonces_v151.order_id AND r.org_id = jw_dev.current_org_from_session()));

ALTER POLICY v159_receipt_insert ON jw_dev.review_delivery_receipts_v151
  WITH CHECK (org_id = jw_dev.current_org_from_session() AND EXISTS (SELECT 1 FROM jw_dev.stage_identity_v84() a WHERE a.org_id = review_delivery_receipts_v151.org_id AND a.actor_role = 'admin') AND EXISTS (SELECT 1 FROM jw_dev.orders o WHERE o.id = review_delivery_receipts_v151.order_id AND o.org_id = review_delivery_receipts_v151.org_id AND o.status = 'fulfilled' AND o.review_state = 'acknowledged'));
COMMIT;
