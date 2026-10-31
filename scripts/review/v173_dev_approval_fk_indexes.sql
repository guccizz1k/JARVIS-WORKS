-- V17.3 additive DEV-only foreign-key performance indexes for the three
-- V17.0 approval / order-draft tables. No data, RLS, grants or policy mutations.
BEGIN;
SET LOCAL lock_timeout='1200ms';
SET LOCAL statement_timeout='20s';
DO $v173_guard$
DECLARE forced integer; policies integer;
BEGIN
 SELECT count(*) INTO forced FROM pg_class c JOIN pg_namespace n
 ON n.oid=c.relnamespace WHERE n.nspname='jw_dev'
 AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity;
 SELECT count(*) INTO policies FROM pg_policies WHERE schemaname='jw_dev';
 IF current_database()<>'postgres' OR current_user<>'postgres'
 OR forced<>43 OR policies<>62
 OR EXISTS(SELECT 1 FROM jw_dev.organizations)
 OR EXISTS(SELECT 1 FROM jw_dev.users)
 OR EXISTS(SELECT 1 FROM jw_dev.sessions)
 OR EXISTS(SELECT 1 FROM jw_dev.order_drafts_v127)
 OR EXISTS(SELECT 1 FROM jw_dev.order_draft_items_v127)
 OR EXISTS(SELECT 1 FROM jw_dev.quote_review_receipts_v128)
 OR to_regclass('jw_dev.jw_v173_idx_draft_item_quote_fk') IS NOT NULL
 OR to_regclass('jw_dev.jw_v173_idx_draft_customer_fk') IS NOT NULL
 OR to_regclass('jw_dev.jw_v173_idx_draft_quote_fk') IS NOT NULL
 OR to_regclass('jw_dev.jw_v173_idx_receipt_org_fk') IS NOT NULL
 OR to_regclass('jw_dev.jw_v173_idx_receipt_quote_fk') IS NOT NULL
 THEN RAISE EXCEPTION 'V173_DEV_ONLY_EMPTY_APPROVAL_TABLE_GUARD'; END IF;
END $v173_guard$;

CREATE INDEX jw_v173_idx_draft_item_quote_fk
 ON jw_dev.order_draft_items_v127 (source_quote_item_id);
CREATE INDEX jw_v173_idx_draft_customer_fk
 ON jw_dev.order_drafts_v127 (customer_id);
CREATE INDEX jw_v173_idx_draft_quote_fk
 ON jw_dev.order_drafts_v127 (quote_id);
CREATE INDEX jw_v173_idx_receipt_org_fk
 ON jw_dev.quote_review_receipts_v128 (org_id);
CREATE INDEX jw_v173_idx_receipt_quote_fk
 ON jw_dev.quote_review_receipts_v128 (quote_id);

DO $v173_verify$
DECLARE indexed integer; invalid integer; forced integer; policies integer;
BEGIN
 SELECT count(*) INTO indexed FROM pg_index ix
 JOIN pg_class ci ON ci.oid=ix.indexrelid JOIN pg_namespace n ON n.oid=ci.relnamespace
 WHERE n.nspname='jw_dev' AND ci.relname IN (
 'jw_v173_idx_draft_item_quote_fk','jw_v173_idx_draft_customer_fk',
 'jw_v173_idx_draft_quote_fk','jw_v173_idx_receipt_org_fk',
 'jw_v173_idx_receipt_quote_fk');
 SELECT count(*) INTO invalid FROM pg_index ix
 JOIN pg_class ci ON ci.oid=ix.indexrelid JOIN pg_namespace n ON n.oid=ci.relnamespace
 WHERE n.nspname='jw_dev' AND ci.relname LIKE 'jw_v173_idx_%'
 AND (NOT ix.indisvalid OR NOT ix.indisready);
 SELECT count(*) INTO forced FROM pg_class c JOIN pg_namespace n
 ON n.oid=c.relnamespace WHERE n.nspname='jw_dev'
 AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity;
 SELECT count(*) INTO policies FROM pg_policies WHERE schemaname='jw_dev';
 IF indexed<>5 OR invalid<>0 OR forced<>43 OR policies<>62
 THEN RAISE EXCEPTION 'V173_INDEX_OR_SECURITY_POSTCONDITION_FAIL'; END IF;
END $v173_verify$;
COMMIT;
SELECT 'PASS_V173_ONLY_FIVE_NEW_DEV_FK_INDEXES' verdict;
