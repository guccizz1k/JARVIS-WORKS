-- V20.1 additive post-install performance hardening for Supabase DEV only.
-- New V201 audit table only. No data changes, role changes, policy changes,
-- secret enrollment or production deployment.
BEGIN;
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';
DO $guard$
BEGIN
 IF NOT EXISTS (
   SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='jw_dev' AND c.relname='v201_approval_receipts'
     AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
 ) THEN
  RAISE EXCEPTION 'BLOCKED_V201_RECEIPT_TABLE_OR_FORCE_RLS_MISSING';
 END IF;
 IF EXISTS (SELECT 1 FROM jw_dev.v201_approval_receipts) THEN
  RAISE EXCEPTION 'BLOCKED_V201_RECEIPT_INDEX_NEEDS_EMPTY_TABLE';
 END IF;
 IF EXISTS (SELECT 1 FROM pg_indexes
   WHERE schemaname='jw_dev' AND indexname IN
    ('v201_receipts_org_fk_idx','v201_receipts_actor_fk_idx')) THEN
  RAISE EXCEPTION 'BLOCKED_V201_RECEIPT_INDEX_ALREADY_PRESENT';
 END IF;
END $guard$;
CREATE INDEX v201_receipts_org_fk_idx
 ON jw_dev.v201_approval_receipts(org_id);
CREATE INDEX v201_receipts_actor_fk_idx
 ON jw_dev.v201_approval_receipts(actor_id);
COMMIT;
