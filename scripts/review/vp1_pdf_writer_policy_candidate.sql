-- Review-only candidate. Never apply to a shared/hosted database without
-- explicit migration approval, a verified snapshot, and a scoped rollback.
-- V20.1 writer policy accepts .xlsx only; the original engine also accepts .pdf.
BEGIN;
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';
DO $guard$
DECLARE p text;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='jw_dev' AND c.relname='import_previews'
      AND c.relrowsecurity AND c.relforcerowsecurity
  ) THEN RAISE EXCEPTION 'BLOCKED_P1_FORCE_RLS_REQUIRED'; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname='jw_dev_import_writer_v201'
      AND NOT rolcanlogin AND NOT rolbypassrls AND NOT rolsuper
  ) THEN RAISE EXCEPTION 'BLOCKED_P1_INACTIVE_WRITER_REQUIRED'; END IF;
  IF (SELECT count(*) FROM pg_policies WHERE schemaname='jw_dev'
      AND tablename='import_previews' AND cmd='INSERT') <> 1 THEN
    RAISE EXCEPTION 'BLOCKED_P1_UNEXPECTED_INSERT_POLICY_SET';
  END IF;
  SELECT with_check INTO p FROM pg_policies WHERE schemaname='jw_dev'
    AND tablename='import_previews'
    AND policyname='v201_verified_writer_insert'
    AND cmd='INSERT' AND roles::text[]=ARRAY['jw_dev_import_writer_v201']::text[];
  IF p IS NULL OR position('.xlsx' in p)=0 OR position('.pdf' in p)>0 THEN
    RAISE EXCEPTION 'BLOCKED_P1_WRITER_POLICY_DRIFT';
  END IF;
END $guard$;
ALTER POLICY v201_verified_writer_insert ON jw_dev.import_previews
  TO jw_dev_import_writer_v201
  WITH CHECK (
    org_id=jw_dev.current_org_from_session()
    AND uploaded_by=jw_dev.current_actor_from_session_v82()
    AND status='pending' AND quote_id IS NULL AND order_id IS NULL
    AND confirmed_at IS NULL
    AND id ~ '^[a-f0-9]{32}$'
    AND file_sha256 ~ '^[a-f0-9]{64}$'
    AND preview_digest ~ '^[a-f0-9]{64}$'
    AND length(filename) BETWEEN 5 AND 120
    AND filename=btrim(filename)
    AND left(filename,1)<>'.'
    AND position('/' in filename)=0
    AND position(chr(92) in filename)=0
    AND filename !~ '[[:cntrl:]]'
    AND filename !~ '[‪-‮⁦-⁩]'
    AND lower(filename) !~ '(\.pdf\.|\.xlsx\.)'
    AND (lower(right(filename,5))='.xlsx'
         OR lower(right(filename,4))='.pdf')
    AND length(created_at) BETWEEN 20 AND 40
  );
COMMIT;
