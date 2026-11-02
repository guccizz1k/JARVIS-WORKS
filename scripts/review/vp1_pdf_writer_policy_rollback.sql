-- Review-only guarded rollback. Reject while ANY PDF preview remains.
BEGIN;
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';
DO $guard$
DECLARE p text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user
      AND (rolsuper OR rolbypassrls)) THEN
    RAISE EXCEPTION 'BLOCKED_P1_ROLLBACK_REQUIRES_FULL_ROW_VISIBILITY';
  END IF;
  IF EXISTS (SELECT 1 FROM jw_dev.import_previews
      WHERE lower(right(filename,4))='.pdf') THEN
    RAISE EXCEPTION 'BLOCKED_P1_ROLLBACK_PDF_ROWS_PRESENT';
  END IF;
  SELECT with_check INTO p FROM pg_policies WHERE schemaname='jw_dev'
    AND tablename='import_previews'
    AND policyname='v201_verified_writer_insert'
    AND cmd='INSERT';
  IF p IS NULL OR position('.pdf' in p)=0 THEN
    RAISE EXCEPTION 'BLOCKED_P1_ROLLBACK_POLICY_DRIFT';
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
    AND position('/' in filename)=0
    AND position(chr(92) in filename)=0
    AND lower(right(filename,5))='.xlsx'
    AND length(created_at) BETWEEN 20 AND 40
  );
COMMIT;
