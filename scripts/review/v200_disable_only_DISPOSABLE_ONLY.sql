-- V20.0 DISABLE-ONLY ROLLBACK for disposable PostgreSQL17 CI.
-- Preserves all rows, existing indexes (including new dedupe safety), data,
-- audit receipt, RLS FORCE, parent FKs, and existing user permissions.
-- No DROP TABLE, DELETE, TRUNCATE, or down-migration of source documents.
BEGIN;
SET LOCAL lock_timeout='3s';
DO $guard$
BEGIN
 IF current_setting('jw.v200_disposable_guard',true)
      IS DISTINCT FROM 'CI_ONLY_FRESH_PG17_NO_PRODUCTION'
  OR current_database()<>'postgres' OR current_user<>'postgres'
  OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='jw_import_writer_v200')
 THEN RAISE EXCEPTION 'BLOCKED_V200_UNSAFE_ROLLBACK_ENVIRONMENT';
 END IF;
END $guard$;
DROP POLICY v200_candidate_pending_only ON jw_dev.import_previews;
DROP POLICY v200_candidate_read ON jw_dev.import_previews;
REVOKE INSERT(id,org_id,uploaded_by,file_sha256,filename,normalized_json,
              preview_digest,status,created_at)
  ON jw_dev.import_previews FROM jw_import_writer_v200;
REVOKE SELECT(id,org_id,file_sha256,status)
  ON jw_dev.import_previews FROM jw_import_writer_v200;
REVOKE EXECUTE ON FUNCTION
  jw_dev.current_org_from_session(),
  jw_dev.current_actor_from_session_v82()
  FROM jw_import_writer_v200;
REVOKE USAGE ON SCHEMA jw_dev FROM jw_import_writer_v200;
-- Intentionally keep role NOLOGIN and the pending uniqueness index:
-- no privilege to insert, no loss of data, no duplicate reentry window.
COMMIT;
