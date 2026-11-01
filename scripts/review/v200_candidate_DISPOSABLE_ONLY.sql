-- V20.0: REVIEW CANDIDATE ONLY. Never execute on actual Supabase/Render.
-- Tested exclusively against a fresh disposable PostgreSQL17 CI database.
-- Real-world deployment needs separately approved, parameterized migration,
-- protected backend credential provisioning, backup, RLS audit and rollout.
-- This test role is NOLOGIN: it cannot enable real user uploads.
BEGIN;
SET LOCAL lock_timeout='3s';
DO $preflight$
DECLARE
  present_names text[];
  required_names text[]:=ARRAY[
    'confirmed_at','created_at','file_sha256','filename','id','normalized_json',
    'order_id','org_id','preview_digest','quote_id','status','uploaded_by'];
  nonnull_count int;
  duplicate_count int;
BEGIN
  IF current_setting('jw.v200_disposable_guard',true)
       IS DISTINCT FROM 'CI_ONLY_FRESH_PG17_NO_PRODUCTION'
     OR current_database() <> 'postgres'
     OR current_user <> 'postgres'
     OR current_setting('server_version_num')::int / 10000 <> 17
  THEN RAISE EXCEPTION 'BLOCKED_V200_NON_DISPOSABLE_ENVIRONMENT';
  END IF;
  SELECT array_agg(column_name::text ORDER BY column_name)
   INTO present_names FROM information_schema.columns
   WHERE table_schema='jw_dev' AND table_name='import_previews';
  IF present_names IS DISTINCT FROM required_names
  THEN RAISE EXCEPTION 'BLOCKED_V200_SCHEMA_COLUMN_DRIFT'; END IF;
  SELECT count(*) INTO nonnull_count FROM information_schema.columns
   WHERE table_schema='jw_dev' AND table_name='import_previews'
   AND column_name=ANY(ARRAY[
      'id','org_id','uploaded_by','file_sha256','filename','normalized_json',
      'preview_digest','status','created_at'])
   AND is_nullable='NO' AND column_default IS NULL;
  IF nonnull_count<>9
  THEN RAISE EXCEPTION 'BLOCKED_V200_REQUIRED_COLUMN_DRIFT'; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_class
    WHERE oid='jw_dev.import_previews'::regclass
      AND relrowsecurity AND relforcerowsecurity
  ) THEN RAISE EXCEPTION 'BLOCKED_V200_FORCE_RLS_MISSING'; END IF;
  IF has_table_privilege('jw_app_dev','jw_dev.import_previews','INSERT')
    OR has_table_privilege('jw_app_dev','jw_dev.import_previews','UPDATE')
  THEN RAISE EXCEPTION 'BLOCKED_V200_EXISTING_APP_WRITE_PRIVILEGE'; END IF;
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='jw_import_writer_v200')
  THEN RAISE EXCEPTION 'BLOCKED_V200_ROLE_ALREADY_EXISTS'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes
    WHERE schemaname='jw_dev' AND tablename='import_previews'
      AND indexdef LIKE '%file_sha256%'
      AND indexdef LIKE '%status%'
      AND indexdef LIKE '%confirmed%')
  THEN RAISE EXCEPTION 'BLOCKED_V200_CONFIRMED_INDEX_MISSING'; END IF;
  SELECT count(*) INTO duplicate_count FROM (
    SELECT org_id,file_sha256 FROM jw_dev.import_previews
    WHERE status='pending' GROUP BY 1,2 HAVING count(*)>1
  ) collisions;
  IF duplicate_count<>0
  THEN RAISE EXCEPTION 'BLOCKED_V200_PREEXISTING_PENDING_DUPLICATES'; END IF;
  IF EXISTS (SELECT 1 FROM jw_dev.import_previews
             WHERE status NOT IN ('pending','confirmed'))
  THEN RAISE EXCEPTION 'BLOCKED_V200_INVALID_STATUS'; END IF;
END $preflight$;
CREATE ROLE jw_import_writer_v200 NOLOGIN NOINHERIT NOBYPASSRLS
  NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT USAGE ON SCHEMA jw_dev TO jw_import_writer_v200;
GRANT SELECT (id,org_id,file_sha256,status)
  ON jw_dev.import_previews TO jw_import_writer_v200;
GRANT INSERT (id,org_id,uploaded_by,file_sha256,filename,normalized_json,
              preview_digest,status,created_at)
  ON jw_dev.import_previews TO jw_import_writer_v200;
GRANT EXECUTE ON FUNCTION
  jw_dev.current_org_from_session(),
  jw_dev.current_actor_from_session_v82()
  TO jw_import_writer_v200;
CREATE POLICY v200_candidate_read ON jw_dev.import_previews
 FOR SELECT TO jw_import_writer_v200
 USING (org_id=jw_dev.current_org_from_session());
CREATE POLICY v200_candidate_pending_only ON jw_dev.import_previews
 FOR INSERT TO jw_import_writer_v200
 WITH CHECK (
    org_id=jw_dev.current_org_from_session()
    AND uploaded_by=jw_dev.current_actor_from_session_v82()
    AND status='pending' AND quote_id IS NULL AND order_id IS NULL
    AND confirmed_at IS NULL
    AND id ~ '^[0-9a-f]{32}$'
    AND file_sha256 ~ '^[0-9a-f]{64}$'
    AND preview_digest ~ '^[0-9a-f]{64}$'
    AND length(filename) BETWEEN 5 AND 120
    AND filename ~* '^[^/\\]{1,116}\.(xlsx|pdf)$'
    AND length(created_at) BETWEEN 20 AND 40
 );
-- Keep existing confirmed-only index intact; reject pre-existing pending
-- duplicates before adding a new pending-only index.
CREATE UNIQUE INDEX v200_candidate_pending_source_unique
  ON jw_dev.import_previews(org_id,file_sha256)
  WHERE status='pending';
COMMIT;
