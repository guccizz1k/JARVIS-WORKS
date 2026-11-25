-- V19.3 disposable CI ONLY. Never execute on actual Supabase, Render or DEV.
-- This grants only narrowly scoped columns on a recreated blank import_previews
-- test table, protected by FORCE RLS and verified request-session functions.
BEGIN;
-- Prevent duplicate-byte concurrent imports per tenant even while pending.
CREATE UNIQUE INDEX v193_import_source_unique
 ON jw_dev.import_previews(org_id,file_sha256);
GRANT INSERT (id,org_id,uploaded_by,file_sha256,normalized_json,
              preview_digest,status,quote_id)
  ON jw_dev.import_previews TO jw_app_dev;
GRANT UPDATE (status)
  ON jw_dev.import_previews TO jw_app_dev;
CREATE POLICY v193_review_pending_insert
 ON jw_dev.import_previews FOR INSERT TO jw_app_dev
 WITH CHECK (org_id=jw_dev.current_org_from_session()
         AND uploaded_by=jw_dev.current_actor_from_session_v82()
         AND status='pending' AND quote_id IS NULL
         AND file_sha256 ~ '^[0-9a-f]{64}$'
         AND preview_digest ~ '^[0-9a-f]{64}$');
CREATE POLICY v193_review_owner_confirm
 ON jw_dev.import_previews FOR UPDATE TO jw_app_dev
 USING (org_id=jw_dev.current_org_from_session()
     AND uploaded_by=jw_dev.current_actor_from_session_v82()
     AND status='pending' AND quote_id IS NULL)
 WITH CHECK (org_id=jw_dev.current_org_from_session()
         AND uploaded_by=jw_dev.current_actor_from_session_v82()
         AND status='confirmed' AND quote_id IS NULL);
-- Must not grant DELETE, table TRUNCATE, or UPDATE(source fields).
-- API must also enforce CSRF, content checks and explicit user confirmation.
COMMIT;
