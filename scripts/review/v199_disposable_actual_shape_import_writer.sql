-- V19.9 isolated GitHub PostgreSQL17, matching read-only observed DEV import_previews.
-- REVIEW-ONLY, NEVER RUN ON ACTUAL SUPABASE OR RENDER. No real migration here.
BEGIN;
-- Existing V19.1 test fixture lacked these four production-required columns.
ALTER TABLE jw_dev.import_previews
 ADD COLUMN filename text NOT NULL DEFAULT 'legacy-review-fixture.xlsx',
 ADD COLUMN created_at text NOT NULL DEFAULT '2026-10-31T00:00:00+00:00',
 ADD COLUMN confirmed_at text,
 ADD COLUMN order_id text;
ALTER TABLE jw_dev.import_previews
 ALTER COLUMN filename DROP DEFAULT,
 ALTER COLUMN created_at DROP DEFAULT;
ALTER TABLE jw_dev.import_previews
 ADD CONSTRAINT v199_import_org_fk FOREIGN KEY (org_id)
   REFERENCES jw_dev.organizations(id),
 ADD CONSTRAINT v199_import_actor_fk FOREIGN KEY (uploaded_by)
   REFERENCES jw_dev.users(id),
 ADD CONSTRAINT v199_import_quote_fk FOREIGN KEY (quote_id)
   REFERENCES jw_dev.quotes(id),
 ADD CONSTRAINT v199_import_order_fk FOREIGN KEY (order_id)
   REFERENCES jw_dev.orders(id),
 ADD CONSTRAINT v199_import_order_unique UNIQUE (order_id),
 ADD CONSTRAINT v199_import_status_check CHECK(status IN ('pending','confirmed'));
-- Mirror actual DEV confirmed-only uniqueness. Add a separate pending-only
-- candidate index; this is NOT claimed to be installed in actual DEV.
DROP INDEX jw_dev.v193_import_source_unique;
CREATE UNIQUE INDEX v199_import_confirmed_unique ON jw_dev.import_previews(org_id,file_sha256)
 WHERE status='confirmed';
CREATE UNIQUE INDEX v199_import_pending_unique ON jw_dev.import_previews(org_id,file_sha256)
 WHERE status='pending';
-- No table-wide or app-role INSERT/UPDATE privilege is permitted.
REVOKE INSERT ON jw_dev.import_previews FROM jw_app_dev;
REVOKE UPDATE ON jw_dev.import_previews FROM jw_app_dev;
DROP POLICY v193_review_pending_insert ON jw_dev.import_previews;
GRANT USAGE ON SCHEMA jw_dev TO jw_ci_v199_import_writer;
GRANT SELECT(id,org_id,file_sha256,status)
 ON jw_dev.import_previews TO jw_ci_v199_import_writer;
GRANT INSERT(id,org_id,uploaded_by,file_sha256,filename,normalized_json,
             preview_digest,status,created_at)
 ON jw_dev.import_previews TO jw_ci_v199_import_writer;
GRANT EXECUTE ON FUNCTION jw_dev.current_org_from_session(),
 jw_dev.current_actor_from_session_v82() TO jw_ci_v199_import_writer;
CREATE POLICY v199_writer_verified_read ON jw_dev.import_previews
 FOR SELECT TO jw_ci_v199_import_writer
 USING(org_id=jw_dev.current_org_from_session());
CREATE POLICY v199_writer_only_verified_pending ON jw_dev.import_previews
 FOR INSERT TO jw_ci_v199_import_writer
 WITH CHECK(
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
-- The synthetic V195 reviewer remains the only write path for confirmations.
-- Avoid granting business users raw INSERT into the review-only source.
COMMIT;
