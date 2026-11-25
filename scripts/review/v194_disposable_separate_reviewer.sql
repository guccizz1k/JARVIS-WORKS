-- V19.4 disposable GitHub PostgreSQL17 review fixture only.
-- Separate HTTP upload reader jw_app_dev from a dedicated trusted reviewer login.
-- Never apply to actual Supabase, Render, shared DEV or prod.
BEGIN;
REVOKE UPDATE(status) ON jw_dev.import_previews FROM jw_app_dev;
DROP POLICY v193_review_owner_confirm ON jw_dev.import_previews;
-- A separate login jw_ci_v194_approver (created with one-use random password
-- by the guarded CI fixture) is NEVER in the trade/auth membership graph.
GRANT USAGE ON SCHEMA jw_dev TO jw_ci_v194_approver;
GRANT SELECT (id,org_id,uploaded_by,status,preview_digest)
 ON jw_dev.import_previews TO jw_ci_v194_approver;
GRANT UPDATE (status) ON jw_dev.import_previews TO jw_ci_v194_approver;
CREATE POLICY v194_approver_read ON jw_dev.import_previews
 FOR SELECT TO jw_ci_v194_approver
 USING (org_id=current_setting('jw.approval_org',true)
        AND uploaded_by=current_setting('jw.approval_actor',true)
        AND status IN ('pending','confirmed'));
CREATE POLICY v194_approver_transition ON jw_dev.import_previews
 FOR UPDATE TO jw_ci_v194_approver
 USING (org_id=current_setting('jw.approval_org',true)
        AND uploaded_by=current_setting('jw.approval_actor',true)
        AND status='pending' AND quote_id IS NULL)
 WITH CHECK (org_id=current_setting('jw.approval_org',true)
        AND uploaded_by=current_setting('jw.approval_actor',true)
        AND status='confirmed' AND quote_id IS NULL);
COMMIT;
