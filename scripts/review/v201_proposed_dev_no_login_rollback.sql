-- V20.1 strictly fail-closed review rollback; apply only with explicit approval.
-- Refuses to erase approval receipts, secrets, or business previews.
BEGIN;
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';
DO $guard$
BEGIN
 IF EXISTS(SELECT 1 FROM jw_dev.import_previews) OR
    EXISTS(SELECT 1 FROM jw_dev.v201_approval_receipts) OR
    EXISTS(SELECT 1 FROM jw_dev.v201_approval_secrets) THEN
  RAISE EXCEPTION 'BLOCKED_V201_ROLLBACK_HAS_DATA';
 END IF;
END $guard$;
REVOKE EXECUTE ON FUNCTION jw_dev.v201_confirm_import(
 text,text,text,text,text,text,text) FROM jw_dev_import_review_executor_v201;
DROP FUNCTION jw_dev.v201_confirm_import(text,text,text,text,text,text,text);
DROP TRIGGER v201_receipt_immutable ON jw_dev.v201_approval_receipts;
DROP FUNCTION jw_dev.v201_reject_receipt_mutation();
DROP TABLE jw_dev.v201_approval_receipts;
DROP TABLE jw_dev.v201_approval_secrets;
DROP POLICY v201_owner_transition ON jw_dev.import_previews;
DROP POLICY v201_owner_read ON jw_dev.import_previews;
DROP POLICY v201_verified_writer_insert ON jw_dev.import_previews;
DROP POLICY v201_verified_writer_read ON jw_dev.import_previews;
DROP INDEX jw_dev.v201_pending_source_unique;
REVOKE ALL ON jw_dev.import_previews FROM jw_dev_import_writer_v201,
 jw_dev_import_approval_owner_v201;
REVOKE EXECUTE ON FUNCTION jw_dev.current_org_from_session(),
 jw_dev.current_actor_from_session_v82()
 FROM jw_dev_import_writer_v201,jw_dev_import_approval_owner_v201;
REVOKE USAGE ON SCHEMA extensions FROM jw_dev_import_approval_owner_v201;
REVOKE USAGE ON SCHEMA jw_dev FROM jw_dev_import_writer_v201,
 jw_dev_import_review_executor_v201,jw_dev_import_approval_owner_v201;
DROP ROLE jw_dev_import_writer_v201;
DROP ROLE jw_dev_import_review_executor_v201;
DROP ROLE jw_dev_import_approval_owner_v201;
COMMIT;
