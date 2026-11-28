-- Fresh disposable queue fixture ONLY; apply after Wave11 queue_schema_ci.sql,
-- before any jobs exist. No production migration or authorization.
DO $$ BEGIN
 IF current_database() !~ '^jw_v112_ci_[0-9a-f]{12}$' OR session_user<>'postgres'
 OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR current_setting('naruv.ocr_digest_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'OCR_DIGEST_DISPOSABLE_ONLY'; END IF;
 IF EXISTS(SELECT 1 FROM jw_dev.ocr_jobs_v112) THEN RAISE EXCEPTION 'OCR_DIGEST_FRESH_QUEUE_ONLY'; END IF;
END $$;
SET ROLE wave11_ocr_owner;
ALTER TABLE jw_dev.ocr_jobs_v112 ADD COLUMN result_sha256 text CHECK(result_sha256 ~ '^[0-9a-f]{64}$');
ALTER TABLE jw_dev.ocr_jobs_v112 ADD CONSTRAINT ocr_result_digest_state CHECK ((state='needs_review')=(result_sha256 IS NOT NULL));
CREATE FUNCTION jw_dev.wave12_result_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF OLD.state='needs_review' AND NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'OCR_RESULT_IMMUTABLE' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION jw_dev.wave12_result_immutable() FROM PUBLIC;
CREATE TRIGGER wave12_result_immutable BEFORE UPDATE ON jw_dev.ocr_jobs_v112 FOR EACH ROW EXECUTE FUNCTION jw_dev.wave12_result_immutable();
GRANT UPDATE(result_sha256) ON jw_dev.ocr_jobs_v112 TO wave11_queue_a,wave11_queue_b;
RESET ROLE;
