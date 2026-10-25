-- REVIEW/TEST ONLY. Not an approved migration or production role grant.
-- Refuses all non-disposable DBs, including Render and Supabase.
BEGIN;
DO $guard$
BEGIN
 IF current_database() !~ '^jw_v112_ci_[0-9a-f]{12}$' THEN
   RAISE EXCEPTION 'V112_REQUIRES_DISPOSABLE_CI_DATABASE';
 END IF;
 IF current_setting('server_version_num')::integer / 10000 <> 17 THEN
   RAISE EXCEPTION 'V112_REQUIRES_POSTGRESQL17';
 END IF;
END
$guard$;

-- All wake payloads are opaque routing digests. No content is sent over NOTIFY.
CREATE FUNCTION jw_dev.v112_messenger_wakeup()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog,jw_dev,pg_temp
AS $fn$
DECLARE v_connection_id text;
BEGIN
 IF TG_TABLE_NAME='messenger_messages' THEN
   v_connection_id:=NEW.connection_id;
 ELSIF TG_TABLE_NAME='messenger_edits' THEN
   SELECT m.connection_id INTO v_connection_id
     FROM jw_dev.messenger_messages m WHERE m.id=NEW.message_id;
 ELSE
   RAISE EXCEPTION 'UNEXPECTED_MESSENGER_SOURCE';
 END IF;
 IF v_connection_id IS NULL THEN
   RAISE EXCEPTION 'MISSING_MESSENGER_CONNECTION';
 END IF;
 PERFORM pg_catalog.pg_notify('jw_v112_messenger_wake',
   pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_connection_id,'UTF8')),'hex'));
 RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION jw_dev.v112_messenger_wakeup() FROM PUBLIC;
CREATE TRIGGER v112_messenger_insert_wakeup AFTER INSERT
  ON jw_dev.messenger_messages FOR EACH ROW
  EXECUTE FUNCTION jw_dev.v112_messenger_wakeup();
CREATE TRIGGER v112_messenger_edit_wakeup AFTER INSERT
  ON jw_dev.messenger_edits FOR EACH ROW
  EXECUTE FUNCTION jw_dev.v112_messenger_wakeup();

-- Tenant-bound OCR metadata pointers only.  Source/result bytes are in an
-- external access-controlled object store; no automatic financial posting.
CREATE TABLE jw_dev.ocr_jobs_v112 (
 id text PRIMARY KEY CHECK (id ~ '^[a-f0-9]{32}$'),
 org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 actor_id text NOT NULL REFERENCES jw_dev.users(id),
 object_key text NOT NULL,
 filename text NOT NULL,
 file_sha256 text NOT NULL CHECK(file_sha256 ~ '^[a-f0-9]{64}$'),
 request_id text NOT NULL,
 state text NOT NULL DEFAULT 'queued'
   CHECK(state IN ('queued','running','needs_review','failed')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
 max_attempts integer NOT NULL DEFAULT 3 CHECK(max_attempts BETWEEN 1 AND 3),
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_token text CHECK(lease_token IS NULL OR lease_token ~ '^[a-f0-9]{64}$'),
 lease_until timestamptz,
 result_key text,
 completed_at timestamptz,
 last_error_code text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(org_id,request_id),
 CHECK ((state='running')=(lease_token IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK ((state='needs_review')=(result_key IS NOT NULL))
);
CREATE INDEX v112_ocr_queue_claim_idx ON jw_dev.ocr_jobs_v112
 (available_at,id) WHERE state IN ('queued','running');
ALTER TABLE jw_dev.ocr_jobs_v112 ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.ocr_jobs_v112 FORCE ROW LEVEL SECURITY;
REVOKE ALL ON jw_dev.ocr_jobs_v112 FROM PUBLIC;
-- No policies or grants here. Worker/trade grants require independently
-- reviewed actor/tenant binding and are NOT activated by this CI-only file.
-- Consequently the proposed Python queue must remain disabled outside mocks.
COMMIT;

