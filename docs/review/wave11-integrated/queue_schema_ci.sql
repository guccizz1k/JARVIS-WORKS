-- Separate queue-only reconstruction for disposable PG17 CI.
-- The original V112 migration is not modified or executed by this candidate.
-- Test-only tenant roles exist before this script; no production grants.
DO $$ BEGIN
 IF current_database() !~ '^jw_v112_ci_[0-9a-f]{12}$'
 OR session_user<>'postgres'
 OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR current_setting('naruv.ocr_queue_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'OCR_QUEUE_DISPOSABLE_ONLY'; END IF;
END $$;
CREATE ROLE wave11_ocr_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE SCHEMA jw_dev AUTHORIZATION wave11_ocr_owner;
REVOKE ALL ON SCHEMA jw_dev FROM PUBLIC;
SET ROLE wave11_ocr_owner;
CREATE TABLE jw_dev.organizations(id text PRIMARY KEY);
CREATE TABLE jw_dev.users(id text PRIMARY KEY, org_id text NOT NULL REFERENCES jw_dev.organizations(id));
INSERT INTO jw_dev.organizations VALUES('ci-a'),('ci-b');
INSERT INTO jw_dev.users VALUES('ci-ua','ci-a'),('ci-ub','ci-b');
CREATE TABLE jw_dev.ocr_jobs_v112(
 id text PRIMARY KEY CHECK(id ~ '^[a-f0-9]{32}$'),
 org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 actor_id text NOT NULL REFERENCES jw_dev.users(id),
 object_key text NOT NULL CHECK(object_key ~ '^tenant/[A-Za-z0-9_-]{1,128}/[a-f0-9]{32}$' AND split_part(object_key,'/',2)=org_id),
 filename text NOT NULL CHECK(length(filename) BETWEEN 1 AND 150),
 file_sha256 text NOT NULL CHECK(file_sha256 ~ '^[a-f0-9]{64}$'),
 request_id text NOT NULL,
 state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','running','needs_review','failed')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
 max_attempts integer NOT NULL DEFAULT 3 CHECK(max_attempts BETWEEN 1 AND 3),
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_token text CHECK(lease_token IS NULL OR lease_token ~ '^[a-f0-9]{64}$'),
 lease_until timestamptz,
 result_key text CHECK(result_key IS NULL OR (result_key ~ '^tenant/[A-Za-z0-9_-]{1,128}/ocr-result/[a-f0-9]{32}/[a-f0-9]{64}$' AND split_part(result_key,'/',2)=org_id AND split_part(result_key,'/',4)=id)),
 completed_at timestamptz,
 last_error_code text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(org_id,request_id),
 CHECK((state='running')=(lease_token IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK((state='needs_review')=(result_key IS NOT NULL))
);
CREATE FUNCTION jw_dev.v112_guard_ocr_job_tenant() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v_actor_org text;
BEGIN
 IF TG_OP='UPDATE' AND (NEW.org_id,NEW.actor_id,NEW.object_key,NEW.file_sha256,NEW.request_id,NEW.filename)
 IS DISTINCT FROM (OLD.org_id,OLD.actor_id,OLD.object_key,OLD.file_sha256,OLD.request_id,OLD.filename)
 THEN RAISE EXCEPTION 'OCR_JOB_SOURCE_IMMUTABLE' USING ERRCODE='23514'; END IF;
 SELECT org_id INTO v_actor_org FROM jw_dev.users WHERE id=NEW.actor_id;
 IF v_actor_org IS NULL OR v_actor_org IS DISTINCT FROM NEW.org_id THEN
 RAISE EXCEPTION 'OCR_JOB_TENANT_MISMATCH' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' AND NEW.state='needs_review' AND (OLD.state<>'running' OR OLD.lease_until<=clock_timestamp()
 OR NEW.result_key IS DISTINCT FROM 'tenant/'||OLD.org_id||'/ocr-result/'||OLD.id||'/'||OLD.lease_token)
 THEN RAISE EXCEPTION 'OCR_JOB_RESULT_LEASE' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION jw_dev.v112_guard_ocr_job_tenant() FROM PUBLIC;
CREATE TRIGGER v112_ocr_tenant_guard BEFORE INSERT OR UPDATE ON jw_dev.ocr_jobs_v112 FOR EACH ROW EXECUTE FUNCTION jw_dev.v112_guard_ocr_job_tenant();
CREATE INDEX v112_ocr_queue_claim_idx ON jw_dev.ocr_jobs_v112(available_at,id) WHERE state IN ('queued','running');
ALTER TABLE jw_dev.ocr_jobs_v112 ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.ocr_jobs_v112 FORCE ROW LEVEL SECURITY;
REVOKE ALL ON jw_dev.ocr_jobs_v112 FROM PUBLIC;
CREATE POLICY queue_fixture_a ON jw_dev.ocr_jobs_v112 TO wave11_queue_a USING(org_id='ci-a') WITH CHECK(org_id='ci-a');
CREATE POLICY queue_fixture_b ON jw_dev.ocr_jobs_v112 TO wave11_queue_b USING(org_id='ci-b') WITH CHECK(org_id='ci-b');
GRANT USAGE ON SCHEMA jw_dev TO wave11_queue_a,wave11_queue_b;
GRANT SELECT ON jw_dev.ocr_jobs_v112 TO wave11_queue_a,wave11_queue_b;
GRANT INSERT(id,org_id,actor_id,object_key,filename,file_sha256,request_id,state,available_at),
 UPDATE(state,attempts,lease_token,lease_until,available_at,result_key,completed_at,last_error_code)
 ON jw_dev.ocr_jobs_v112 TO wave11_queue_a,wave11_queue_b;
RESET ROLE;
