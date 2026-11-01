-- V19.5 ONLY: disposable isolated local PostgreSQL17 CI fixture.
-- No real Supabase/Render/main permissions, tables, roles, keys are changed.
-- Only a function-owned, signed and atomic approval transition may write status.
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
REVOKE UPDATE(status) ON jw_dev.import_previews FROM jw_ci_v194_approver;
DROP POLICY v194_approver_transition ON jw_dev.import_previews;
CREATE ROLE jw_ci_v195_proof_owner NOLOGIN NOINHERIT NOBYPASSRLS
  NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT USAGE,CREATE ON SCHEMA jw_dev TO jw_ci_v195_proof_owner;
GRANT SELECT (id,org_id,uploaded_by,status,preview_digest,quote_id),
  UPDATE(status) ON jw_dev.import_previews TO jw_ci_v195_proof_owner;
CREATE POLICY v195_owner_select ON jw_dev.import_previews
 FOR SELECT TO jw_ci_v195_proof_owner
 USING (org_id=current_setting('jw.approval_org',true)
    AND uploaded_by=current_setting('jw.approval_actor',true));
CREATE POLICY v195_owner_update ON jw_dev.import_previews
 FOR UPDATE TO jw_ci_v195_proof_owner
 USING (org_id=current_setting('jw.approval_org',true)
    AND uploaded_by=current_setting('jw.approval_actor',true)
    AND status='pending' AND quote_id IS NULL)
 WITH CHECK (org_id=current_setting('jw.approval_org',true)
    AND uploaded_by=current_setting('jw.approval_actor',true)
    AND status='confirmed' AND quote_id IS NULL);

CREATE TABLE jw_dev.v195_approval_secrets(
  name text PRIMARY KEY,secret bytea NOT NULL CHECK(octet_length(secret)=32)
);
ALTER TABLE jw_dev.v195_approval_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.v195_approval_secrets FORCE ROW LEVEL SECURITY;
REVOKE ALL ON jw_dev.v195_approval_secrets FROM PUBLIC;
GRANT SELECT ON jw_dev.v195_approval_secrets TO jw_ci_v195_proof_owner;
CREATE POLICY v195_secret_owner_read ON jw_dev.v195_approval_secrets
 FOR SELECT TO jw_ci_v195_proof_owner USING (name='active');

CREATE TABLE jw_dev.v195_approval_receipts(
  id text PRIMARY KEY CHECK(id ~ '^[a-f0-9]{32}$'),
  preview_id text NOT NULL UNIQUE REFERENCES jw_dev.import_previews(id),
  org_id text NOT NULL,
  actor_id text NOT NULL,
  preview_digest text NOT NULL CHECK(preview_digest ~ '^[a-f0-9]{64}$'),
  statement text NOT NULL CHECK(length(statement) BETWEEN 50 AND 2048),
  signature text NOT NULL CHECK(signature ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE jw_dev.v195_approval_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.v195_approval_receipts FORCE ROW LEVEL SECURITY;
REVOKE ALL ON jw_dev.v195_approval_receipts FROM PUBLIC;
GRANT INSERT,SELECT ON jw_dev.v195_approval_receipts TO jw_ci_v195_proof_owner;
CREATE POLICY v195_receipt_owner_read ON jw_dev.v195_approval_receipts
 FOR SELECT TO jw_ci_v195_proof_owner
 USING (org_id=current_setting('jw.approval_org',true)
    AND actor_id=current_setting('jw.approval_actor',true));
CREATE POLICY v195_receipt_owner_insert ON jw_dev.v195_approval_receipts
 FOR INSERT TO jw_ci_v195_proof_owner
 WITH CHECK (org_id=current_setting('jw.approval_org',true)
    AND actor_id=current_setting('jw.approval_actor',true));

CREATE FUNCTION jw_dev.v195_reject_receipt_mutation() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog AS $immutable$
BEGIN
  RAISE EXCEPTION 'Approval receipt immutable' USING ERRCODE='42501';
END $immutable$;
CREATE TRIGGER v195_receipt_immutable BEFORE UPDATE OR DELETE
 ON jw_dev.v195_approval_receipts FOR EACH ROW
 EXECUTE FUNCTION jw_dev.v195_reject_receipt_mutation();

CREATE FUNCTION jw_dev.v195_confirm_import(
  p_id text,p_org text,p_actor text,p_digest text,
  p_statement text,p_signature text,p_receipt_id text
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog AS $approval$
DECLARE v_details jsonb;v_expected text;v_updated text;
BEGIN
  IF p_id !~ '^[a-f0-9]{32}$' OR p_receipt_id !~ '^[a-f0-9]{32}$'
    OR p_digest !~ '^[a-f0-9]{64}$' OR p_signature !~ '^[a-f0-9]{64}$'
    OR length(p_statement) NOT BETWEEN 50 AND 2048
  THEN RAISE EXCEPTION 'Invalid approval request' USING ERRCODE='42501'; END IF;
  BEGIN
    v_details := p_statement::jsonb;
  EXCEPTION WHEN others THEN
    RAISE EXCEPTION 'Invalid approval payload' USING ERRCODE='42501';
  END;
  IF v_details->>'schema' <> 'jw-import-approval-v195'
      OR v_details->>'preview_id' <> p_id
      OR v_details->>'org_id' <> p_org
      OR v_details->>'actor_id' <> p_actor
      OR v_details->>'preview_digest' <> p_digest
      OR v_details->>'approved' <> 'true'
      OR coalesce(length(v_details->>'company'),0) < 1
      OR coalesce(length(v_details->>'quote_date'),0) <> 10
      OR coalesce((v_details->>'total_krw')::bigint,0) < 1
  THEN RAISE EXCEPTION 'Approval facts mismatch' USING ERRCODE='42501'; END IF;
  SELECT pg_catalog.encode(public.hmac(
    pg_catalog.convert_to(p_statement,'UTF8'),s.secret,'sha256'),'hex')
    INTO v_expected
    FROM jw_dev.v195_approval_secrets s WHERE s.name='active';
  IF v_expected IS NULL OR v_expected <> p_signature
  THEN RAISE EXCEPTION 'Approval signature invalid' USING ERRCODE='42501'; END IF;
  PERFORM pg_catalog.set_config('jw.approval_org',p_org,true);
  PERFORM pg_catalog.set_config('jw.approval_actor',p_actor,true);
  UPDATE jw_dev.import_previews SET status='confirmed'
   WHERE id=p_id AND org_id=p_org AND uploaded_by=p_actor
     AND preview_digest=p_digest AND status='pending' AND quote_id IS NULL
   RETURNING id INTO v_updated;
  IF v_updated IS DISTINCT FROM p_id
  THEN RAISE EXCEPTION 'Invalid or duplicate approval' USING ERRCODE='42501'; END IF;
  INSERT INTO jw_dev.v195_approval_receipts(
     id,preview_id,org_id,actor_id,preview_digest,statement,signature
  ) VALUES (p_receipt_id,p_id,p_org,p_actor,p_digest,p_statement,p_signature);
  RETURN p_receipt_id;
END $approval$;
REVOKE ALL ON FUNCTION jw_dev.v195_confirm_import(
 text,text,text,text,text,text,text) FROM PUBLIC,anon,authenticated,jw_app_dev;
ALTER FUNCTION jw_dev.v195_confirm_import(
 text,text,text,text,text,text,text) OWNER TO jw_ci_v195_proof_owner;
REVOKE CREATE ON SCHEMA jw_dev FROM jw_ci_v195_proof_owner;
GRANT EXECUTE ON FUNCTION jw_dev.v195_confirm_import(
 text,text,text,text,text,text,text) TO jw_ci_v194_approver;
COMMIT;
