-- V20.1 PROPOSED DEV MIGRATION. DO NOT APPLY TO SHARED/REAL DATABASE
-- without separate permission, explicit review and verified rollback.
-- Never enroll secrets or grant LOGIN/membership in this phase.
-- Designed against read-only observed jw_dev.import_previews 12-column shape.
BEGIN;
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';
DO $guard$
DECLARE cnt int;
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='jw_dev' AND c.relname='import_previews'
     AND c.relrowsecurity AND c.relforcerowsecurity) THEN
   RAISE EXCEPTION 'BLOCKED_V201_FORCE_RLS_REQUIRED';
 END IF;
 SELECT count(*) INTO cnt FROM information_schema.columns
   WHERE table_schema='jw_dev' AND table_name='import_previews';
 IF cnt<>12 THEN RAISE EXCEPTION 'BLOCKED_V201_EXPECTED_12_COLUMNS'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace
     WHERE e.extname='pgcrypto' AND n.nspname='extensions') THEN
   RAISE EXCEPTION 'BLOCKED_V201_PINNED_CRYPTO_EXTENSION_MISSING';
 END IF;
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN
 ('jw_dev_import_writer_v201','jw_dev_import_review_executor_v201',
  'jw_dev_import_approval_owner_v201')) THEN
   RAISE EXCEPTION 'BLOCKED_V201_ROLE_ALREADY_EXISTS';
 END IF;
 IF has_table_privilege('jw_app_dev','jw_dev.import_previews','INSERT')
 OR has_table_privilege('jw_app_dev','jw_dev.import_previews','UPDATE')
 OR has_table_privilege('anon','jw_dev.import_previews','INSERT')
 OR has_table_privilege('authenticated','jw_dev.import_previews','INSERT') THEN
   RAISE EXCEPTION 'BLOCKED_V201_EXISTING_PRIVILEGES_WIDENED';
 END IF;
 IF EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='jw_dev'
 AND tablename='import_previews' AND cmd='INSERT') THEN
   RAISE EXCEPTION 'BLOCKED_V201_UNEXPECTED_INSERT_POLICY';
 END IF;
END $guard$;
CREATE ROLE jw_dev_import_writer_v201 NOLOGIN NOINHERIT NOBYPASSRLS
 NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE jw_dev_import_review_executor_v201 NOLOGIN NOINHERIT NOBYPASSRLS
 NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE jw_dev_import_approval_owner_v201 NOLOGIN NOINHERIT NOBYPASSRLS
 NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE UNIQUE INDEX v201_pending_source_unique ON jw_dev.import_previews(org_id,file_sha256)
 WHERE status='pending';
GRANT USAGE ON SCHEMA jw_dev TO jw_dev_import_writer_v201,
 jw_dev_import_review_executor_v201,jw_dev_import_approval_owner_v201;
GRANT SELECT(id,org_id,file_sha256,status)
 ON jw_dev.import_previews TO jw_dev_import_writer_v201;
GRANT INSERT(id,org_id,uploaded_by,file_sha256,filename,normalized_json,
 preview_digest,status,created_at) ON jw_dev.import_previews
 TO jw_dev_import_writer_v201;
GRANT EXECUTE ON FUNCTION jw_dev.current_org_from_session(),
 jw_dev.current_actor_from_session_v82()
 TO jw_dev_import_writer_v201,jw_dev_import_approval_owner_v201;
CREATE POLICY v201_verified_writer_read ON jw_dev.import_previews
 FOR SELECT TO jw_dev_import_writer_v201
 USING(org_id=jw_dev.current_org_from_session());
CREATE POLICY v201_verified_writer_insert ON jw_dev.import_previews
 FOR INSERT TO jw_dev_import_writer_v201
 WITH CHECK(
  org_id=jw_dev.current_org_from_session()
  AND uploaded_by=jw_dev.current_actor_from_session_v82()
  AND status='pending' AND quote_id IS NULL AND order_id IS NULL
  AND confirmed_at IS NULL
  AND id ~ '^[a-f0-9]{32}$'
  AND file_sha256 ~ '^[a-f0-9]{64}$'
  AND preview_digest ~ '^[a-f0-9]{64}$'
  AND length(filename) BETWEEN 5 AND 120
  AND position('/' in filename)=0
  AND position(chr(92) in filename)=0
  AND lower(right(filename,5))='.xlsx'
  AND length(created_at) BETWEEN 20 AND 40);
-- Approval owner cannot login, cannot bypass RLS; only one-column UPDATE.
GRANT SELECT(id,org_id,uploaded_by,status,preview_digest,quote_id)
 ON jw_dev.import_previews TO jw_dev_import_approval_owner_v201;
GRANT UPDATE(status) ON jw_dev.import_previews TO jw_dev_import_approval_owner_v201;
CREATE POLICY v201_owner_read ON jw_dev.import_previews
 FOR SELECT TO jw_dev_import_approval_owner_v201
 USING(org_id=jw_dev.current_org_from_session()
   AND uploaded_by=jw_dev.current_actor_from_session_v82());
CREATE POLICY v201_owner_transition ON jw_dev.import_previews
 FOR UPDATE TO jw_dev_import_approval_owner_v201
 USING(org_id=jw_dev.current_org_from_session()
   AND uploaded_by=jw_dev.current_actor_from_session_v82()
   AND status='pending' AND quote_id IS NULL)
 WITH CHECK(org_id=jw_dev.current_org_from_session()
   AND uploaded_by=jw_dev.current_actor_from_session_v82()
   AND status='confirmed' AND quote_id IS NULL);
-- NO secret enrollment: no approvals possible after schema creation.
CREATE TABLE jw_dev.v201_approval_secrets (
 name text PRIMARY KEY CHECK(name='active'),
 secret bytea NOT NULL CHECK(octet_length(secret)=32)
);
ALTER TABLE jw_dev.v201_approval_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.v201_approval_secrets FORCE ROW LEVEL SECURITY;
REVOKE ALL ON jw_dev.v201_approval_secrets FROM PUBLIC,anon,authenticated,jw_app_dev;
GRANT SELECT ON jw_dev.v201_approval_secrets TO jw_dev_import_approval_owner_v201;
CREATE POLICY v201_owner_secret ON jw_dev.v201_approval_secrets
 FOR SELECT TO jw_dev_import_approval_owner_v201 USING(name='active');
CREATE TABLE jw_dev.v201_approval_receipts(
 id text PRIMARY KEY CHECK(id ~ '^[a-f0-9]{32}$'),
 preview_id text NOT NULL UNIQUE REFERENCES jw_dev.import_previews(id),
 org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 actor_id text NOT NULL REFERENCES jw_dev.users(id),
 preview_digest text NOT NULL CHECK(preview_digest ~ '^[a-f0-9]{64}$'),
 statement text NOT NULL CHECK(length(statement) BETWEEN 50 AND 2048),
 signature text NOT NULL CHECK(signature ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE jw_dev.v201_approval_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.v201_approval_receipts FORCE ROW LEVEL SECURITY;
REVOKE ALL ON jw_dev.v201_approval_receipts FROM PUBLIC,anon,authenticated,jw_app_dev;
GRANT SELECT,INSERT ON jw_dev.v201_approval_receipts
 TO jw_dev_import_approval_owner_v201;
CREATE POLICY v201_owner_receipt_read ON jw_dev.v201_approval_receipts
 FOR SELECT TO jw_dev_import_approval_owner_v201
 USING(org_id=jw_dev.current_org_from_session()
   AND actor_id=jw_dev.current_actor_from_session_v82());
CREATE POLICY v201_owner_receipt_insert ON jw_dev.v201_approval_receipts
 FOR INSERT TO jw_dev_import_approval_owner_v201
 WITH CHECK(org_id=jw_dev.current_org_from_session()
   AND actor_id=jw_dev.current_actor_from_session_v82());
CREATE FUNCTION jw_dev.v201_reject_receipt_mutation() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog AS $reject$
BEGIN
 RAISE EXCEPTION 'V201 immutable receipt' USING ERRCODE='42501';
END $reject$;
REVOKE ALL ON FUNCTION jw_dev.v201_reject_receipt_mutation() FROM PUBLIC;
CREATE TRIGGER v201_receipt_immutable BEFORE UPDATE OR DELETE
 ON jw_dev.v201_approval_receipts FOR EACH ROW
 EXECUTE FUNCTION jw_dev.v201_reject_receipt_mutation();
GRANT CREATE ON SCHEMA jw_dev TO jw_dev_import_approval_owner_v201;
CREATE FUNCTION jw_dev.v201_confirm_import(
 p_id text,p_org text,p_actor text,p_digest text,
 p_statement text,p_signature text,p_receipt_id text
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog AS $fn$
DECLARE v_facts jsonb; v_expected text; v_id text;
BEGIN
 IF p_id !~ '^[a-f0-9]{32}$' OR p_receipt_id !~ '^[a-f0-9]{32}$'
   OR p_digest !~ '^[a-f0-9]{64}$' OR p_signature !~ '^[a-f0-9]{64}$'
   OR length(p_statement) NOT BETWEEN 50 AND 2048 THEN
  RAISE EXCEPTION 'Invalid V201 approval request' USING ERRCODE='42501';
 END IF;
 -- DB-derived authenticated identity, never org/actor freeform GUCs.
 IF p_org IS DISTINCT FROM jw_dev.current_org_from_session()
  OR p_actor IS DISTINCT FROM jw_dev.current_actor_from_session_v82() THEN
  RAISE EXCEPTION 'V201 verified session required' USING ERRCODE='42501';
 END IF;
 BEGIN v_facts:=p_statement::jsonb;
 EXCEPTION WHEN OTHERS THEN
  RAISE EXCEPTION 'Invalid V201 approval JSON' USING ERRCODE='42501';
 END;
 IF v_facts->>'schema' IS DISTINCT FROM 'jw-import-approval-v195'
  OR v_facts->>'preview_id' IS DISTINCT FROM p_id
  OR v_facts->>'org_id' IS DISTINCT FROM p_org
  OR v_facts->>'actor_id' IS DISTINCT FROM p_actor
  OR v_facts->>'preview_digest' IS DISTINCT FROM p_digest
  OR v_facts->'approved' IS DISTINCT FROM 'true'::jsonb
  OR coalesce(length(v_facts->>'company'),0)<1
  OR coalesce(v_facts->>'quote_date','') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}
  OR coalesce(v_facts->>'total_krw','') !~ '^[0-9]{1,15}$'
  OR (v_facts->>'total_krw')::bigint < 1 THEN
  RAISE EXCEPTION 'V201 approval facts mismatch' USING ERRCODE='42501';
 END IF;
 SELECT encode(extensions.hmac(convert_to(p_statement,'UTF8'),s.secret,'sha256'),'hex')
 INTO v_expected FROM jw_dev.v201_approval_secrets s WHERE s.name='active';
 IF v_expected IS NULL OR v_expected <> p_signature THEN
  RAISE EXCEPTION 'V201 signature absent/invalid' USING ERRCODE='42501';
 END IF;
 UPDATE jw_dev.import_previews SET status='confirmed'
  WHERE id=p_id AND org_id=p_org AND uploaded_by=p_actor
  AND preview_digest=p_digest AND status='pending' AND quote_id IS NULL
 RETURNING id INTO v_id;
 IF v_id IS DISTINCT FROM p_id THEN
  RAISE EXCEPTION 'V201 missing/duplicate preview' USING ERRCODE='42501';
 END IF;
 INSERT INTO jw_dev.v201_approval_receipts
 (id,preview_id,org_id,actor_id,preview_digest,statement,signature)
 VALUES(p_receipt_id,p_id,p_org,p_actor,p_digest,p_statement,p_signature);
 RETURN p_receipt_id;
END $fn$;
REVOKE ALL ON FUNCTION jw_dev.v201_confirm_import(
 text,text,text,text,text,text,text) FROM PUBLIC,anon,authenticated,jw_app_dev;
ALTER FUNCTION jw_dev.v201_confirm_import(
 text,text,text,text,text,text,text) OWNER TO jw_dev_import_approval_owner_v201;
REVOKE CREATE ON SCHEMA jw_dev FROM jw_dev_import_approval_owner_v201;
GRANT EXECUTE ON FUNCTION jw_dev.v201_confirm_import(
 text,text,text,text,text,text,text) TO jw_dev_import_review_executor_v201;
-- Critical: writer, executor and owner remain NOLOGIN, have no memberships.
-- No approval secret rows, no live API credentials or routes enabled.
COMMIT;

  OR coalesce(v_facts->>'total_krw','') !~ '^[0-9]{1,15}$'
  OR (v_facts->>'total_krw')::bigint < 1 THEN
  RAISE EXCEPTION 'V201 approval facts mismatch' USING ERRCODE='42501';
 END IF;
 SELECT encode(extensions.hmac(convert_to(p_statement,'UTF8'),s.secret,'sha256'),'hex')
 INTO v_expected FROM jw_dev.v201_approval_secrets s WHERE s.name='active';
 IF v_expected IS NULL OR v_expected <> p_signature THEN
  RAISE EXCEPTION 'V201 signature absent/invalid' USING ERRCODE='42501';
 END IF;
 UPDATE jw_dev.import_previews SET status='confirmed'
  WHERE id=p_id AND org_id=p_org AND uploaded_by=p_actor
  AND preview_digest=p_digest AND status='pending' AND quote_id IS NULL
 RETURNING id INTO v_id;
 IF v_id IS DISTINCT FROM p_id THEN
  RAISE EXCEPTION 'V201 missing/duplicate preview' USING ERRCODE='42501';
 END IF;
 INSERT INTO jw_dev.v201_approval_receipts
 (id,preview_id,org_id,actor_id,preview_digest,statement,signature)
 VALUES(p_receipt_id,p_id,p_org,p_actor,p_digest,p_statement,p_signature);
 RETURN p_receipt_id;
END $fn$;
REVOKE ALL ON FUNCTION jw_dev.v201_confirm_import(
 text,text,text,text,text,text,text) FROM PUBLIC,anon,authenticated,jw_app_dev;
ALTER FUNCTION jw_dev.v201_confirm_import(
 text,text,text,text,text,text,text) OWNER TO jw_dev_import_approval_owner_v201;
REVOKE CREATE ON SCHEMA jw_dev FROM jw_dev_import_approval_owner_v201;
GRANT EXECUTE ON FUNCTION jw_dev.v201_confirm_import(
 text,text,text,text,text,text,text) TO jw_dev_import_review_executor_v201;
-- Critical: writer, executor and owner remain NOLOGIN, have no memberships.
-- No approval secret rows, no live API credentials or routes enabled.
COMMIT;
