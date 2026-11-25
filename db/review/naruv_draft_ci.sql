-- Disposable PG17 synthetic read-only sources. Never install against customer data.
DO $$ BEGIN
 IF current_database()<>'postgres' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user<>'postgres' OR current_setting('naruv.draft_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'DRAFT_DISPOSABLE_ONLY'; END IF;
END $$;
CREATE SCHEMA naruv_draft AUTHORIZATION naruv_native_owner;
REVOKE ALL ON SCHEMA naruv_draft FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT USAGE ON SCHEMA naruv_draft TO jw_app_dev;
SET ROLE naruv_native_owner;
CREATE TABLE naruv_draft.documents(
 org_id text NOT NULL, document_id text NOT NULL, revision text NOT NULL,
 original_bytes bytea NOT NULL CHECK(octet_length(original_bytes) BETWEEN 1 AND 1048576),
 original_sha256 text NOT NULL CHECK(original_sha256 ~ '^[0-9a-f]{64}$'),
 observations jsonb NOT NULL CHECK(jsonb_typeof(observations)='array' AND octet_length(observations::text)<=32768),
 active boolean NOT NULL,PRIMARY KEY(org_id,document_id));
CREATE TABLE naruv_draft.staff(
 org_id text NOT NULL,worker_id text NOT NULL,active boolean NOT NULL,
 PRIMARY KEY(org_id,worker_id));
CREATE TABLE naruv_draft.pay_periods(
 org_id text NOT NULL,worker_id text NOT NULL,period text NOT NULL,
 revision text NOT NULL,hourly_krw bigint NOT NULL CHECK(hourly_krw BETWEEN 1 AND 100000000),
 additional_bps int NOT NULL CHECK(additional_bps BETWEEN 1 AND 50000),
 confirmed boolean NOT NULL,PRIMARY KEY(org_id,worker_id,period),
 FOREIGN KEY(org_id,worker_id) REFERENCES naruv_draft.staff);
CREATE TABLE naruv_draft.attendance(
 org_id text NOT NULL,worker_id text NOT NULL,period text NOT NULL,work_day date NOT NULL,
 regular int NOT NULL CHECK(regular BETWEEN 0 AND 1440),additional int NOT NULL CHECK(additional BETWEEN 0 AND 1440),
 CHECK(regular+additional<=1440),CHECK(to_char(work_day,'YYYY-MM')=period),
 PRIMARY KEY(org_id,worker_id,period,work_day),
 FOREIGN KEY(org_id,worker_id,period) REFERENCES naruv_draft.pay_periods);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['documents','staff','pay_periods','attendance'] LOOP
  EXECUTE format('ALTER TABLE naruv_draft.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE naruv_draft.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY draft_scope ON naruv_draft.%I TO naruv_native_owner USING (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin'')) WITH CHECK (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin''))',t);
  EXECUTE format('REVOKE ALL ON naruv_draft.%I FROM PUBLIC,jw_app_dev,naruv_native_stage',t);
 END LOOP;
END $$;
CREATE FUNCTION naruv_draft.document_source(p_id text,p_csrf text)
 RETURNS TABLE(revision text,original_bytes bytea,original_sha256 text,observations jsonb)
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_id IS NULL OR p_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' THEN RAISE EXCEPTION 'DRAFT_INPUT'; END IF;
 RETURN QUERY SELECT d.revision,d.original_bytes,d.original_sha256,d.observations FROM naruv_draft.documents d
 WHERE d.org_id=a.org_id AND d.document_id=p_id AND d.active;
END $$;
CREATE FUNCTION naruv_draft.pay_source(p_worker text,p_period text,p_csrf text)
 RETURNS TABLE(revision text,hourly_krw bigint,additional_bps int,days jsonb)
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_worker IS NULL OR p_worker !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_period IS NULL OR p_period !~ '^[0-9]{4}-(0[1-9]|1[0-2])$' THEN RAISE EXCEPTION 'DRAFT_INPUT'; END IF;
 RETURN QUERY SELECT p.revision,p.hourly_krw,p.additional_bps,
 (SELECT coalesce(jsonb_agg(jsonb_build_object('date',to_char(d.work_day,'YYYY-MM-DD'),'regular',d.regular,'additional',d.additional) ORDER BY d.work_day),'[]'::jsonb)
 FROM naruv_draft.attendance d WHERE (d.org_id,d.worker_id,d.period)=(p.org_id,p.worker_id,p.period))
 FROM naruv_draft.pay_periods p JOIN naruv_draft.staff s USING(org_id,worker_id)
 WHERE p.org_id=a.org_id AND p.worker_id=p_worker AND p.period=p_period AND p.confirmed AND s.active;
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA naruv_draft FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_draft.document_source(text,text),naruv_draft.pay_source(text,text,text) TO jw_app_dev;
-- Bounded opaque original registration; no parser, OCR, or automatic posting.
CREATE TABLE naruv_draft.document_admissions(
 org_id text NOT NULL,document_id text NOT NULL,request_id text NOT NULL,actor_id text NOT NULL,
 format text NOT NULL CHECK(format IN ('pdf','xlsx')),source_sha256 text NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
 observation_sha256 text NOT NULL CHECK(observation_sha256 ~ '^[0-9a-f]{64}$'),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(org_id,document_id),UNIQUE(org_id,request_id),
 FOREIGN KEY(org_id,document_id) REFERENCES naruv_draft.documents);
ALTER TABLE naruv_draft.document_admissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_draft.document_admissions FORCE ROW LEVEL SECURITY;
CREATE POLICY document_admission_scope ON naruv_draft.document_admissions TO naruv_native_owner
 USING(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))
 WITH CHECK(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
REVOKE ALL ON naruv_draft.document_admissions FROM PUBLIC,jw_app_dev,naruv_native_stage;
CREATE TRIGGER document_admission_immutable BEFORE UPDATE OR DELETE ON naruv_draft.document_admissions
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE FUNCTION naruv_draft.admit_document(p_doc text,p_request text,p_format text,p_raw bytea,p_observations jsonb,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; r naruv_draft.document_admissions; d naruv_draft.documents; sha text; obs_sha text; v jsonb; field text; n bigint; total bigint;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_doc IS NULL OR p_doc !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_format IS NULL OR p_format NOT IN ('pdf','xlsx') OR p_raw IS NULL OR octet_length(p_raw) NOT BETWEEN 5 AND 524288
 OR p_confirm IS DISTINCT FROM true OR jsonb_typeof(p_observations) IS DISTINCT FROM 'array'
 OR octet_length(p_observations::text)>32768 THEN RAISE EXCEPTION 'DOC_INPUT'; END IF;
 IF jsonb_array_length(p_observations) NOT BETWEEN 1 AND 128 OR
 (p_format='pdf' AND substring(p_raw from 1 for 5)<>decode('255044462d','hex')) OR
 (p_format='xlsx' AND substring(p_raw from 1 for 4)<>decode('504b0304','hex'))
 THEN RAISE EXCEPTION 'DOC_INPUT'; END IF;
 FOR v IN SELECT value FROM jsonb_array_elements(p_observations) LOOP
  IF jsonb_typeof(v) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'DOC_INPUT'; END IF;
  IF NOT v ?& ARRAY['field','value','page'] OR v-ARRAY['field','value','page']<>'{}'::jsonb
   OR jsonb_typeof(v->'field') IS DISTINCT FROM 'string' OR jsonb_typeof(v->'page') IS DISTINCT FROM 'number'
   OR (v->>'page') !~ '^[0-9]{1,4}$' THEN RAISE EXCEPTION 'DOC_INPUT'; END IF;
  IF (v->>'page')::int NOT BETWEEN 1 AND 1000 THEN RAISE EXCEPTION 'DOC_INPUT'; END IF;
  field:=v->>'field';
  IF field IN ('subtotal','vat','gross_amount') THEN
   IF jsonb_typeof(v->'value') IS DISTINCT FROM 'number' OR (v->>'value') !~ '^[0-9]{1,13}$' THEN RAISE EXCEPTION 'DOC_INPUT'; END IF;
   IF (v->>'value')::numeric>1000000000000 THEN RAISE EXCEPTION 'DOC_INPUT'; END IF;
  ELSIF field IN ('document_kind','counterparty_id','document_date','reference_number') THEN
   IF jsonb_typeof(v->'value') IS DISTINCT FROM 'string' OR (v->>'value') !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' THEN RAISE EXCEPTION 'DOC_INPUT'; END IF;
   IF field='document_kind' AND v->>'value' NOT IN ('quote','purchase_order','delivery_statement','invoice','transaction_statement') THEN RAISE EXCEPTION 'DOC_INPUT'; END IF;
   IF field='document_date' AND (v->>'value') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' THEN RAISE EXCEPTION 'DOC_INPUT'; END IF;
  ELSE RAISE EXCEPTION 'DOC_INPUT'; END IF;
 END LOOP;
 sha:=encode(sha256(p_raw),'hex');obs_sha:=encode(sha256(convert_to(p_observations::text,'UTF8')),'hex');
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-document-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO r FROM naruv_draft.document_admissions x WHERE x.org_id=a.org_id AND x.request_id=p_request;
 IF FOUND THEN
  IF (r.actor_id,r.document_id,r.format,r.source_sha256,r.observation_sha256)
    IS DISTINCT FROM (a.actor_id,p_doc,p_format,sha,obs_sha) THEN RAISE EXCEPTION 'DOC_CONFLICT'; END IF;
  SELECT * INTO d FROM naruv_draft.documents x WHERE (x.org_id,x.document_id)=(a.org_id,p_doc);
  IF NOT FOUND OR NOT d.active OR d.original_bytes IS DISTINCT FROM p_raw OR d.original_sha256 IS DISTINCT FROM sha
   OR d.observations IS DISTINCT FROM p_observations OR d.revision IS DISTINCT FROM p_request THEN RAISE EXCEPTION 'DOC_CONFLICT'; END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM naruv_draft.documents x WHERE (x.org_id,x.document_id)=(a.org_id,p_doc))
  THEN RAISE EXCEPTION 'DOC_CONFLICT'; END IF;
  SELECT count(*),coalesce(sum(octet_length(x.original_bytes)),0) INTO n,total FROM naruv_draft.documents x WHERE x.org_id=a.org_id;
  IF n>=1000 OR total+octet_length(p_raw)>67108864 THEN RAISE EXCEPTION 'DOC_CAPACITY'; END IF;
  INSERT INTO naruv_draft.documents VALUES(a.org_id,p_doc,p_request,p_raw,sha,p_observations,true);
  INSERT INTO naruv_draft.document_admissions(org_id,document_id,request_id,actor_id,format,source_sha256,observation_sha256)
   VALUES(a.org_id,p_doc,p_request,a.actor_id,p_format,sha,obs_sha);
 END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN jsonb_build_object('status','SOURCE_REGISTERED_FOR_MANUAL_REVIEW','document_id',p_doc,'request_id',p_request,
 'source_sha256',sha,'posting_authorized',false,'production_authorized',false,'requires_human_review',true,'content_verified',false);
END $$;
REVOKE ALL ON FUNCTION naruv_draft.admit_document(text,text,text,bytea,jsonb,boolean,text) FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_draft.admit_document(text,text,text,bytea,jsonb,boolean,text) TO jw_app_dev;
RESET ROLE;
