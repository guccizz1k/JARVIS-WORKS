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
RESET ROLE;
