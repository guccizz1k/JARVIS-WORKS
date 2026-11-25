-- Synthetic PG17 attendance admission only; no personnel PII or payroll posting.
DO $$ BEGIN
 IF current_database()<>'postgres' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user<>'postgres' OR current_setting('naruv.hr_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'HR_DISPOSABLE_ONLY'; END IF;
END $$;
SET ROLE naruv_native_owner;
CREATE TABLE naruv_draft.attendance_receipts(
 org_id text NOT NULL,request_id text NOT NULL,actor_id text NOT NULL,
 worker_id text NOT NULL,period text NOT NULL,work_day date NOT NULL,
 regular int NOT NULL CHECK(regular BETWEEN 0 AND 1440),
 additional int NOT NULL CHECK(additional BETWEEN 0 AND 1440),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(regular+additional<=1440),
 PRIMARY KEY(org_id,request_id),
 UNIQUE(org_id,worker_id,period,work_day),
 FOREIGN KEY(org_id,worker_id,period,work_day) REFERENCES naruv_draft.attendance);
ALTER TABLE naruv_draft.attendance_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_draft.attendance_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY attendance_receipt_scope ON naruv_draft.attendance_receipts TO naruv_native_owner
 USING(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))
 WITH CHECK(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
REVOKE ALL ON naruv_draft.attendance_receipts FROM PUBLIC,jw_app_dev,naruv_native_stage;
CREATE TRIGGER attendance_receipt_immutable BEFORE UPDATE OR DELETE ON naruv_draft.attendance_receipts
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();

CREATE FUNCTION naruv_draft.admit_attendance(p_worker text,p_period text,p_request text,p_day text,p_regular int,p_additional int,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; r naruv_draft.attendance_receipts; d date; closed boolean;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_worker IS NULL OR p_worker !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_period IS NULL OR p_period !~ '^[0-9]{4}-(0[1-9]|1[0-2])$'
 OR p_day IS NULL OR p_day !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
 OR left(p_day,7)<>p_period OR p_regular IS NULL OR p_additional IS NULL
 OR p_regular NOT BETWEEN 0 AND 1440 OR p_additional NOT BETWEEN 0 AND 1440
 OR p_regular::bigint+p_additional::bigint>1440 OR p_confirm IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
 BEGIN d:=p_day::date; EXCEPTION WHEN datetime_field_overflow OR invalid_datetime_format THEN RAISE EXCEPTION 'HR_INPUT'; END;
 IF to_char(d,'YYYY-MM-DD')<>p_day THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-attendance-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO r FROM naruv_draft.attendance_receipts x WHERE x.org_id=a.org_id AND x.request_id=p_request;
 IF FOUND THEN
  IF (r.actor_id,r.worker_id,r.period,r.work_day,r.regular,r.additional)
  IS DISTINCT FROM (a.actor_id,p_worker,p_period,d,p_regular,p_additional) THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
 ELSE
  PERFORM 1 FROM naruv_draft.staff s WHERE s.org_id=a.org_id AND s.worker_id=p_worker AND s.active FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'HR_NOT_FOUND'; END IF;
  SELECT p.confirmed INTO closed FROM naruv_draft.pay_periods p
   WHERE p.org_id=a.org_id AND p.worker_id=p_worker AND p.period=p_period FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'HR_NOT_FOUND'; END IF;
  IF closed THEN RAISE EXCEPTION 'HR_PERIOD_CONFIRMED'; END IF;
  IF EXISTS(SELECT 1 FROM naruv_draft.attendance x WHERE (x.org_id,x.worker_id,x.period,x.work_day)=(a.org_id,p_worker,p_period,d))
   THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
  INSERT INTO naruv_draft.attendance VALUES(a.org_id,p_worker,p_period,d,p_regular,p_additional);
  INSERT INTO naruv_draft.attendance_receipts(org_id,request_id,actor_id,worker_id,period,work_day,regular,additional)
   VALUES(a.org_id,p_request,a.actor_id,p_worker,p_period,d,p_regular,p_additional) RETURNING * INTO r;
 END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN jsonb_build_object('status','ATTENDANCE_RECORDED','request_id',r.request_id,
 'worker_id',r.worker_id,'period',r.period,'date',to_char(r.work_day,'YYYY-MM-DD'),
 'regular',r.regular,'additional',r.additional,'payment_authorized',false,'production_authorized',false);
END $$;
REVOKE ALL ON FUNCTION naruv_draft.admit_attendance(text,text,text,text,int,int,boolean,text) FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_draft.admit_attendance(text,text,text,text,int,int,boolean,text) TO jw_app_dev;
-- Confirmation freezes a reviewed snapshot, not an actual payroll payment.
CREATE TABLE naruv_draft.period_confirmations(
 org_id text NOT NULL,worker_id text NOT NULL,period text NOT NULL,
 request_id text NOT NULL,actor_id text NOT NULL,review_sha256 text NOT NULL CHECK(review_sha256 ~ '^[0-9a-f]{64}$'),
 confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(org_id,worker_id,period),UNIQUE(org_id,request_id),
 FOREIGN KEY(org_id,worker_id,period) REFERENCES naruv_draft.pay_periods);
ALTER TABLE naruv_draft.period_confirmations ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_draft.period_confirmations FORCE ROW LEVEL SECURITY;
CREATE POLICY confirmation_scope ON naruv_draft.period_confirmations TO naruv_native_owner
 USING(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))
 WITH CHECK(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
REVOKE ALL ON naruv_draft.period_confirmations FROM PUBLIC,jw_app_dev,naruv_native_stage;
CREATE TRIGGER period_confirmation_immutable BEFORE UPDATE OR DELETE ON naruv_draft.period_confirmations
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();

CREATE FUNCTION naruv_draft.period_digest(p_org text,p_worker text,p_period text,p_revision text,p_rate bigint,p_bps int,p_rows jsonb)
 RETURNS text LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT encode(sha256(convert_to(jsonb_build_array('naruv-period-review-v1',p_org,p_worker,p_period,p_revision,p_rate,p_bps,p_rows)::text,'UTF8')),'hex')
$$;
REVOKE ALL ON FUNCTION naruv_draft.period_digest(text,text,text,text,bigint,int,jsonb) FROM PUBLIC,jw_app_dev,naruv_native_stage;

CREATE FUNCTION naruv_draft.review_period(p_worker text,p_period text,p_request text,p_expected text,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; p naruv_draft.pay_periods; r naruv_draft.period_confirmations;
 rows jsonb; n bigint; digest text; receipt boolean:=false; active_flag boolean;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_worker IS NULL OR p_worker !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_period IS NULL OR p_period !~ '^[0-9]{4}-(0[1-9]|1[0-2])$'
 OR p_confirm IS NULL OR (p_confirm AND (p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR p_expected IS NULL OR p_expected !~ '^[0-9a-f]{64}$'))
 OR (NOT p_confirm AND (p_request IS NOT NULL OR p_expected IS NOT NULL))
 THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-attendance-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT s.active INTO active_flag FROM naruv_draft.staff s WHERE (s.org_id,s.worker_id)=(a.org_id,p_worker) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'HR_NOT_FOUND'; END IF;
 SELECT * INTO p FROM naruv_draft.pay_periods x WHERE (x.org_id,x.worker_id,x.period)=(a.org_id,p_worker,p_period) FOR UPDATE;
 IF NOT FOUND OR (NOT active_flag AND NOT p.confirmed) THEN RAISE EXCEPTION 'HR_NOT_FOUND'; END IF;
 SELECT count(*),coalesce(jsonb_agg(jsonb_build_array(to_char(d.work_day,'YYYY-MM-DD'),d.regular,d.additional) ORDER BY d.work_day),'[]'::jsonb)
 INTO n,rows FROM naruv_draft.attendance d WHERE (d.org_id,d.worker_id,d.period)=(a.org_id,p_worker,p_period);
 IF n NOT BETWEEN 1 AND 31 THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
 digest:=naruv_draft.period_digest(a.org_id,p_worker,p_period,p.revision,p.hourly_krw,p.additional_bps,rows);
 IF p.confirmed THEN
  PERFORM 1 FROM naruv_draft.period_confirmations x WHERE (x.org_id,x.worker_id,x.period)=(a.org_id,p_worker,p_period) AND x.review_sha256=digest;
  IF NOT FOUND THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
 END IF;
 IF p_confirm THEN
  SELECT * INTO r FROM naruv_draft.period_confirmations x WHERE x.org_id=a.org_id AND x.request_id=p_request;
  IF FOUND THEN
   IF (r.actor_id,r.worker_id,r.period,r.review_sha256) IS DISTINCT FROM (a.actor_id,p_worker,p_period,p_expected)
    OR NOT p.confirmed OR digest<>r.review_sha256 THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
  ELSE
   IF p.confirmed THEN RAISE EXCEPTION 'HR_PERIOD_CONFIRMED'; END IF;
   IF digest<>p_expected THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
   UPDATE naruv_draft.pay_periods x SET confirmed=true WHERE (x.org_id,x.worker_id,x.period)=(a.org_id,p_worker,p_period) AND NOT x.confirmed;
   IF NOT FOUND THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
   INSERT INTO naruv_draft.period_confirmations(org_id,worker_id,period,request_id,actor_id,review_sha256)
   VALUES(a.org_id,p_worker,p_period,p_request,a.actor_id,digest);
  END IF;
  receipt:=true;
 END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN jsonb_build_object('status',CASE WHEN receipt THEN 'PERIOD_CONFIRMED' ELSE 'PERIOD_REVIEW' END,
 'worker_id',p_worker,'period',p_period,'review_sha256',digest,'day_count',n,
 'policy_revision',p.revision,'hourly_krw',p.hourly_krw,'additional_bps',p.additional_bps,'days',rows,
 'confirmed',p.confirmed OR receipt,'payment_authorized',false,'production_authorized',false,'statutory_validated',false);
END $$;
REVOKE ALL ON FUNCTION naruv_draft.review_period(text,text,text,text,boolean,text) FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_draft.review_period(text,text,text,text,boolean,text) TO jw_app_dev;
-- Read-side confirmation proof: fail closed if the approved inputs drift.
-- This replacement preserves the original return contract and role grants.
CREATE OR REPLACE FUNCTION naruv_draft.pay_source(p_worker text,p_period text,p_csrf text)
 RETURNS TABLE(revision text,hourly_krw bigint,additional_bps int,days jsonb)
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; p naruv_draft.pay_periods; entries jsonb; pairs jsonb; proof text;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_worker IS NULL OR p_worker !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_period IS NULL OR p_period !~ '^[0-9]{4}-(0[1-9]|1[0-2])$' THEN RAISE EXCEPTION 'DRAFT_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-attendance-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 -- Historical confirmed gross-pay drafts remain accessible after archival.
 PERFORM 1 FROM naruv_draft.staff s WHERE (s.org_id,s.worker_id)=(a.org_id,p_worker) FOR SHARE;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT * INTO p FROM naruv_draft.pay_periods x WHERE (x.org_id,x.worker_id,x.period)=(a.org_id,p_worker,p_period) AND x.confirmed FOR SHARE;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('date',to_char(d.work_day,'YYYY-MM-DD'),'regular',d.regular,'additional',d.additional) ORDER BY d.work_day),'[]'::jsonb),
 coalesce(jsonb_agg(jsonb_build_array(to_char(d.work_day,'YYYY-MM-DD'),d.regular,d.additional) ORDER BY d.work_day),'[]'::jsonb)
 INTO entries,pairs FROM naruv_draft.attendance d WHERE (d.org_id,d.worker_id,d.period)=(a.org_id,p_worker,p_period);
 proof:=naruv_draft.period_digest(a.org_id,p_worker,p_period,p.revision,p.hourly_krw,p.additional_bps,pairs);
 PERFORM 1 FROM naruv_draft.period_confirmations x WHERE (x.org_id,x.worker_id,x.period)=(a.org_id,p_worker,p_period) AND x.review_sha256=proof;
 IF NOT FOUND THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT p.revision,p.hourly_krw,p.additional_bps,entries;
END $$;
REVOKE ALL ON FUNCTION naruv_draft.pay_source(text,text,text) FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_draft.pay_source(text,text,text) TO jw_app_dev;
-- Synthetic staff registry and immutable initial period policy admission.
CREATE TABLE naruv_draft.setup_receipts(
 org_id text NOT NULL,request_id text NOT NULL,actor_id text NOT NULL,
 worker_id text NOT NULL,kind text NOT NULL CHECK(kind IN ('staff','period')),
 period text NOT NULL, payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(org_id,request_id),UNIQUE(org_id,worker_id,kind,period),
 FOREIGN KEY(org_id,worker_id) REFERENCES naruv_draft.staff,
 CHECK((kind='staff' AND period='') OR (kind='period' AND period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$')));
ALTER TABLE naruv_draft.setup_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_draft.setup_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY setup_scope ON naruv_draft.setup_receipts TO naruv_native_owner
 USING(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))
 WITH CHECK(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
REVOKE ALL ON naruv_draft.setup_receipts FROM PUBLIC,jw_app_dev,naruv_native_stage;
CREATE TRIGGER setup_receipt_immutable BEFORE UPDATE OR DELETE ON naruv_draft.setup_receipts
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE FUNCTION naruv_draft.setup_worker(p_worker text,p_period text,p_request text,p_revision text,p_rate bigint,p_bps int,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; r naruv_draft.setup_receipts; k text; scope_period text; data jsonb; n bigint;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_worker IS NULL OR p_worker !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_confirm IS DISTINCT FROM true THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
 IF p_period IS NULL THEN
  IF p_revision IS NOT NULL OR p_rate IS NOT NULL OR p_bps IS NOT NULL THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
  k:='staff';scope_period:='';data:=jsonb_build_object('active',true);
 ELSE
  IF p_period !~ '^[0-9]{4}-(0[1-9]|1[0-2])$' OR left(p_period,4)='0000'
  OR p_revision IS NULL OR p_revision !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
  OR p_rate IS NULL OR p_rate NOT BETWEEN 1 AND 100000000 OR p_bps IS NULL OR p_bps NOT BETWEEN 1 AND 50000
  THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
  k:='period';scope_period:=p_period;
  data:=jsonb_build_object('revision',p_revision,'hourly_krw',p_rate,'additional_bps',p_bps);
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-attendance-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO r FROM naruv_draft.setup_receipts x WHERE x.org_id=a.org_id AND x.request_id=p_request;
 IF FOUND THEN
  IF (r.actor_id,r.worker_id,r.kind,r.period,r.payload) IS DISTINCT FROM (a.actor_id,p_worker,k,scope_period,data)
  THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
 ELSE
  IF k='staff' THEN
   IF EXISTS(SELECT 1 FROM naruv_draft.staff s WHERE (s.org_id,s.worker_id)=(a.org_id,p_worker))
   THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
   SELECT count(*) INTO n FROM naruv_draft.staff s WHERE s.org_id=a.org_id;
   IF n>=1000 THEN RAISE EXCEPTION 'HR_CAPACITY'; END IF;
   INSERT INTO naruv_draft.staff VALUES(a.org_id,p_worker,true);
  ELSE
   PERFORM 1 FROM naruv_draft.staff s WHERE (s.org_id,s.worker_id)=(a.org_id,p_worker) AND s.active FOR SHARE;
   IF NOT FOUND THEN RAISE EXCEPTION 'HR_NOT_FOUND'; END IF;
   IF EXISTS(SELECT 1 FROM naruv_draft.pay_periods x WHERE (x.org_id,x.worker_id,x.period)=(a.org_id,p_worker,p_period))
   THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
   SELECT count(*) INTO n FROM naruv_draft.pay_periods x WHERE (x.org_id,x.worker_id)=(a.org_id,p_worker);
   IF n>=120 THEN RAISE EXCEPTION 'HR_CAPACITY'; END IF;
   INSERT INTO naruv_draft.pay_periods VALUES(a.org_id,p_worker,p_period,p_revision,p_rate,p_bps,false);
  END IF;
  INSERT INTO naruv_draft.setup_receipts(org_id,request_id,actor_id,worker_id,kind,period,payload)
   VALUES(a.org_id,p_request,a.actor_id,p_worker,k,scope_period,data);
 END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN jsonb_build_object('status',CASE WHEN k='staff' THEN 'STAFF_REGISTERED' ELSE 'PERIOD_CREATED' END,
 'worker_id',p_worker,'period',p_period,'request_id',p_request,'initial_values',data,
 'payment_authorized',false,'production_authorized',false,'statutory_validated',false);
END $$;
CREATE FUNCTION naruv_draft.inspect_worker(p_worker text,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; active_flag boolean; periods jsonb;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_worker IS NULL OR p_worker !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-attendance-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT s.active INTO active_flag FROM naruv_draft.staff s WHERE (s.org_id,s.worker_id)=(a.org_id,p_worker);
 IF NOT FOUND THEN RAISE EXCEPTION 'HR_NOT_FOUND'; END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('period',x.period,'revision',x.revision,'confirmed',x.confirmed) ORDER BY x.period),'[]'::jsonb)
 INTO periods FROM (SELECT p.period,p.revision,p.confirmed FROM naruv_draft.pay_periods p
 WHERE (p.org_id,p.worker_id)=(a.org_id,p_worker) ORDER BY p.period LIMIT 121) x;
 IF jsonb_array_length(periods)>120 THEN RAISE EXCEPTION 'HR_CAPACITY'; END IF;
 RETURN jsonb_build_object('worker_id',p_worker,'active',active_flag,'periods',periods,
 'payment_authorized',false,'production_authorized',false,'statutory_validated',false);
END $$;
REVOKE ALL ON FUNCTION naruv_draft.setup_worker(text,text,text,text,bigint,int,boolean,text),naruv_draft.inspect_worker(text,text) FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_draft.setup_worker(text,text,text,text,bigint,int,boolean,text),naruv_draft.inspect_worker(text,text) TO jw_app_dev;
-- Archival is non-destructive; no rehire or account termination in this fixture.
CREATE TABLE naruv_draft.staff_archivals(
 org_id text NOT NULL,worker_id text NOT NULL,request_id text NOT NULL,actor_id text NOT NULL,
 archived_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(org_id,worker_id),UNIQUE(org_id,request_id),
 FOREIGN KEY(org_id,worker_id) REFERENCES naruv_draft.staff);
ALTER TABLE naruv_draft.staff_archivals ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_draft.staff_archivals FORCE ROW LEVEL SECURITY;
CREATE POLICY archival_scope ON naruv_draft.staff_archivals TO naruv_native_owner
 USING(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))
 WITH CHECK(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
REVOKE ALL ON naruv_draft.staff_archivals FROM PUBLIC,jw_app_dev,naruv_native_stage;
CREATE TRIGGER staff_archival_immutable BEFORE UPDATE OR DELETE ON naruv_draft.staff_archivals
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();

CREATE FUNCTION naruv_draft.archive_worker(p_worker text,p_request text,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; r naruv_draft.staff_archivals; active_flag boolean;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_worker IS NULL OR p_worker !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_confirm IS DISTINCT FROM true THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-attendance-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT s.active INTO active_flag FROM naruv_draft.staff s WHERE (s.org_id,s.worker_id)=(a.org_id,p_worker) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'HR_NOT_FOUND'; END IF;
 SELECT * INTO r FROM naruv_draft.staff_archivals x WHERE x.org_id=a.org_id AND x.request_id=p_request;
 IF FOUND THEN
  IF (r.actor_id,r.worker_id) IS DISTINCT FROM (a.actor_id,p_worker) OR active_flag
  THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
 ELSE
  IF NOT active_flag THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
  IF EXISTS(SELECT 1 FROM naruv_draft.pay_periods p
    WHERE (p.org_id,p.worker_id)=(a.org_id,p_worker) AND
    (NOT p.confirmed OR NOT EXISTS(SELECT 1 FROM naruv_draft.period_confirmations c
      WHERE (c.org_id,c.worker_id,c.period)=(p.org_id,p.worker_id,p.period)
      AND c.review_sha256=naruv_draft.period_digest(p.org_id,p.worker_id,p.period,p.revision,p.hourly_krw,p.additional_bps,
       (SELECT coalesce(jsonb_agg(jsonb_build_array(to_char(d.work_day,'YYYY-MM-DD'),d.regular,d.additional) ORDER BY d.work_day),'[]'::jsonb)
        FROM naruv_draft.attendance d WHERE (d.org_id,d.worker_id,d.period)=(p.org_id,p.worker_id,p.period))))))
   THEN RAISE EXCEPTION 'HR_UNSETTLED_PERIOD'; END IF;
  UPDATE naruv_draft.staff s SET active=false WHERE (s.org_id,s.worker_id)=(a.org_id,p_worker) AND s.active;
  IF NOT FOUND THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
  INSERT INTO naruv_draft.staff_archivals(org_id,worker_id,request_id,actor_id) VALUES(a.org_id,p_worker,p_request,a.actor_id);
 END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN jsonb_build_object('status','STAFF_ARCHIVED','worker_id',p_worker,'request_id',p_request,'active',false,
 'payment_authorized',false,'production_authorized',false,'statutory_validated',false);
END $$;
CREATE FUNCTION naruv_draft.list_workers(p_after text,p_limit int,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; entries jsonb; next_id text;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100
 OR (p_after IS NOT NULL AND p_after !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$')
 THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-attendance-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('worker_id',q.worker_id,'active',q.active) ORDER BY q.worker_id COLLATE "C"),'[]'::jsonb)
 INTO entries FROM (SELECT s.worker_id,s.active FROM naruv_draft.staff s WHERE s.org_id=a.org_id
 AND (p_after IS NULL OR s.worker_id COLLATE "C">p_after COLLATE "C")
 ORDER BY s.worker_id COLLATE "C" LIMIT p_limit+1) q;
 IF jsonb_array_length(entries)>p_limit THEN
  entries:=entries-p_limit;next_id:=entries->(p_limit-1)->>'worker_id';
 END IF;
 RETURN jsonb_build_object('workers',entries,'next_after',next_id,'payment_authorized',false,'production_authorized',false,'statutory_validated',false);
END $$;
REVOKE ALL ON FUNCTION naruv_draft.archive_worker(text,text,boolean,text),naruv_draft.list_workers(text,int,text) FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_draft.archive_worker(text,text,boolean,text),naruv_draft.list_workers(text,int,text) TO jw_app_dev;
-- Open-period amendments require the exact reviewed snapshot and an immutable before/after record.
CREATE TABLE naruv_draft.period_amendments(
 org_id text NOT NULL,request_id text NOT NULL,actor_id text NOT NULL,worker_id text NOT NULL,period text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('attendance','policy')),expected_sha256 text NOT NULL CHECK(expected_sha256 ~ '^[0-9a-f]{64}$'),
 input jsonb NOT NULL,before_values jsonb NOT NULL,after_values jsonb NOT NULL,receipt jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(org_id,request_id),
 FOREIGN KEY(org_id,worker_id,period) REFERENCES naruv_draft.pay_periods);
ALTER TABLE naruv_draft.period_amendments ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_draft.period_amendments FORCE ROW LEVEL SECURITY;
CREATE POLICY amendment_scope ON naruv_draft.period_amendments TO naruv_native_owner
 USING(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))
 WITH CHECK(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
REVOKE ALL ON naruv_draft.period_amendments FROM PUBLIC,jw_app_dev,naruv_native_stage;
CREATE TRIGGER period_amendment_immutable BEFORE UPDATE OR DELETE ON naruv_draft.period_amendments
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE FUNCTION naruv_draft.amend_period(p_worker text,p_period text,p_request text,p_expected text,p_kind text,p_data jsonb,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; r naruv_draft.period_amendments; old_review jsonb; new_review jsonb; result jsonb;
 d date; reg int; extra int; rate bigint; bps int; rev text;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_worker IS NULL OR p_worker !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_period IS NULL OR p_period !~ '^[0-9]{4}-(0[1-9]|1[0-2])$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_expected IS NULL OR p_expected !~ '^[0-9a-f]{64}$' OR p_confirm IS DISTINCT FROM true
 OR p_kind IS NULL OR p_kind NOT IN ('attendance','policy') OR jsonb_typeof(p_data) IS DISTINCT FROM 'object'
 OR octet_length(p_data::text)>4096 THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
 IF p_kind='attendance' THEN
  IF NOT p_data ?& ARRAY['date','regular','additional'] OR p_data-ARRAY['date','regular','additional']<>'{}'::jsonb
  OR jsonb_typeof(p_data->'date') IS DISTINCT FROM 'string' OR (p_data->>'date') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
  OR left(p_data->>'date',7)<>p_period OR jsonb_typeof(p_data->'regular') IS DISTINCT FROM 'number'
  OR jsonb_typeof(p_data->'additional') IS DISTINCT FROM 'number'
  OR (p_data->>'regular') !~ '^[0-9]{1,4}$' OR (p_data->>'additional') !~ '^[0-9]{1,4}$' THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
  BEGIN d:=(p_data->>'date')::date; EXCEPTION WHEN datetime_field_overflow OR invalid_datetime_format THEN RAISE EXCEPTION 'HR_INPUT'; END;
  reg:=(p_data->>'regular')::int;extra:=(p_data->>'additional')::int;
  IF reg+extra>1440 OR to_char(d,'YYYY-MM-DD')<>p_data->>'date' THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
 ELSE
  IF NOT p_data ?& ARRAY['revision','hourly_krw','additional_bps'] OR p_data-ARRAY['revision','hourly_krw','additional_bps']<>'{}'::jsonb
  OR jsonb_typeof(p_data->'revision') IS DISTINCT FROM 'string' OR (p_data->>'revision') !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
  OR jsonb_typeof(p_data->'hourly_krw') IS DISTINCT FROM 'number' OR (p_data->>'hourly_krw') !~ '^[0-9]{1,9}$'
  OR jsonb_typeof(p_data->'additional_bps') IS DISTINCT FROM 'number' OR (p_data->>'additional_bps') !~ '^[0-9]{1,5}$'
  THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
  rev:=p_data->>'revision';rate:=(p_data->>'hourly_krw')::bigint;bps:=(p_data->>'additional_bps')::int;
  IF rate NOT BETWEEN 1 AND 100000000 OR bps NOT BETWEEN 1 AND 50000 THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-attendance-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO r FROM naruv_draft.period_amendments x WHERE x.org_id=a.org_id AND x.request_id=p_request;
 IF FOUND THEN
  IF (r.actor_id,r.worker_id,r.period,r.kind,r.expected_sha256,r.input) IS DISTINCT FROM (a.actor_id,p_worker,p_period,p_kind,p_expected,p_data)
  THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
  RETURN r.receipt;
 END IF;
 old_review:=naruv_draft.review_period(p_worker,p_period,NULL,NULL,false,p_csrf);
 IF (old_review->>'confirmed')::boolean THEN RAISE EXCEPTION 'HR_PERIOD_CONFIRMED'; END IF;
 IF old_review->>'review_sha256' IS DISTINCT FROM p_expected THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
 IF p_kind='attendance' THEN
  UPDATE naruv_draft.attendance x SET regular=reg,additional=extra WHERE
   (x.org_id,x.worker_id,x.period,x.work_day)=(a.org_id,p_worker,p_period,d)
   AND (x.regular,x.additional) IS DISTINCT FROM (reg,extra);
  IF NOT FOUND THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
 ELSE
  IF old_review->>'policy_revision'=rev THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
  UPDATE naruv_draft.pay_periods x SET revision=rev,hourly_krw=rate,additional_bps=bps WHERE
   (x.org_id,x.worker_id,x.period)=(a.org_id,p_worker,p_period) AND NOT x.confirmed;
  IF NOT FOUND THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
 END IF;
 new_review:=naruv_draft.review_period(p_worker,p_period,NULL,NULL,false,p_csrf);
 IF new_review->>'review_sha256'=p_expected THEN RAISE EXCEPTION 'HR_CONFLICT'; END IF;
 result:=jsonb_build_object('status','PERIOD_AMENDED','kind',p_kind,'request_id',p_request,
 'worker_id',p_worker,'period',p_period,'review_sha256',new_review->>'review_sha256',
 'payment_authorized',false,'production_authorized',false,'statutory_validated',false);
 INSERT INTO naruv_draft.period_amendments(org_id,request_id,actor_id,worker_id,period,kind,expected_sha256,input,before_values,after_values,receipt)
 VALUES(a.org_id,p_request,a.actor_id,p_worker,p_period,p_kind,p_expected,p_data,old_review,new_review,result);
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION naruv_draft.amend_period(text,text,text,text,text,jsonb,boolean,text) FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_draft.amend_period(text,text,text,text,text,jsonb,boolean,text) TO jw_app_dev;
RESET ROLE;
