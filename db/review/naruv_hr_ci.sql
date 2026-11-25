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

CREATE FUNCTION naruv_draft.review_period(p_worker text,p_period text,p_request text,p_expected text,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; p naruv_draft.pay_periods; r naruv_draft.period_confirmations;
 rows jsonb; n bigint; digest text; receipt boolean:=false;
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
 PERFORM 1 FROM naruv_draft.staff s WHERE s.org_id=a.org_id AND s.worker_id=p_worker AND s.active FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'HR_NOT_FOUND'; END IF;
 SELECT * INTO p FROM naruv_draft.pay_periods x WHERE (x.org_id,x.worker_id,x.period)=(a.org_id,p_worker,p_period) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'HR_NOT_FOUND'; END IF;
 SELECT count(*),coalesce(jsonb_agg(jsonb_build_array(to_char(d.work_day,'YYYY-MM-DD'),d.regular,d.additional) ORDER BY d.work_day),'[]'::jsonb)
 INTO n,rows FROM naruv_draft.attendance d WHERE (d.org_id,d.worker_id,d.period)=(a.org_id,p_worker,p_period);
 IF n NOT BETWEEN 1 AND 31 THEN RAISE EXCEPTION 'HR_INPUT'; END IF;
 digest:=encode(sha256(convert_to(jsonb_build_array('naruv-period-review-v1',a.org_id,p_worker,p_period,p.revision,p.hourly_krw,p.additional_bps,rows)::text,'UTF8')),'hex');
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
 'confirmed',p.confirmed OR receipt,'payment_authorized',false,'production_authorized',false,'statutory_validated',false);
END $$;
REVOKE ALL ON FUNCTION naruv_draft.review_period(text,text,text,text,boolean,text) FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_draft.review_period(text,text,text,text,boolean,text) TO jw_app_dev;
RESET ROLE;
