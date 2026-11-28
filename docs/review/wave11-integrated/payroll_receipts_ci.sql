-- REVIEW CANDIDATE ONLY. Fresh disposable PG17 after naruv_hr_ci.sql.
-- No membership/login/production grant provisioned. Publisher is an additional
-- capability: existing normal business login may read but cannot publish.
DO $$ BEGIN
 IF current_database()<>'postgres' OR session_user<>'postgres'
 OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR current_setting('naruv.hr_evidence_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'HR_EVIDENCE_DISPOSABLE_ONLY'; END IF;
END $$;
CREATE ROLE naruv_hr_evidence_publisher NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
SET ROLE naruv_native_owner;
CREATE TABLE naruv_draft.payroll_review_receipts(
 org_id text NOT NULL, worker_id text NOT NULL, period text NOT NULL,
 confirmation_sha256 text NOT NULL CHECK(confirmation_sha256 ~ '^[0-9a-f]{64}$'),
 assessment_sha256 text NOT NULL CHECK(assessment_sha256 ~ '^[0-9a-f]{64}$'),
 review_sha256 text NOT NULL CHECK(review_sha256 ~ '^[0-9a-f]{64}$'),
 monthly_sha256 text NOT NULL CHECK(monthly_sha256 ~ '^[0-9a-f]{64}$'),
 receipt_sha256 text NOT NULL CHECK(receipt_sha256 ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(org_id,worker_id,period,confirmation_sha256),
 FOREIGN KEY(org_id,worker_id,period) REFERENCES naruv_draft.period_confirmations(org_id,worker_id,period));
ALTER TABLE naruv_draft.payroll_review_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_draft.payroll_review_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY payroll_receipt_scope ON naruv_draft.payroll_review_receipts TO naruv_native_owner
 USING(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))
 WITH CHECK(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
REVOKE ALL ON naruv_draft.payroll_review_receipts FROM PUBLIC,jw_app_dev,naruv_native_stage,naruv_hr_evidence_publisher;
CREATE TRIGGER payroll_receipt_immutable BEFORE UPDATE OR DELETE ON naruv_draft.payroll_review_receipts
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE FUNCTION naruv_draft.payroll_review_receipt(p_worker text,p_period text,p_confirmation text,p_assessment text,p_review text,p_monthly text,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; source jsonb; pin text; saved naruv_draft.payroll_review_receipts; created boolean;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF NOT pg_has_role(session_user,'naruv_hr_evidence_publisher','MEMBER') THEN RAISE EXCEPTION 'HR_EVIDENCE_PUBLISHER_REQUIRED' USING ERRCODE='42501'; END IF;
 IF p_confirmation IS NULL OR p_confirmation !~ '^[0-9a-f]{64}$' OR p_assessment IS NULL OR p_assessment !~ '^[0-9a-f]{64}$'
 OR p_review IS NULL OR p_review !~ '^[0-9a-f]{64}$' OR p_monthly IS NULL OR p_monthly !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'HR_EVIDENCE_INPUT'; END IF;
 -- Existing review_period takes the tenant lock, rechecks session, and re-hashes confirmed attendance.
 source:=naruv_draft.review_period(p_worker,p_period,NULL,NULL,false,p_csrf);
 IF source->>'confirmed' IS DISTINCT FROM 'true' OR source->>'review_sha256' IS DISTINCT FROM p_confirmation THEN RAISE EXCEPTION 'HR_EVIDENCE_CONFIRMATION'; END IF;
 pin:=encode(sha256(convert_to(jsonb_build_array('NARUV_PG_REVIEW_RECEIPT_V1',a.org_id,p_worker,p_period,p_confirmation,p_assessment,p_review,p_monthly)::text,'UTF8')),'hex');
 INSERT INTO naruv_draft.payroll_review_receipts VALUES(a.org_id,p_worker,p_period,p_confirmation,p_assessment,p_review,p_monthly,pin) ON CONFLICT DO NOTHING;
 created:=FOUND;
 SELECT * INTO saved FROM naruv_draft.payroll_review_receipts r WHERE (r.org_id,r.worker_id,r.period,r.confirmation_sha256)=(a.org_id,p_worker,p_period,p_confirmation);
 IF NOT FOUND OR (saved.assessment_sha256,saved.review_sha256,saved.monthly_sha256,saved.receipt_sha256) IS DISTINCT FROM (p_assessment,p_review,p_monthly,pin) THEN RAISE EXCEPTION 'HR_EVIDENCE_CONFLICT'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN jsonb_build_object('status','REVIEW_RECEIPT_ONLY','receipt_sha256',pin,'created',created,'statutory_validated',false,'payment_authorized',false,'production_authorized',false);
END $$;
CREATE FUNCTION naruv_draft.read_payroll_review_receipt(p_worker text,p_period text,p_confirmation text,p_pin text,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; source jsonb; r naruv_draft.payroll_review_receipts;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_confirmation IS NULL OR p_confirmation !~ '^[0-9a-f]{64}$' OR p_pin IS NULL OR p_pin !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'HR_EVIDENCE_INPUT'; END IF;
 source:=naruv_draft.review_period(p_worker,p_period,NULL,NULL,false,p_csrf);
 IF source->>'confirmed' IS DISTINCT FROM 'true' OR source->>'review_sha256' IS DISTINCT FROM p_confirmation THEN RAISE EXCEPTION 'HR_EVIDENCE_CONFIRMATION'; END IF;
 SELECT * INTO r FROM naruv_draft.payroll_review_receipts x WHERE (x.org_id,x.worker_id,x.period,x.confirmation_sha256)=(a.org_id,p_worker,p_period,p_confirmation);
 IF NOT FOUND OR r.receipt_sha256 IS DISTINCT FROM p_pin OR r.receipt_sha256 IS DISTINCT FROM encode(sha256(convert_to(jsonb_build_array('NARUV_PG_REVIEW_RECEIPT_V1',a.org_id,p_worker,p_period,p_confirmation,r.assessment_sha256,r.review_sha256,r.monthly_sha256)::text,'UTF8')),'hex') THEN RAISE EXCEPTION 'HR_EVIDENCE_NOT_FOUND_OR_CHANGED'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN jsonb_build_object('confirmation_sha256',p_confirmation,'confirmed_days',source->'days','record',jsonb_build_object('tenant',a.org_id,'worker',p_worker,'period',p_period,'assessment_sha256',r.assessment_sha256,'expected_review_sha256',r.review_sha256,'expected_monthly_review_sha256',r.monthly_sha256));
END $$;
REVOKE ALL ON FUNCTION naruv_draft.payroll_review_receipt(text,text,text,text,text,text,text),naruv_draft.read_payroll_review_receipt(text,text,text,text,text) FROM PUBLIC,jw_app_dev,naruv_native_stage,naruv_hr_evidence_publisher;
-- Writer checks the separate session-user capability internally. No membership is added.
GRANT EXECUTE ON FUNCTION naruv_draft.payroll_review_receipt(text,text,text,text,text,text,text),naruv_draft.read_payroll_review_receipt(text,text,text,text,text) TO jw_app_dev;
RESET ROLE;
