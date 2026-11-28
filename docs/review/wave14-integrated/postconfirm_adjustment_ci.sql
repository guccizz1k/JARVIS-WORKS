-- Disposable PG17 only, after Wave11 payroll_receipts_ci.sql. No production grants.
DO $$ BEGIN
 IF current_database()<>'postgres' OR session_user<>'postgres'
 OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR current_setting('naruv.adjustment_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'ADJUSTMENT_DISPOSABLE_ONLY'; END IF;
END $$;
SET ROLE naruv_native_owner;
CREATE TABLE naruv_draft.postconfirm_adjustment_proposals (
 org_id text NOT NULL, worker_id text NOT NULL, period text NOT NULL,
 request_id text NOT NULL, confirmation_sha256 text NOT NULL CHECK(confirmation_sha256 ~ '^[0-9a-f]{64}$'),
 original_receipt_sha256 text NOT NULL CHECK(original_receipt_sha256 ~ '^[0-9a-f]{64}$'),
 proposal_sha256 text NOT NULL CHECK(proposal_sha256 ~ '^[0-9a-f]{64}$'),
 proposal jsonb NOT NULL CHECK(jsonb_typeof(proposal)='object' AND octet_length(proposal::text)<=32768),
 PRIMARY KEY(org_id,request_id), UNIQUE(org_id,worker_id,period,proposal_sha256),
 FOREIGN KEY(org_id,worker_id,period,confirmation_sha256) REFERENCES naruv_draft.payroll_review_receipts(org_id,worker_id,period,confirmation_sha256)
);
ALTER TABLE naruv_draft.postconfirm_adjustment_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_draft.postconfirm_adjustment_proposals FORCE ROW LEVEL SECURITY;
CREATE POLICY adjustment_scope ON naruv_draft.postconfirm_adjustment_proposals TO naruv_native_owner
 USING(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))
 WITH CHECK(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
REVOKE ALL ON naruv_draft.postconfirm_adjustment_proposals FROM PUBLIC,jw_app_dev,naruv_native_stage,naruv_hr_evidence_publisher;
CREATE TRIGGER adjustment_immutable BEFORE UPDATE OR DELETE ON naruv_draft.postconfirm_adjustment_proposals
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE FUNCTION naruv_draft.propose_postconfirm_adjustment(p_worker text,p_period text,p_request text,p_confirmation text,p_receipt text,p_proposal text,p_data jsonb,p_csrf text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; source jsonb; saved naruv_draft.postconfirm_adjustment_proposals; inserted boolean;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF NOT pg_has_role(session_user,'naruv_hr_evidence_publisher','MEMBER') THEN RAISE EXCEPTION 'HR_EVIDENCE_PUBLISHER_REQUIRED' USING ERRCODE='42501'; END IF;
 IF p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR p_proposal IS NULL OR p_proposal !~ '^[0-9a-f]{64}$'
 OR jsonb_typeof(p_data) IS DISTINCT FROM 'object' OR octet_length(p_data::text)>32768
 OR NOT p_data ?& ARRAY['tenant','worker','period','original_receipt_sha256','original_review_sha256','proposed_review_sha256','new_assessment_sha256','reason_sha256','comparison','proposal_sha256','status','payment_authorized','recovery_authorized','statutory_validated','production_authorized']
 OR p_data-ARRAY['tenant','worker','period','original_receipt_sha256','original_review_sha256','proposed_review_sha256','new_assessment_sha256','reason_sha256','comparison','proposal_sha256','status','payment_authorized','recovery_authorized','statutory_validated','production_authorized']<>'{}'::jsonb
 OR p_data->>'tenant' IS DISTINCT FROM a.org_id OR p_data->>'worker' IS DISTINCT FROM p_worker OR p_data->>'period' IS DISTINCT FROM p_period
 OR p_data->>'original_receipt_sha256' IS DISTINCT FROM p_receipt OR p_data->>'proposal_sha256' IS DISTINCT FROM p_proposal
 OR p_data->>'status' IS DISTINCT FROM 'POSTCONFIRM_ADJUSTMENT_PROPOSAL_ONLY'
 OR p_data->'payment_authorized' IS DISTINCT FROM 'false'::jsonb OR p_data->'recovery_authorized' IS DISTINCT FROM 'false'::jsonb
 OR p_data->'statutory_validated' IS DISTINCT FROM 'false'::jsonb OR p_data->'production_authorized' IS DISTINCT FROM 'false'::jsonb
 OR coalesce(p_data->>'original_review_sha256','') !~ '^[0-9a-f]{64}$'
 OR coalesce(p_data->>'proposed_review_sha256','') !~ '^[0-9a-f]{64}$'
 OR coalesce(p_data->>'new_assessment_sha256','') !~ '^[0-9a-f]{64}$'
 OR coalesce(p_data->>'reason_sha256','') !~ '^[0-9a-f]{64}$'
 OR p_data->>'original_review_sha256'=p_data->>'proposed_review_sha256'
 OR jsonb_typeof(p_data->'comparison') IS DISTINCT FROM 'object'
 OR p_data->'comparison'->>'status' IS DISTINCT FROM 'ADJUSTMENT_REVIEW_ONLY'
 OR p_data->'comparison'->'payment_authorized' IS DISTINCT FROM 'false'::jsonb
 OR p_data->'comparison'->'recovery_authorized' IS DISTINCT FROM 'false'::jsonb
 OR p_data->'comparison'->'statutory_validated' IS DISTINCT FROM 'false'::jsonb
 OR p_data->'comparison'->'production_authorized' IS DISTINCT FROM 'false'::jsonb
 THEN RAISE EXCEPTION 'ADJUSTMENT_INPUT'; END IF;
 -- Reuses the original RPC's tenant and confirmed-attendance lock, never mutates it.
 source:=naruv_draft.read_payroll_review_receipt(p_worker,p_period,p_confirmation,p_receipt,p_csrf);
 IF p_data->>'original_review_sha256' IS DISTINCT FROM source->'record'->>'expected_review_sha256' THEN RAISE EXCEPTION 'ADJUSTMENT_SOURCE'; END IF;
 INSERT INTO naruv_draft.postconfirm_adjustment_proposals VALUES(a.org_id,p_worker,p_period,p_request,p_confirmation,p_receipt,p_proposal,p_data) ON CONFLICT DO NOTHING;
 inserted:=FOUND;
 SELECT * INTO saved FROM naruv_draft.postconfirm_adjustment_proposals r WHERE r.org_id=a.org_id AND r.request_id=p_request;
 IF NOT FOUND OR (saved.worker_id,saved.period,saved.confirmation_sha256,saved.original_receipt_sha256,saved.proposal_sha256,saved.proposal) IS DISTINCT FROM (p_worker,p_period,p_confirmation,p_receipt,p_proposal,p_data) THEN RAISE EXCEPTION 'ADJUSTMENT_CONFLICT'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN jsonb_build_object('status','POSTCONFIRM_ADJUSTMENT_PROPOSAL_ONLY','proposal_sha256',p_proposal,'created',inserted,'payment_authorized',false,'recovery_authorized',false,'statutory_validated',false,'production_authorized',false);
END $$;
REVOKE ALL ON FUNCTION naruv_draft.propose_postconfirm_adjustment(text,text,text,text,text,text,jsonb,text) FROM PUBLIC,jw_app_dev,naruv_native_stage,naruv_hr_evidence_publisher;
GRANT EXECUTE ON FUNCTION naruv_draft.propose_postconfirm_adjustment(text,text,text,text,text,text,jsonb,text) TO jw_app_dev;
CREATE FUNCTION naruv_draft.read_postconfirm_adjustment(p_worker text,p_period text,p_request text,p_proposal text,p_csrf text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; saved naruv_draft.postconfirm_adjustment_proposals; source jsonb;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR p_proposal IS NULL OR p_proposal !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'ADJUSTMENT_INPUT'; END IF;
 SELECT * INTO saved FROM naruv_draft.postconfirm_adjustment_proposals r WHERE (r.org_id,r.worker_id,r.period,r.request_id,r.proposal_sha256)=(a.org_id,p_worker,p_period,p_request,p_proposal);
 IF NOT FOUND THEN RAISE EXCEPTION 'ADJUSTMENT_NOT_FOUND'; END IF;
 source:=naruv_draft.read_payroll_review_receipt(p_worker,p_period,saved.confirmation_sha256,saved.original_receipt_sha256,p_csrf);
 IF saved.proposal->>'original_review_sha256' IS DISTINCT FROM source->'record'->>'expected_review_sha256' THEN RAISE EXCEPTION 'ADJUSTMENT_SOURCE'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN saved.proposal;
END $$;
REVOKE ALL ON FUNCTION naruv_draft.read_postconfirm_adjustment(text,text,text,text,text) FROM PUBLIC,jw_app_dev,naruv_native_stage,naruv_hr_evidence_publisher;
GRANT EXECUTE ON FUNCTION naruv_draft.read_postconfirm_adjustment(text,text,text,text,text) TO jw_app_dev;
RESET ROLE;
