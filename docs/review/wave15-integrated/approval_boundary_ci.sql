-- Only after Wave14 in a fresh disposable PG17. Independent trusted reviewer
-- role attests a verified signature; PostgreSQL does not implement Ed25519 here.
-- No reviewer or publisher membership provisioned by this migration.
DO $$ BEGIN
 IF current_database()<>'postgres' OR session_user<>'postgres'
 OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR current_setting('naruv.adjustment_approval_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'ADJUSTMENT_APPROVAL_DISPOSABLE_ONLY'; END IF;
 IF EXISTS(SELECT 1 FROM naruv_draft.postconfirm_adjustment_proposals) THEN RAISE EXCEPTION 'ADJUSTMENT_APPROVAL_FRESH_ONLY'; END IF;
END $$;
CREATE ROLE naruv_adjustment_reviewer NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
SET ROLE naruv_native_owner;
CREATE TABLE naruv_draft.adjustment_approval_assertions(
 org_id text NOT NULL, request_id text NOT NULL, worker_id text NOT NULL, period text NOT NULL,
 confirmation_sha256 text NOT NULL CHECK(confirmation_sha256 ~ '^[0-9a-f]{64}$'),
 proposal_sha256 text NOT NULL CHECK(proposal_sha256 ~ '^[0-9a-f]{64}$'),
 approval_sha256 text NOT NULL CHECK(approval_sha256 ~ '^[0-9a-f]{64}$'),
 policy_sha256 text NOT NULL CHECK(policy_sha256 ~ '^[0-9a-f]{64}$'),
 expires_at timestamptz NOT NULL, issuer name NOT NULL,
 proposal jsonb NOT NULL CHECK(jsonb_typeof(proposal)='object' AND octet_length(proposal::text)<=32768),
 PRIMARY KEY(org_id,request_id), UNIQUE(org_id,approval_sha256),
 FOREIGN KEY(org_id,worker_id,period,confirmation_sha256) REFERENCES naruv_draft.payroll_review_receipts(org_id,worker_id,period,confirmation_sha256)
);
ALTER TABLE naruv_draft.adjustment_approval_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_draft.adjustment_approval_assertions FORCE ROW LEVEL SECURITY;
CREATE POLICY adjustment_approval_scope ON naruv_draft.adjustment_approval_assertions TO naruv_native_owner
 USING(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))
 WITH CHECK(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
REVOKE ALL ON naruv_draft.adjustment_approval_assertions FROM PUBLIC,jw_app_dev,naruv_native_stage,naruv_hr_evidence_publisher,naruv_adjustment_reviewer;
CREATE TRIGGER adjustment_approval_immutable BEFORE UPDATE OR DELETE ON naruv_draft.adjustment_approval_assertions
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
-- Preserve the existing implementation, remove its externally callable path.
ALTER FUNCTION naruv_draft.propose_postconfirm_adjustment(text,text,text,text,text,text,jsonb,text) RENAME TO internal_postconfirm_adjustment_v14;
REVOKE ALL ON FUNCTION naruv_draft.internal_postconfirm_adjustment_v14(text,text,text,text,text,text,jsonb,text) FROM PUBLIC,jw_app_dev,naruv_native_stage,naruv_hr_evidence_publisher,naruv_adjustment_reviewer;
CREATE FUNCTION naruv_draft.assert_adjustment_review(p_worker text,p_period text,p_request text,p_confirmation text,p_receipt text,p_proposal text,p_approval text,p_policy text,p_expires timestamptz,p_data jsonb,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; src jsonb; saved naruv_draft.adjustment_approval_assertions; inserted boolean;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF NOT pg_has_role(session_user,'naruv_adjustment_reviewer','MEMBER') OR pg_has_role(session_user,'naruv_hr_evidence_publisher','MEMBER') THEN RAISE EXCEPTION 'ADJUSTMENT_INDEPENDENT_REVIEWER_REQUIRED' USING ERRCODE='42501'; END IF;
 IF p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_proposal IS NULL OR p_proposal !~ '^[0-9a-f]{64}$' OR p_approval IS NULL OR p_approval !~ '^[0-9a-f]{64}$'
 OR p_policy IS NULL OR p_policy !~ '^[0-9a-f]{64}$' OR p_expires IS NULL OR p_expires<=clock_timestamp() OR p_expires>clock_timestamp()+interval '24 hours'
 OR jsonb_typeof(p_data) IS DISTINCT FROM 'object' OR octet_length(p_data::text)>32768
 OR (p_data->>'tenant',p_data->>'worker',p_data->>'period',p_data->>'original_receipt_sha256',p_data->>'proposal_sha256') IS DISTINCT FROM (a.org_id,p_worker,p_period,p_receipt,p_proposal)
 OR p_data->>'status' IS DISTINCT FROM 'POSTCONFIRM_ADJUSTMENT_PROPOSAL_ONLY'
 OR p_data->'payment_authorized' IS DISTINCT FROM 'false'::jsonb OR p_data->'recovery_authorized' IS DISTINCT FROM 'false'::jsonb
 OR p_data->'statutory_validated' IS DISTINCT FROM 'false'::jsonb OR p_data->'production_authorized' IS DISTINCT FROM 'false'::jsonb
 THEN RAISE EXCEPTION 'ADJUSTMENT_APPROVAL_INPUT'; END IF;
 src:=naruv_draft.read_payroll_review_receipt(p_worker,p_period,p_confirmation,p_receipt,p_csrf);
 IF p_data->>'original_review_sha256' IS DISTINCT FROM src->'record'->>'expected_review_sha256' THEN RAISE EXCEPTION 'ADJUSTMENT_SOURCE'; END IF;
 INSERT INTO naruv_draft.adjustment_approval_assertions VALUES(a.org_id,p_request,p_worker,p_period,p_confirmation,p_proposal,p_approval,p_policy,p_expires,session_user,p_data) ON CONFLICT DO NOTHING;
 inserted:=FOUND;
 SELECT * INTO saved FROM naruv_draft.adjustment_approval_assertions x WHERE (x.org_id,x.request_id)=(a.org_id,p_request);
 IF NOT FOUND OR (saved.worker_id,saved.period,saved.confirmation_sha256,saved.proposal_sha256,saved.approval_sha256,saved.policy_sha256,saved.expires_at,saved.issuer,saved.proposal) IS DISTINCT FROM (p_worker,p_period,p_confirmation,p_proposal,p_approval,p_policy,p_expires,session_user,p_data) THEN RAISE EXCEPTION 'ADJUSTMENT_APPROVAL_CONFLICT'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN jsonb_build_object('status','REVIEW_ASSERTION_ONLY','approval_sha256',p_approval,'created',inserted,'production_authorized',false);
END $$;
REVOKE ALL ON FUNCTION naruv_draft.assert_adjustment_review(text,text,text,text,text,text,text,text,timestamptz,jsonb,text) FROM PUBLIC,jw_app_dev,naruv_native_stage,naruv_hr_evidence_publisher,naruv_adjustment_reviewer;
GRANT EXECUTE ON FUNCTION naruv_draft.assert_adjustment_review(text,text,text,text,text,text,text,text,timestamptz,jsonb,text) TO jw_app_dev;
CREATE FUNCTION naruv_draft.propose_postconfirm_adjustment(p_worker text,p_period text,p_request text,p_confirmation text,p_receipt text,p_proposal text,p_data jsonb,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; approved naruv_draft.adjustment_approval_assertions; result jsonb;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF NOT pg_has_role(session_user,'naruv_hr_evidence_publisher','MEMBER') OR pg_has_role(session_user,'naruv_adjustment_reviewer','MEMBER') THEN RAISE EXCEPTION 'ADJUSTMENT_SEPARATE_PUBLISHER_REQUIRED' USING ERRCODE='42501'; END IF;
 -- Recheck confirmed source and take the original tenant transaction lock.
 PERFORM naruv_draft.read_payroll_review_receipt(p_worker,p_period,p_confirmation,p_receipt,p_csrf);
 SELECT * INTO approved FROM naruv_draft.adjustment_approval_assertions x WHERE (x.org_id,x.request_id)=(a.org_id,p_request);
 IF NOT FOUND OR approved.expires_at<=clock_timestamp() OR approved.issuer=session_user
 OR NOT pg_has_role(approved.issuer,'naruv_adjustment_reviewer','MEMBER') OR pg_has_role(approved.issuer,'naruv_hr_evidence_publisher','MEMBER')
 OR (approved.worker_id,approved.period,approved.confirmation_sha256,approved.proposal_sha256,approved.proposal) IS DISTINCT FROM (p_worker,p_period,p_confirmation,p_proposal,p_data)
 THEN RAISE EXCEPTION 'ADJUSTMENT_APPROVAL_REQUIRED' USING ERRCODE='42501'; END IF;
 result:=naruv_draft.internal_postconfirm_adjustment_v14(p_worker,p_period,p_request,p_confirmation,p_receipt,p_proposal,p_data,p_csrf);
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF approved.expires_at<=clock_timestamp() OR NOT pg_has_role(approved.issuer,'naruv_adjustment_reviewer','MEMBER')
 OR (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256) THEN RAISE EXCEPTION 'ADJUSTMENT_APPROVAL_REQUIRED' USING ERRCODE='42501'; END IF;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION naruv_draft.propose_postconfirm_adjustment(text,text,text,text,text,text,jsonb,text) FROM PUBLIC,jw_app_dev,naruv_native_stage,naruv_hr_evidence_publisher,naruv_adjustment_reviewer;
GRANT EXECUTE ON FUNCTION naruv_draft.propose_postconfirm_adjustment(text,text,text,text,text,text,jsonb,text) TO jw_app_dev;
RESET ROLE;
