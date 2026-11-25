-- CI-only synthetic encrypted staff profile storage. No production migration.
DO $$ BEGIN
 IF current_database()<>'postgres' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user<>'postgres' OR current_setting('naruv.profile_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'PROFILE_DISPOSABLE_ONLY'; END IF;
END $$;
SET ROLE naruv_native_owner;
CREATE TABLE naruv_draft.profile_envelopes(
 org_id text NOT NULL,worker_id text NOT NULL,revision text NOT NULL,
 actor_id text NOT NULL,envelope jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(org_id,worker_id),
 FOREIGN KEY(org_id,worker_id) REFERENCES naruv_draft.staff(org_id,worker_id),
 CHECK(jsonb_typeof(envelope)='object' AND octet_length(envelope::text)<=5000));
ALTER TABLE naruv_draft.profile_envelopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_draft.profile_envelopes FORCE ROW LEVEL SECURITY;
CREATE POLICY profile_scope ON naruv_draft.profile_envelopes TO naruv_native_owner
 USING(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))
 WITH CHECK(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
REVOKE ALL ON naruv_draft.profile_envelopes FROM PUBLIC,jw_app_dev,naruv_native_stage;
CREATE TABLE naruv_draft.profile_revision_history(
 org_id text NOT NULL,worker_id text NOT NULL,revision text NOT NULL,
 previous_revision text,actor_id text NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(org_id,worker_id,revision),
 FOREIGN KEY(org_id,worker_id) REFERENCES naruv_draft.staff(org_id,worker_id));
ALTER TABLE naruv_draft.profile_revision_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_draft.profile_revision_history FORCE ROW LEVEL SECURITY;
CREATE POLICY profile_history_scope ON naruv_draft.profile_revision_history TO naruv_native_owner
 USING(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))
 WITH CHECK(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
REVOKE ALL ON naruv_draft.profile_revision_history FROM PUBLIC,jw_app_dev,naruv_native_stage;
CREATE TRIGGER profile_history_immutable BEFORE UPDATE OR DELETE ON naruv_draft.profile_revision_history
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE FUNCTION naruv_draft.profile_envelope(p_worker text,p_revision text,p_envelope jsonb,p_expected text,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; fresh record; saved jsonb; current_revision text;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF a.org_id NOT IN ('ci-a','ci-b') OR p_worker IS DISTINCT FROM 'worker-1'
 OR (p_revision IS NULL)<>(p_envelope IS NULL)
 OR (p_envelope IS NULL AND p_expected IS NOT NULL)
 THEN RAISE EXCEPTION 'PROFILE_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-profile-ci:'||a.org_id,0));
 SELECT * INTO fresh FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (fresh.actor_id,fresh.org_id,fresh.auth_epoch,fresh.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 PERFORM 1 FROM naruv_draft.staff s WHERE s.org_id=a.org_id AND s.worker_id=p_worker AND s.active FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PROFILE_NOT_FOUND'; END IF;
 IF p_envelope IS NOT NULL THEN
  IF p_revision !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
   OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object'
   OR p_envelope-ARRAY['v','key_id','nonce','ciphertext']<>'{}'::jsonb
   OR NOT (p_envelope ?& ARRAY['v','key_id','nonce','ciphertext'])
   OR p_envelope->'v' IS DISTINCT FROM '1'::jsonb
   OR jsonb_typeof(p_envelope->'key_id') IS DISTINCT FROM 'string'
   OR jsonb_typeof(p_envelope->'nonce') IS DISTINCT FROM 'string'
   OR jsonb_typeof(p_envelope->'ciphertext') IS DISTINCT FROM 'string'
   OR p_envelope->>'key_id' IS DISTINCT FROM 'ci-profile-key'
   OR p_envelope->>'nonce' !~ '^[A-Za-z0-9+/]{16}$'
   OR length(p_envelope->>'ciphertext') NOT BETWEEN 24 AND 4096
   OR p_envelope->>'ciphertext' !~ '^[A-Za-z0-9+/]+={0,2}$'
  THEN RAISE EXCEPTION 'PROFILE_INPUT'; END IF;
  SELECT x.revision INTO current_revision FROM naruv_draft.profile_envelopes x
   WHERE x.org_id=a.org_id AND x.worker_id=p_worker FOR UPDATE;
  IF p_expected IS NULL THEN
   IF current_revision IS NOT NULL THEN RAISE EXCEPTION 'PROFILE_EXISTS'; END IF;
  ELSE
   IF p_expected !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR p_expected=p_revision THEN RAISE EXCEPTION 'PROFILE_INPUT'; END IF;
   IF current_revision IS NULL THEN RAISE EXCEPTION 'PROFILE_NOT_FOUND'; END IF;
   IF current_revision IS DISTINCT FROM p_expected THEN RAISE EXCEPTION 'PROFILE_STALE'; END IF;
  END IF;
  IF EXISTS(SELECT 1 FROM naruv_draft.profile_revision_history x WHERE (x.org_id,x.worker_id,x.revision)=(a.org_id,p_worker,p_revision))
  THEN RAISE EXCEPTION 'PROFILE_REVISION_REUSED'; END IF;
  SELECT * INTO fresh FROM naruv_native_review.guard(p_csrf,'business');
  IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
   IS DISTINCT FROM (fresh.actor_id,fresh.org_id,fresh.auth_epoch,fresh.session_binding_sha256)
  THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
  IF p_expected IS NULL THEN
   INSERT INTO naruv_draft.profile_envelopes(org_id,worker_id,revision,actor_id,envelope)
   VALUES(a.org_id,p_worker,p_revision,a.actor_id,p_envelope);
  ELSE
   UPDATE naruv_draft.profile_envelopes x SET revision=p_revision,actor_id=a.actor_id,envelope=p_envelope
    WHERE (x.org_id,x.worker_id,x.revision)=(a.org_id,p_worker,p_expected);
   IF NOT FOUND THEN RAISE EXCEPTION 'PROFILE_STALE'; END IF;
  END IF;
  INSERT INTO naruv_draft.profile_revision_history(org_id,worker_id,revision,previous_revision,actor_id)
   VALUES(a.org_id,p_worker,p_revision,p_expected,a.actor_id);
  RETURN jsonb_build_object('status','SEALED','revision',p_revision);
 END IF;
 SELECT jsonb_build_object('revision',x.revision,'envelope',x.envelope) INTO saved
 FROM naruv_draft.profile_envelopes x WHERE x.org_id=a.org_id AND x.worker_id=p_worker;
 IF NOT FOUND THEN RAISE EXCEPTION 'PROFILE_NOT_FOUND'; END IF;
 RETURN saved;
END $$;
REVOKE ALL ON FUNCTION naruv_draft.profile_envelope(text,text,jsonb,text,text) FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_draft.profile_envelope(text,text,jsonb,text,text) TO jw_app_dev;
RESET ROLE;
