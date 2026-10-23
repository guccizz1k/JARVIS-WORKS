-- Applied 2026-10-23 to Supabase project jarvis-works-dev / jw_dev.
-- Source-of-truth migration name: jw_dev_v88_normalized_auth_lookup_alignment
-- Aligns the login lookup with V8.7's unique index on lower(btrim(email)).
-- Does not modify any user records, session records, or their credentials.
BEGIN;
CREATE OR REPLACE FUNCTION jw_dev.v85_auth_candidate(p_email text)
RETURNS TABLE(user_id text,org_id text,password_hash text,mfa_ciphertext text,mfa_counter bigint,is_disabled boolean,failure_attempts bigint,failure_first_at text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog
AS $body$
DECLARE v_id text; v_org text; v_hash text; v_cipher text; v_counter bigint;
        v_disabled boolean; v_attempts bigint; v_first text;
BEGIN
 IF p_email IS NULL OR length(p_email) NOT BETWEEN 3 AND 255
   OR p_email<>lower(btrim(p_email)) THEN
  RAISE EXCEPTION 'Invalid normalized email' USING ERRCODE='23514';
 END IF;
 SELECT u.id,u.org_id,u.password_hash,
   COALESCE(m.secret_encrypted,''),COALESCE(m.last_counter,-1),d.user_id IS NOT NULL
 INTO v_id,v_org,v_hash,v_cipher,v_counter,v_disabled
 FROM jw_dev.users u
 LEFT JOIN jw_dev.mfa_credentials m ON m.user_id=u.id
 LEFT JOIN jw_dev.staff_disabled d ON d.user_id=u.id
 WHERE lower(btrim(u.email))=p_email FOR UPDATE OF u;
 SELECT l.attempts,l.first_failed_at INTO v_attempts,v_first
 FROM jw_dev.login_failures l WHERE l.email=p_email FOR UPDATE;
 RETURN QUERY SELECT v_id,v_org,v_hash,v_cipher,v_counter,
   COALESCE(v_disabled,false),COALESCE(v_attempts,0),v_first;
END $body$;
REVOKE ALL ON FUNCTION jw_dev.v85_auth_candidate(text) FROM PUBLIC,anon,authenticated,service_role,jw_app_dev;
GRANT EXECUTE ON FUNCTION jw_dev.v85_auth_candidate(text) TO jw_auth_stage_v85;
COMMIT;
