-- V8.5: isolated PostgreSQL-native authentication stage.
-- Runs only on jw_dev after V8.4, no user data migrated or exposed.
-- The NOLOGIN role must NEVER be granted to jw_app_dev / anon / authenticated.
BEGIN;
DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='jw_auth_stage_v85') THEN
    CREATE ROLE jw_auth_stage_v85 NOLOGIN NOINHERIT NOBYPASSRLS;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles
             WHERE rolname='jw_auth_stage_v85'
             AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb)) THEN
    RAISE EXCEPTION 'Unsafe auth staging role';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid
    JOIN pg_roles u ON u.oid=m.member
    WHERE r.rolname='jw_auth_stage_v85'
      AND u.rolname IN ('jw_app_dev','anon','authenticated','service_role')
  ) THEN RAISE EXCEPTION 'Auth role membership exposed'; END IF;
END $role$;
GRANT USAGE ON SCHEMA jw_dev TO jw_auth_stage_v85;

CREATE FUNCTION jw_dev.v85_auth_candidate(p_email text)
RETURNS TABLE(user_id text, org_id text, password_hash text,
              mfa_ciphertext text, mfa_counter bigint, is_disabled boolean,
              failure_attempts bigint, failure_first_at text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE v_id text; v_org text; v_hash text; v_cipher text; v_counter bigint;
        v_disabled boolean; v_attempts bigint; v_first text;
BEGIN
  IF p_email IS NULL OR length(p_email) NOT BETWEEN 3 AND 255
    OR p_email<>lower(btrim(p_email)) THEN
    RAISE EXCEPTION 'Invalid normalized email' USING ERRCODE='23514';
  END IF;
  -- The row lock lasts until the caller's transaction commits or rolls back.
  SELECT u.id,u.org_id,u.password_hash,
    COALESCE(m.secret_encrypted,''),COALESCE(m.last_counter,-1),d.user_id IS NOT NULL
  INTO v_id,v_org,v_hash,v_cipher,v_counter,v_disabled
  FROM jw_dev.users u
  LEFT JOIN jw_dev.mfa_credentials m ON m.user_id=u.id
  LEFT JOIN jw_dev.staff_disabled d ON d.user_id=u.id
  WHERE lower(u.email)=p_email
  FOR UPDATE OF u;
  SELECT l.attempts,l.first_failed_at INTO v_attempts,v_first
    FROM jw_dev.login_failures l WHERE l.email=p_email FOR UPDATE;
  RETURN QUERY SELECT v_id,v_org,v_hash,v_cipher,v_counter,
    COALESCE(v_disabled,false),COALESCE(v_attempts,0),v_first;
END $fn$;

CREATE FUNCTION jw_dev.v85_auth_failed(p_email text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
  IF p_email IS NULL OR length(p_email) NOT BETWEEN 3 AND 255
    OR p_email<>lower(btrim(p_email)) THEN
    RAISE EXCEPTION 'Invalid normalized email' USING ERRCODE='23514'; END IF;
  INSERT INTO jw_dev.login_failures(email,attempts,first_failed_at)
  VALUES(p_email,1,clock_timestamp()::text)
  ON CONFLICT(email) DO UPDATE SET
    attempts=CASE WHEN jw_dev.login_failures.first_failed_at::timestamptz
                         <=clock_timestamp()-interval '15 minutes'
                   THEN 1 ELSE jw_dev.login_failures.attempts+1 END,
    first_failed_at=CASE WHEN jw_dev.login_failures.first_failed_at::timestamptz
                         <=clock_timestamp()-interval '15 minutes'
                   THEN clock_timestamp()::text ELSE jw_dev.login_failures.first_failed_at END;
END $fn$;

CREATE FUNCTION jw_dev.v85_auth_issue_session(p_user_id text,p_token_hash text,p_csrf text,
                                              p_mfa_counter bigint DEFAULT NULL,
                                              p_recovery_hash text DEFAULT NULL)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE v_user jw_dev.users%ROWTYPE; v_mfa jw_dev.mfa_credentials%ROWTYPE;
        v_rows int; v_id text;
BEGIN
  IF p_token_hash !~ '^[0-9a-f]{64}$' OR p_csrf IS NULL OR length(p_csrf)<32
      OR length(p_csrf)>256 OR p_user_id IS NULL OR p_user_id='' THEN
    RAISE EXCEPTION 'Invalid session request' USING ERRCODE='23514'; END IF;
  SELECT * INTO v_user FROM jw_dev.users WHERE id=p_user_id FOR UPDATE;
  IF NOT FOUND OR EXISTS (SELECT 1 FROM jw_dev.staff_disabled WHERE user_id=p_user_id) THEN
    RAISE EXCEPTION 'User unavailable' USING ERRCODE='23514'; END IF;
  SELECT * INTO v_mfa FROM jw_dev.mfa_credentials WHERE user_id=p_user_id FOR UPDATE;
  IF FOUND AND v_mfa.secret_encrypted<>'' THEN
    IF (p_mfa_counter IS NULL)=(p_recovery_hash IS NULL) THEN
      RAISE EXCEPTION 'Exactly one MFA proof required' USING ERRCODE='23514'; END IF;
    IF p_mfa_counter IS NOT NULL THEN
      IF p_mfa_counter<=v_mfa.last_counter THEN
        RAISE EXCEPTION 'Replayed OTP' USING ERRCODE='23514'; END IF;
      UPDATE jw_dev.mfa_credentials SET last_counter=p_mfa_counter WHERE user_id=p_user_id;
    ELSE
      UPDATE jw_dev.mfa_recovery_codes SET consumed_at=clock_timestamp()::text
       WHERE user_id=p_user_id AND code_hash=p_recovery_hash AND consumed_at IS NULL;
      GET DIAGNOSTICS v_rows=ROW_COUNT;
      IF v_rows<>1 THEN RAISE EXCEPTION 'Invalid recovery proof' USING ERRCODE='23514'; END IF;
    END IF;
  ELSIF p_mfa_counter IS NOT NULL OR p_recovery_hash IS NOT NULL THEN
    RAISE EXCEPTION 'Unexpected MFA proof' USING ERRCODE='23514';
  END IF;
  v_id=gen_random_uuid()::text;
  INSERT INTO jw_dev.sessions(token_hash,user_id,expires_at,csrf_token,id,created_at)
  VALUES(p_token_hash,p_user_id,(clock_timestamp()+interval '12 hours')::text,
         p_csrf,v_id,clock_timestamp()::text);
  DELETE FROM jw_dev.login_failures WHERE email=lower(v_user.email);
  INSERT INTO jw_dev.security_events(id,org_id,actor_id,event_type,created_at)
  VALUES(gen_random_uuid()::text,v_user.org_id,v_user.id,'login_success',clock_timestamp()::text);
  RETURN v_id;
END $fn$;

CREATE FUNCTION jw_dev.v85_auth_revoke_session(p_token_hash text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE v_uid text; v_org text; v_n integer;
BEGIN
  SELECT s.user_id,u.org_id INTO v_uid,v_org
    FROM jw_dev.sessions s JOIN jw_dev.users u ON u.id=s.user_id
    WHERE s.token_hash=p_token_hash FOR UPDATE OF s;
  IF NOT FOUND THEN RETURN false; END IF;
  DELETE FROM jw_dev.sessions WHERE token_hash=p_token_hash;
  GET DIAGNOSTICS v_n=ROW_COUNT;
  IF v_n<>1 THEN RAISE EXCEPTION 'Unexpected logout state' USING ERRCODE='23514'; END IF;
  INSERT INTO jw_dev.security_events(id,org_id,actor_id,event_type,created_at)
  VALUES(gen_random_uuid()::text,v_org,v_uid,'logout',clock_timestamp()::text);
  RETURN true;
END $fn$;

CREATE FUNCTION jw_dev.v85_auth_check_csrf(p_token_hash text,p_csrf text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT EXISTS(
  SELECT 1 FROM jw_dev.sessions s JOIN jw_dev.users u ON u.id=s.user_id
  LEFT JOIN jw_dev.staff_disabled d ON d.user_id=u.id
  WHERE s.token_hash=p_token_hash AND s.csrf_token=p_csrf AND s.csrf_token<>''
    AND s.expires_at::timestamptz>clock_timestamp() AND d.user_id IS NULL
 )
$fn$;
REVOKE ALL ON FUNCTION jw_dev.v85_auth_candidate(text) FROM PUBLIC,anon,authenticated,service_role,jw_app_dev;
REVOKE ALL ON FUNCTION jw_dev.v85_auth_failed(text) FROM PUBLIC,anon,authenticated,service_role,jw_app_dev;
REVOKE ALL ON FUNCTION jw_dev.v85_auth_issue_session(text,text,text,bigint,text) FROM PUBLIC,anon,authenticated,service_role,jw_app_dev;
REVOKE ALL ON FUNCTION jw_dev.v85_auth_revoke_session(text) FROM PUBLIC,anon,authenticated,service_role,jw_app_dev;
REVOKE ALL ON FUNCTION jw_dev.v85_auth_check_csrf(text,text) FROM PUBLIC,anon,authenticated,service_role,jw_app_dev;
GRANT EXECUTE ON FUNCTION jw_dev.v85_auth_candidate(text) TO jw_auth_stage_v85;
GRANT EXECUTE ON FUNCTION jw_dev.v85_auth_failed(text) TO jw_auth_stage_v85;
GRANT EXECUTE ON FUNCTION jw_dev.v85_auth_issue_session(text,text,text,bigint,text) TO jw_auth_stage_v85;
GRANT EXECUTE ON FUNCTION jw_dev.v85_auth_revoke_session(text) TO jw_auth_stage_v85;
GRANT EXECUTE ON FUNCTION jw_dev.v85_auth_check_csrf(text,text) TO jw_auth_stage_v85;
COMMIT;
