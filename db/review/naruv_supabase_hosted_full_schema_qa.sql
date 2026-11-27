-- ISOLATED QA ONLY. Never apply to production. No source rows, credentials, or LOGIN roles.
-- Authorized target: scvqtsyxkqddoorcaiqr, naruv-one-isolated-qa; connector must verify project identity.
-- Source artifact #186 SQL SHA256 3fb429a2c5f4e3cc32289aad8a9c9d1cb67460f9021dc2ce93388d239b22acd0; original CI-only guard and artifact are unchanged.
-- Separate hosted schema migration derived from successful rollback-only test.
BEGIN;
SET LOCAL statement_timeout='30s';
SET LOCAL lock_timeout='2s';
SET LOCAL transaction_timeout='90s';
SET LOCAL naruv.managed_rehearsal='HOSTED_QA_SCHEMA_ONLY';
SET LOCAL search_path=pg_catalog,pg_temp;
DO $qa$ BEGIN
 IF current_user<>'postgres' OR session_user<>'postgres' OR current_database()<>'postgres'
 OR current_setting('server_version_num')::int<>170012
 OR to_regclass('naruv_qa_probe.fixture') IS NULL OR (SELECT count(*) FROM naruv_qa_probe.fixture)<>2
 OR NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='naruv_qa_probe.fixture'::regclass AND relrowsecurity AND relforcerowsecurity)
 OR NOT EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)
 OR NOT has_database_privilege(current_user,current_database(),'CREATE WITH GRANT OPTION')
 THEN RAISE EXCEPTION 'HOSTED_QA_EXACT_SCOPE'; END IF;
END $qa$;
CREATE TEMP TABLE naruv_qa_platform_roles ON COMMIT DROP AS SELECT rolname,rolsuper,rolinherit,rolcanlogin,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication FROM pg_roles WHERE rolname=ANY(ARRAY['postgres','anon','authenticated','service_role','authenticator','supabase_admin']);
CREATE TEMP TABLE naruv_qa_platform_graph ON COMMIT DROP AS SELECT r.rolname AS granted_role,u.rolname AS member_role,g.rolname AS grantor_role,m.admin_option,m.inherit_option,m.set_option FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member JOIN pg_roles g ON g.oid=m.grantor WHERE r.rolname=ANY(ARRAY['postgres','anon','authenticated','service_role','authenticator','supabase_admin']) AND u.rolname=ANY(ARRAY['postgres','anon','authenticated','service_role','authenticator','supabase_admin']);
CREATE TEMP TABLE naruv_qa_db_acl ON COMMIT DROP AS SELECT a.grantor,a.grantee,a.privilege_type,a.is_grantable FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname=current_database();
DO $guard$ BEGIN
 IF current_setting('naruv.managed_rehearsal',true) IS DISTINCT FROM 'HOSTED_QA_SCHEMA_ONLY'
 OR current_user<>'postgres' OR current_database()<>'postgres'
 OR current_setting('server_version_num')::int/10000<>17
 OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='postgres' AND NOT rolsuper AND rolcreaterole AND rolbypassrls)
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('jw_app_dev','jw_auth_stage_v85','jw_ci_auth','jw_ci_trade','naruv_auth_fence_owner','naruv_ci_ingest','naruv_hid_auth','naruv_hid_business','naruv_hid_ingest','naruv_hid_owner','naruv_hid_reader','naruv_hid_writer','naruv_identity_reader_ci','naruv_messenger_executor_ci','naruv_native_owner','naruv_native_stage','naruv_quote_fence','naruv_sync_broker_ci','naruv_sync_owner_ci','naruv_v85_cutover_ci','naruv_v85_writer_ci'))
 OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspname IN ('jw_dev','naruv_accounting','naruv_auth_fence','naruv_bundle','naruv_customer_bridge','naruv_draft','naruv_finance','naruv_hosted_identity_review','naruv_inventory','naruv_native_review','naruv_production','naruv_quote_bundle','naruv_quote_fence','naruv_sync_ci','naruv_trade','naruv_valuation'))
 OR (SELECT count(*) FROM pg_roles WHERE rolname IN ('anon','authenticated','service_role'))<>3
 OR EXISTS(SELECT 1 FROM pg_default_acl WHERE defaclnamespace=0 AND defaclrole=(SELECT oid FROM pg_roles WHERE rolname='postgres'))
 THEN RAISE EXCEPTION 'MANAGED_INSTALL_GUARD'; END IF;
END $guard$;
CREATE ROLE "jw_app_dev" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "jw_app_dev" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "jw_auth_stage_v85" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "jw_auth_stage_v85" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "jw_ci_auth" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "jw_ci_auth" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "jw_ci_trade" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "jw_ci_trade" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_auth_fence_owner" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_auth_fence_owner" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_ci_ingest" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_ci_ingest" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_hid_auth" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_hid_auth" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_hid_business" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_hid_business" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_hid_ingest" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_hid_ingest" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_hid_owner" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_hid_owner" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_hid_reader" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_hid_reader" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_hid_writer" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_hid_writer" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_identity_reader_ci" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_identity_reader_ci" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_messenger_executor_ci" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_messenger_executor_ci" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_native_owner" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_native_owner" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_native_stage" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_native_stage" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_quote_fence" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_quote_fence" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_sync_broker_ci" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_sync_broker_ci" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_sync_owner_ci" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_sync_owner_ci" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_v85_cutover_ci" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_v85_cutover_ci" TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE ROLE "naruv_v85_writer_ci" NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT "naruv_v85_writer_ci" TO postgres WITH INHERIT FALSE, SET TRUE;
GRANT "jw_app_dev" TO "jw_ci_trade" WITH INHERIT FALSE, SET TRUE;
GRANT "jw_auth_stage_v85" TO "jw_ci_auth" WITH INHERIT FALSE, SET TRUE;
GRANT "jw_auth_stage_v85" TO "naruv_v85_cutover_ci" WITH INHERIT FALSE, SET TRUE;
GRANT "naruv_native_stage" TO "naruv_ci_ingest" WITH INHERIT FALSE, SET TRUE;
--
-- PostgreSQL database dump
--


-- Dumped from database version 17.12 (Debian 17.12-1.pgdg13+1)
-- Dumped by pg_dump version 17.12 (Debian 17.12-1.pgdg13+1)

SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '2s';
SET LOCAL idle_in_transaction_session_timeout = '60s';
SET LOCAL transaction_timeout = '90s';
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: jw_dev; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA jw_dev;


--
-- Name: naruv_accounting; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA naruv_accounting;


--
-- Name: naruv_auth_fence; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA naruv_auth_fence;


--
-- Name: naruv_bundle; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA naruv_bundle;


--
-- Name: naruv_customer_bridge; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA naruv_customer_bridge;


--
-- Name: naruv_draft; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA naruv_draft;


--
-- Name: naruv_finance; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA naruv_finance;


--
-- Name: naruv_hosted_identity_review; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA naruv_hosted_identity_review;


--
-- Name: naruv_inventory; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA naruv_inventory;


--
-- Name: naruv_native_review; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA naruv_native_review;


--
-- Name: naruv_production; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA naruv_production;


--
-- Name: naruv_quote_bundle; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA naruv_quote_bundle;


--
-- Name: naruv_quote_fence; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA naruv_quote_fence;


--
-- Name: naruv_sync_ci; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA naruv_sync_ci;


--
-- Name: naruv_trade; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA naruv_trade;


--
-- Name: naruv_valuation; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA naruv_valuation;


--
-- Name: current_actor_from_session_v82(); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.current_actor_from_session_v82() RETURNS text
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT i.actor_id FROM jw_dev.stage_identity_v84() i
$$;


--
-- Name: current_org_from_session(); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.current_org_from_session() RETURNS text
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT i.org_id FROM jw_dev.stage_identity_v84() i
$$;


--
-- Name: search_messenger_companies_v90(text, integer, integer); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.search_messenger_companies_v90(p_query text DEFAULT ''::text, p_limit integer DEFAULT 30, p_offset integer DEFAULT 0) RETURNS TABLE(org_id text, company_name text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE v_org text; v_q text; v_pattern text;
BEGIN
  v_org:=jw_dev.current_org_from_session();
  IF v_org IS NULL OR NOT EXISTS(
    SELECT 1 FROM jw_dev.messenger_companies mc WHERE mc.org_id=v_org
  ) THEN
    RAISE EXCEPTION 'Verified company session required' USING ERRCODE='42501';
  END IF;
  IF p_query IS NULL OR length(p_query)>80 OR p_limit IS NULL
     OR p_limit NOT BETWEEN 1 AND 50 OR p_offset IS NULL
     OR p_offset NOT BETWEEN 0 AND 100000 THEN
    RAISE EXCEPTION 'Invalid directory search request' USING ERRCODE='23514';
  END IF;
  v_q:=lower(btrim(p_query));
  v_pattern:='%'||replace(replace(replace(v_q,chr(92),chr(92)||chr(92)),
    '%',chr(92)||'%'),'_',chr(92)||'_')||'%';
  RETURN QUERY SELECT o.id,o.name
    FROM jw_dev.messenger_companies m
    JOIN jw_dev.organizations o ON o.id=m.org_id
    WHERE m.org_id<>v_org
      AND (v_q='' OR lower(o.name) LIKE v_pattern ESCAPE E'\\'
         OR m.business_number LIKE v_pattern ESCAPE E'\\')
    ORDER BY lower(o.name),o.id LIMIT p_limit OFFSET p_offset;
END $$;


--
-- Name: stage_identity_v84(); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.stage_identity_v84() RETURNS TABLE(actor_id text, org_id text, actor_role text, csrf_token text, org_name text)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT u.id,u.org_id,u.role,l.csrf_token,o.name FROM jw_dev.sessions l
 JOIN jw_dev.users u ON u.id=l.user_id JOIN jw_dev.organizations o ON o.id=u.org_id
 JOIN naruv_hosted_identity_review.sessions s ON s.token_hash=l.token_hash AND s.actor_id=l.user_id
 JOIN naruv_hosted_identity_review.users h ON h.id=s.actor_id
 LEFT JOIN jw_dev.staff_disabled d ON d.user_id=u.id
 WHERE l.token_hash=nullif(current_setting('jw.session_hash',true),'')
 AND l.csrf_token=s.csrf_token AND l.csrf_token<>'' AND l.expires_at::timestamptz=s.expires_at
 AND s.expires_at>clock_timestamp() AND NOT s.revoked AND h.active AND s.epoch=h.epoch
 AND h.org_id=u.org_id AND h.actor_role=u.role AND d.user_id IS NULL
$$;


--
-- Name: v85_auth_candidate(text); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.v85_auth_candidate(p_email text) RETURNS TABLE(user_id text, org_id text, password_hash text, mfa_ciphertext text, mfa_counter bigint, is_disabled boolean, failure_attempts bigint, failure_first_at text)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE actor text;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'CUTOVER_ISOLATION' USING ERRCODE='25000'; END IF;
 SELECT u.id INTO actor FROM jw_dev.users u WHERE lower(u.email)=p_email;
 -- Hosted user before native user, same order as management change.
 IF FOUND THEN
  PERFORM 1 FROM naruv_hosted_identity_review.users h WHERE h.id=actor FOR UPDATE;
 END IF;
 RETURN QUERY SELECT c.user_id,c.org_id,c.password_hash,c.mfa_ciphertext,c.mfa_counter,
  c.is_disabled,c.failure_attempts,c.failure_first_at FROM jw_dev.v85_candidate_native_ci(p_email) c;
END $$;


--
-- Name: v85_auth_check_csrf(text, text); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.v85_auth_check_csrf(p_token_hash text, p_csrf text) RETURNS boolean
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT EXISTS(SELECT 1 FROM jw_dev.sessions l JOIN jw_dev.users u ON u.id=l.user_id
 JOIN naruv_hosted_identity_review.sessions s ON s.token_hash=l.token_hash AND s.actor_id=l.user_id
 JOIN naruv_hosted_identity_review.users h ON h.id=s.actor_id
 LEFT JOIN jw_dev.staff_disabled d ON d.user_id=u.id
 WHERE l.token_hash=p_token_hash AND l.csrf_token=p_csrf AND s.csrf_token=p_csrf
 AND p_csrf<>'' AND l.expires_at::timestamptz=s.expires_at AND s.expires_at>clock_timestamp()
 AND NOT s.revoked AND h.active AND s.epoch=h.epoch AND h.org_id=u.org_id AND h.actor_role=u.role AND d.user_id IS NULL)
$$;


--
-- Name: v85_auth_failed(text); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.v85_auth_failed(p_email text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
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
END $$;


--
-- Name: v85_auth_issue_session(text, text, text, bigint, text); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.v85_auth_issue_session(p_user_id text, p_token_hash text, p_csrf text, p_mfa_counter bigint DEFAULT NULL::bigint, p_recovery_hash text DEFAULT NULL::text) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE h naruv_hosted_identity_review.users%ROWTYPE; l jw_dev.users%ROWTYPE; v_id text; expiry timestamptz;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'CUTOVER_INPUT' USING ERRCODE='23514'; END IF;
 SELECT * INTO h FROM naruv_hosted_identity_review.users WHERE id=p_user_id FOR UPDATE;
 IF NOT FOUND OR NOT h.active THEN RAISE EXCEPTION 'CUTOVER_IDENTITY' USING ERRCODE='23514'; END IF;
 SELECT * INTO l FROM jw_dev.users WHERE id=p_user_id FOR UPDATE;
 IF NOT FOUND OR (h.id,h.org_id,h.actor_role) IS DISTINCT FROM (l.id,l.org_id,l.role) THEN RAISE EXCEPTION 'CUTOVER_IDENTITY' USING ERRCODE='23514'; END IF;
 -- Original MFA/recovery, native session, login failure reset and audit event.
 v_id:=jw_dev.v85_issue_native_ci(p_user_id,p_token_hash,p_csrf,p_mfa_counter,p_recovery_hash);
 SELECT expires_at::timestamptz INTO STRICT expiry FROM jw_dev.sessions WHERE id=v_id AND token_hash=p_token_hash;
 INSERT INTO naruv_hosted_identity_review.sessions(token_hash,actor_id,epoch,csrf_token,expires_at)
 VALUES(p_token_hash,h.id,h.epoch,p_csrf,expiry);
 RETURN v_id;
END $_$;


--
-- Name: v85_auth_revoke_session(text); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.v85_auth_revoke_session(p_token_hash text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE actor text; n int;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'CUTOVER_ISOLATION' USING ERRCODE='25000'; END IF;
 SELECT actor_id INTO actor FROM naruv_hosted_identity_review.sessions WHERE token_hash=p_token_hash;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM naruv_hosted_identity_review.users WHERE id=actor FOR UPDATE;
 UPDATE naruv_hosted_identity_review.sessions SET revoked=true WHERE token_hash=p_token_hash AND actor_id=actor AND NOT revoked;
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n<>1 THEN RETURN false; END IF;
 IF NOT jw_dev.v85_revoke_native_ci(p_token_hash) THEN RAISE EXCEPTION 'CUTOVER_REVOKE_DRIFT' USING ERRCODE='42501'; END IF;
 RETURN true;
END $$;


--
-- Name: v85_candidate_native_ci(text); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.v85_candidate_native_ci(p_email text) RETURNS TABLE(user_id text, org_id text, password_hash text, mfa_ciphertext text, mfa_counter bigint, is_disabled boolean, failure_attempts bigint, failure_first_at text)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
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
END $$;


--
-- Name: v85_issue_native_ci(text, text, text, bigint, text); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.v85_issue_native_ci(p_user_id text, p_token_hash text, p_csrf text, p_mfa_counter bigint DEFAULT NULL::bigint, p_recovery_hash text DEFAULT NULL::text) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
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
END $_$;


--
-- Name: v85_revoke_native_ci(text); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.v85_revoke_native_ci(p_token_hash text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
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
END $$;


--
-- Name: v90_edit_text(text, text, bigint); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.v90_edit_text(p_message_id text, p_new_body text, p_expected_version bigint) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE v_org text; v_actor text; v_m jw_dev.messenger_messages%ROWTYPE; v_version bigint;
  v_event_at timestamptz; v_connection_id text;
BEGIN
  v_org:=jw_dev.current_org_from_session(); v_actor:=jw_dev.current_actor_from_session_v82();
  IF v_org IS NULL OR v_actor IS NULL OR p_new_body IS NULL
    OR length(p_new_body)>5000 OR btrim(p_new_body)=''
  THEN RAISE EXCEPTION 'Invalid edit request or session' USING ERRCODE='42501'; END IF;
  -- Read candidate chat WITHOUT taking a row lock. This is only a hint for
  -- choosing a per-chat advisory lock, NOT authorization for the write.
  SELECT m.connection_id INTO v_connection_id FROM jw_dev.messenger_messages m
  JOIN jw_dev.messenger_connections c ON c.id=m.connection_id
  WHERE m.id=p_message_id AND m.sender_org=v_org AND m.sender_user=v_actor
    AND m.kind='text' AND c.status='active' AND v_org IN(c.org_a,c.org_b);
  IF NOT FOUND THEN RAISE EXCEPTION 'Message not owned by actor' USING ERRCODE='42501'; END IF;
  -- Global lock order: conversation advisory lock FIRST; message FOR UPDATE SECOND.
  -- Never hold a message row lock while waiting for the conversation lock.
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('jw_dev.v90.messenger/' || v_connection_id, 0));
  IF jw_dev.current_org_from_session() IS DISTINCT FROM v_org
    OR jw_dev.current_actor_from_session_v82() IS DISTINCT FROM v_actor
  THEN RAISE EXCEPTION 'Session revoked before edit' USING ERRCODE='42501'; END IF;
  -- Recheck authorization, active chat and current version after any wait.
  SELECT m.* INTO v_m FROM jw_dev.messenger_messages m
  JOIN jw_dev.messenger_connections c ON c.id=m.connection_id
  WHERE m.id=p_message_id AND m.connection_id=v_connection_id
    AND m.sender_org=v_org AND m.sender_user=v_actor
    AND m.kind='text' AND c.status='active' AND v_org IN(c.org_a,c.org_b)
  FOR UPDATE OF m;
  IF NOT FOUND THEN RAISE EXCEPTION 'Message or chat revoked before edit' USING ERRCODE='42501'; END IF;
  IF clock_timestamp() > v_m.created_at::timestamptz + interval '30 minutes'
  THEN RAISE EXCEPTION 'Edit window expired' USING ERRCODE='42501'; END IF;
  IF p_expected_version IS DISTINCT FROM v_m.version
  THEN RAISE EXCEPTION 'Version conflict' USING ERRCODE='40001'; END IF;
  IF v_m.body IS NOT DISTINCT FROM p_new_body THEN RETURN v_m.version; END IF;
  v_version:=v_m.version+1;
  -- Existing edit cursor is (edited_at, edit_id). Ensure a STRICTLY increasing
  -- timestamp within this conversation, including equal-clock-tick commits.
  -- This query is protected by the per-conversation advisory transaction lock.
  -- Its O(edit history) cost must be benchmarked before production.
  SELECT greatest(clock_timestamp(),
         coalesce(max(e.edited_at::timestamptz) + interval '1 microsecond',
                  clock_timestamp()))
    INTO v_event_at
    FROM jw_dev.messenger_edits e
    JOIN jw_dev.messenger_messages historical ON historical.id=e.message_id
    WHERE historical.connection_id=v_m.connection_id;
  UPDATE jw_dev.messenger_messages SET body=p_new_body,version=v_version,
    edited_at=v_event_at::text WHERE id=p_message_id;
  INSERT INTO jw_dev.messenger_edits
    (id,message_id,previous_body,new_body,actor_user,edited_at,version)
  VALUES(gen_random_uuid()::text,p_message_id,v_m.body,p_new_body,v_actor,v_event_at::text,v_version);
  RETURN v_version;
END $$;


--
-- Name: v90_mark_read(text, bigint); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.v90_mark_read(p_connection_id text, p_cursor bigint) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE v_org text; v_actor text; v_max bigint; v_out bigint;
BEGIN
  v_org:=jw_dev.current_org_from_session(); v_actor:=jw_dev.current_actor_from_session_v82();
  IF v_org IS NULL OR v_actor IS NULL OR NOT EXISTS(
    SELECT 1 FROM jw_dev.messenger_connections c WHERE c.id=p_connection_id
       AND c.status='active' AND v_org IN(c.org_a,c.org_b))
  THEN RAISE EXCEPTION 'Not a chat participant' USING ERRCODE='42501'; END IF;
  SELECT coalesce(max(message_seq),0) INTO v_max
    FROM jw_dev.messenger_messages WHERE connection_id=p_connection_id;
  IF p_cursor IS NULL OR p_cursor<0 OR p_cursor>v_max
  THEN RAISE EXCEPTION 'Invalid read cursor' USING ERRCODE='23514'; END IF;
  INSERT INTO jw_dev.messenger_read_positions
    (connection_id,org_id,last_read_rowid,updated_at,last_read_seq)
  VALUES(p_connection_id,v_org,0,clock_timestamp()::text,p_cursor)
  ON CONFLICT (connection_id,org_id) DO UPDATE
    SET last_read_seq=greatest(coalesce(jw_dev.messenger_read_positions.last_read_seq,0),
                                excluded.last_read_seq),
        updated_at=clock_timestamp()::text
  RETURNING last_read_seq INTO v_out;
  RETURN v_out;
END $$;


--
-- Name: v90_send_text(text, text, text, text, text, bytea); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.v90_send_text(p_connection_id text, p_request_id text, p_body text, p_filename text DEFAULT NULL::text, p_mime text DEFAULT NULL::text, p_data bytea DEFAULT NULL::bytea) RETURNS TABLE(message_id text, message_cursor bigint, replayed boolean)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE v_org text; v_actor text; v_saved jw_dev.messenger_messages%ROWTYPE;
  v_added boolean; v_sha text; v_file jw_dev.messenger_attachments%ROWTYPE;
BEGIN
  v_org:=jw_dev.current_org_from_session(); v_actor:=jw_dev.current_actor_from_session_v82();
  IF v_org IS NULL OR v_actor IS NULL
    OR NOT EXISTS (SELECT 1 FROM jw_dev.messenger_companies WHERE org_id=v_org)
    OR NOT EXISTS (SELECT 1 FROM jw_dev.messenger_connections c
      WHERE c.id=p_connection_id AND c.status='active' AND v_org IN(c.org_a,c.org_b)
      AND EXISTS (SELECT 1 FROM jw_dev.messenger_companies mc
                  WHERE mc.org_id=CASE WHEN c.org_a=v_org THEN c.org_b ELSE c.org_a END))
  THEN RAISE EXCEPTION 'Not a verified active chat participant' USING ERRCODE='42501'; END IF;
  IF p_request_id IS NULL OR length(p_request_id) NOT BETWEEN 8 AND 128 OR
     p_body IS NULL OR length(p_body)>5000 OR
     (btrim(p_body)='' AND p_data IS NULL)
  THEN RAISE EXCEPTION 'Invalid message request' USING ERRCODE='23514'; END IF;
  IF (p_data IS NULL AND (p_filename IS NOT NULL OR p_mime IS NOT NULL))
    OR (p_data IS NOT NULL AND
      (octet_length(p_data) NOT BETWEEN 1 AND 5242880
       OR p_filename IS NULL OR length(p_filename) NOT BETWEEN 1 AND 180
       OR p_filename LIKE '%/%' OR p_filename LIKE '%'||chr(92)||'%'
       OR p_mime IS NULL OR p_mime NOT IN (
         'image/jpeg','image/png','image/webp','image/gif','application/pdf',
         'text/plain','application/vnd.openxmlformats-officedocument.wordprocessingml.document',
         'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')))
  THEN RAISE EXCEPTION 'Invalid attachment' USING ERRCODE='23514'; END IF;
  -- Serialize writers per conversation until COMMIT; nextval must execute AFTER this lock.
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('jw_dev.v90.messenger/' || p_connection_id, 0));
  -- Authorization can be revoked while waiting for the lock: check it AGAIN
  -- under a new READ COMMITTED snapshot before writing or using the sequence.
  IF jw_dev.current_org_from_session() IS DISTINCT FROM v_org
    OR jw_dev.current_actor_from_session_v82() IS DISTINCT FROM v_actor
    OR NOT EXISTS (
      SELECT 1 FROM jw_dev.messenger_connections c WHERE c.id=p_connection_id
      AND c.status='active' AND v_org IN(c.org_a,c.org_b)
      AND EXISTS(SELECT 1 FROM jw_dev.messenger_companies mc WHERE mc.org_id=CASE WHEN c.org_a=v_org THEN c.org_b ELSE c.org_a END))
  THEN RAISE EXCEPTION 'Chat or session revoked before send' USING ERRCODE='42501'; END IF;
  v_sha:=CASE WHEN p_data IS NULL THEN NULL ELSE encode(sha256(p_data),'hex') END;
  INSERT INTO jw_dev.messenger_messages
    (id,connection_id,sender_org,sender_user,kind,body,actor_name,
     request_id,version,created_at,message_seq)
  VALUES (gen_random_uuid()::text,p_connection_id,v_org,v_actor,'text',p_body,
    '',p_request_id,1,clock_timestamp()::text,nextval('jw_dev.messenger_seq_v90'))
  ON CONFLICT (sender_org,request_id) DO NOTHING
  RETURNING * INTO v_saved;
  v_added:=FOUND;
  IF NOT v_added THEN
    SELECT * INTO v_saved FROM jw_dev.messenger_messages m
      WHERE m.sender_org=v_org AND m.request_id=p_request_id;
    IF NOT FOUND OR v_saved.connection_id IS DISTINCT FROM p_connection_id
      OR v_saved.sender_user IS DISTINCT FROM v_actor OR v_saved.kind<>'text'
      OR v_saved.body IS DISTINCT FROM p_body
    THEN RAISE EXCEPTION 'Idempotency key collision' USING ERRCODE='23505'; END IF;
    SELECT * INTO v_file FROM jw_dev.messenger_attachments a WHERE a.message_id=v_saved.id;
    IF (p_data IS NULL AND FOUND) OR (p_data IS NOT NULL AND
       (NOT FOUND OR v_file.filename IS DISTINCT FROM p_filename OR
        v_file.mime IS DISTINCT FROM p_mime OR v_file.content_hash IS DISTINCT FROM v_sha))
    THEN RAISE EXCEPTION 'Idempotency attachment mismatch' USING ERRCODE='23505'; END IF;
  ELSIF p_data IS NOT NULL THEN
    INSERT INTO jw_dev.messenger_attachments
      (message_id,filename,mime,data,size_bytes,content_hash)
    VALUES (v_saved.id,p_filename,p_mime,p_data,octet_length(p_data),v_sha);
  END IF;
  RETURN QUERY SELECT v_saved.id,v_saved.message_seq,NOT v_added;
END $$;


--
-- Name: v90_start_chat(text); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.v90_start_chat(p_other_org text) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE v_org text; v_actor text; v_id text;
BEGIN
  v_org:=jw_dev.current_org_from_session(); v_actor:=jw_dev.current_actor_from_session_v82();
  IF v_org IS NULL OR v_actor IS NULL OR p_other_org IS NULL OR p_other_org=v_org
     OR NOT EXISTS (SELECT 1 FROM jw_dev.messenger_companies WHERE org_id=v_org)
     OR NOT EXISTS (SELECT 1 FROM jw_dev.messenger_companies WHERE org_id=p_other_org)
  THEN RAISE EXCEPTION 'Verified company session and different verified recipient required' USING ERRCODE='42501'; END IF;
  INSERT INTO jw_dev.messenger_connections
    (id,org_a,org_b,requester_org,status,created_at,accepted_at)
  VALUES (gen_random_uuid()::text,least(v_org,p_other_org),greatest(v_org,p_other_org),
    v_org,'active',clock_timestamp()::text,clock_timestamp()::text)
  ON CONFLICT (org_a,org_b) DO UPDATE SET status='active',
    accepted_at=coalesce(jw_dev.messenger_connections.accepted_at,clock_timestamp()::text)
  RETURNING id INTO v_id;
  RETURN v_id;
END $$;


--
-- Name: v90_sync_edits(text, timestamp with time zone, text, integer); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.v90_sync_edits(p_connection_id text, p_after_at timestamp with time zone DEFAULT '1970-01-01 00:00:00+00'::timestamp with time zone, p_after_edit_id text DEFAULT ''::text, p_limit integer DEFAULT 50) RETURNS TABLE(edit_id text, message_id text, version bigint, new_body text, edited_at text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE v_org text; v_actor text;
BEGIN
 v_org:=jw_dev.current_org_from_session(); v_actor:=jw_dev.current_actor_from_session_v82();
 IF v_org IS NULL OR v_actor IS NULL OR NOT EXISTS
 (SELECT 1 FROM jw_dev.messenger_connections c WHERE c.id=p_connection_id
   AND c.status='active' AND v_org IN(c.org_a,c.org_b))
 THEN RAISE EXCEPTION 'Not a chat participant' USING ERRCODE='42501'; END IF;
 IF p_after_at IS NULL OR p_after_edit_id IS NULL OR p_limit IS NULL
    OR p_limit NOT BETWEEN 1 AND 100
 THEN RAISE EXCEPTION 'Invalid edit sync cursor' USING ERRCODE='23514'; END IF;
 RETURN QUERY SELECT e.id,e.message_id,e.version,e.new_body,e.edited_at
 FROM jw_dev.messenger_edits e
 JOIN jw_dev.messenger_messages m ON m.id=e.message_id
 WHERE m.connection_id=p_connection_id AND
   (e.edited_at::timestamptz>p_after_at OR
     (e.edited_at::timestamptz=p_after_at AND e.id>p_after_edit_id))
 ORDER BY e.edited_at::timestamptz,e.id LIMIT p_limit;
END $$;


--
-- Name: v90_sync_messages(text, bigint, integer); Type: FUNCTION; Schema: jw_dev; Owner: -
--

CREATE FUNCTION jw_dev.v90_sync_messages(p_connection_id text, p_after_cursor bigint DEFAULT 0, p_limit integer DEFAULT 50) RETURNS TABLE(message_id text, message_cursor bigint, sender_org text, sender_user text, body text, version bigint, created_at text, edited_at text, filename text, mime text, size_bytes bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE v_org text; v_actor text;
BEGIN
  v_org:=jw_dev.current_org_from_session(); v_actor:=jw_dev.current_actor_from_session_v82();
  IF v_org IS NULL OR v_actor IS NULL OR NOT EXISTS (
    SELECT 1 FROM jw_dev.messenger_connections c WHERE c.id=p_connection_id
    AND c.status='active' AND v_org IN(c.org_a,c.org_b))
  THEN RAISE EXCEPTION 'Not a chat participant' USING ERRCODE='42501'; END IF;
  IF p_after_cursor IS NULL OR p_after_cursor<0 OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100
  THEN RAISE EXCEPTION 'Invalid sync paging' USING ERRCODE='23514'; END IF;
  RETURN QUERY SELECT m.id,m.message_seq,m.sender_org,m.sender_user,m.body,
    m.version,m.created_at,m.edited_at,a.filename,a.mime,a.size_bytes
    FROM jw_dev.messenger_messages m
    LEFT JOIN jw_dev.messenger_attachments a ON a.message_id=m.id
    WHERE m.connection_id=p_connection_id AND m.message_seq>p_after_cursor
    ORDER BY m.message_seq LIMIT p_limit;
END $$;


--
-- Name: close_period(text, boolean, text); Type: FUNCTION; Schema: naruv_accounting; Owner: -
--

CREATE FUNCTION naruv_accounting.close_period(p_month text, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a record; a2 record; p naruv_accounting.periods; m date;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_confirm IS DISTINCT FROM true OR p_month IS NULL OR p_month !~ '^[0-9]{4}-(0[1-9]|1[0-2])-01$' OR left(p_month,4)='0000'
 THEN RAISE EXCEPTION 'ACCT_INPUT'; END IF;
 m:=p_month::date;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO p FROM naruv_accounting.periods x WHERE x.org_id=a.org_id AND x.period_start=m FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'ACCT_NOT_FOUND'; END IF;
 IF p.closed_at IS NULL THEN
  UPDATE naruv_accounting.periods x SET closed_at=clock_timestamp(),closed_by=a.actor_id
   WHERE x.org_id=a.org_id AND x.period_start=m RETURNING * INTO p;
 END IF;
 RETURN jsonb_build_object('period_start',p.period_start,'state','CLOSED','closed_at',p.closed_at,'production_authorized',false);
END $_$;


--
-- Name: inspect_bill(text, text); Type: FUNCTION; Schema: naruv_accounting; Owner: -
--

CREATE FUNCTION naruv_accounting.inspect_bill(p_bill text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; b naruv_finance.bills; paid_amt bigint; ar numeric; ap numeric; dr numeric; cr numeric; entries jsonb; n bigint; jn bigint; due bigint;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO b FROM naruv_finance.bills x WHERE x.org_id=a.org_id AND x.bill_id=p_bill;
 IF NOT FOUND THEN RAISE EXCEPTION 'ACCT_NOT_FOUND'; END IF;
 paid_amt:=naruv_finance.paid(a.org_id,p_bill);
 SELECT count(*) INTO n FROM naruv_finance.events x WHERE x.org_id=a.org_id AND x.bill_id=p_bill;
 SELECT count(*) INTO jn FROM naruv_accounting.journals x WHERE x.org_id=a.org_id AND x.bill_id=p_bill;
 SELECT coalesce(sum(l.debit),0),coalesce(sum(l.credit),0),
 coalesce(sum(l.debit-l.credit) FILTER(WHERE l.account='AR'),0),
 coalesce(sum(l.credit-l.debit) FILTER(WHERE l.account='AP'),0)
 INTO dr,cr,ar,ap FROM naruv_accounting.lines l JOIN naruv_accounting.journals j USING(org_id,event_id)
 WHERE j.org_id=a.org_id AND j.bill_id=p_bill;
 due:=b.total-paid_amt-naruv_finance.credit_sum(a.org_id,p_bill);
 IF due<0 OR n<>jn OR n=0 OR dr<>cr OR paid_amt<0 OR paid_amt>b.total
 OR ar<>(CASE WHEN b.kind='sale' THEN due ELSE 0 END)
 OR ap<>(CASE WHEN b.kind='purchase' THEN due ELSE 0 END) THEN RAISE EXCEPTION 'ACCT_RECONCILIATION'; END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.account),'[]'::jsonb) INTO entries FROM (
  SELECT l.account,sum(l.debit) AS debit,sum(l.credit) AS credit FROM naruv_accounting.lines l
  JOIN naruv_accounting.journals j USING(org_id,event_id) WHERE j.org_id=a.org_id AND j.bill_id=p_bill GROUP BY l.account
 ) x;
 RETURN jsonb_build_object('bill_id',p_bill,'journal_count',jn,'debit',dr,'credit',cr,'ar',ar,'ap',ap,
 'outstanding',due,'accounts',entries,'production_authorized',false);
END $$;


--
-- Name: period_guard(); Type: FUNCTION; Schema: naruv_accounting; Owner: -
--

CREATE FUNCTION naruv_accounting.period_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'ACCT_PERIOD_IMMUTABLE'; END IF;
 IF OLD.closed_at IS NOT NULL OR (OLD.org_id,OLD.period_start) IS DISTINCT FROM (NEW.org_id,NEW.period_start)
 OR NEW.closed_at IS NULL OR NEW.closed_by IS NULL THEN RAISE EXCEPTION 'ACCT_PERIOD_IMMUTABLE'; END IF;
 RETURN NEW;
END $$;


--
-- Name: post_finance(); Type: FUNCTION; Schema: naruv_accounting; Owner: -
--

CREATE FUNCTION naruv_accounting.post_finance() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE b naruv_finance.bills; p naruv_accounting.periods; a record; month_start date; net bigint; tax bigint; variance bigint;
BEGIN
 IF current_user<>'naruv_native_owner' THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT i.actor_id,i.org_id,i.actor_role INTO a FROM jw_dev.stage_identity_v84() i;
 IF NOT FOUND OR (a.actor_id,a.org_id,a.actor_role) IS DISTINCT FROM (NEW.actor_id,NEW.org_id,'admin'::text)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 month_start:=date_trunc('month',NEW.created_at AT TIME ZONE 'Asia/Seoul')::date;
 SELECT * INTO p FROM naruv_accounting.periods x WHERE x.org_id=NEW.org_id AND x.period_start=month_start FOR UPDATE;
 IF NOT FOUND OR p.closed_at IS NOT NULL THEN RAISE EXCEPTION 'ACCT_PERIOD_CLOSED'; END IF;
 SELECT * INTO b FROM naruv_finance.bills x WHERE x.org_id=NEW.org_id AND x.bill_id=NEW.bill_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'ACCT_SOURCE_MISSING'; END IF;
 INSERT INTO naruv_accounting.journals VALUES(NEW.org_id,NEW.request_id,NEW.bill_id,month_start,NEW.actor_id,NEW.action,NEW.created_at,NEW.reversal_of);
 IF NEW.action='bill' THEN
  IF b.total=0 THEN RETURN NEW; END IF;
  IF b.kind='sale' THEN
   INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,1,'AR',b.total,0);
   IF b.subtotal>0 THEN INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,2,'SALES',0,b.subtotal); END IF;
   IF b.vat>0 THEN INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,3,'VAT_OUTPUT',0,b.vat); END IF;
  ELSE
   INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,1,'AP',0,b.total);
   IF b.subtotal>0 THEN INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,2,'PURCHASE_CLEARING',b.subtotal,0); END IF;
   IF b.vat>0 THEN INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,3,'VAT_INPUT',b.vat,0); END IF;
  END IF;
 ELSIF NEW.action='pay' THEN
  IF b.kind='sale' THEN
   INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,1,'CASH_CLEARING',NEW.amount,0),(NEW.org_id,NEW.request_id,2,'AR',0,NEW.amount);
  ELSE
   INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,1,'AP',NEW.amount,0),(NEW.org_id,NEW.request_id,2,'CASH_CLEARING',0,NEW.amount);
  END IF;
 ELSIF NEW.action='refund' THEN
  IF NEW.amount<1 THEN RAISE EXCEPTION 'ACCT_RECONCILIATION'; END IF;
  IF b.kind='sale' THEN
   INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,1,'AR',NEW.amount,0),(NEW.org_id,NEW.request_id,2,'CASH_CLEARING',0,NEW.amount);
  ELSE
   INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,1,'AP',0,NEW.amount),(NEW.org_id,NEW.request_id,2,'CASH_CLEARING',NEW.amount,0);
  END IF;
 ELSIF NEW.action='credit' THEN
  net:=(NEW.payload->>'net')::bigint;tax:=(NEW.payload->>'vat')::bigint;
  IF net IS NULL OR tax IS NULL OR net<0 OR tax<0 OR NEW.amount<>net+tax
   OR naruv_finance.paid(NEW.org_id,NEW.bill_id)+naruv_finance.credit_sum(NEW.org_id,NEW.bill_id)>b.total
  THEN RAISE EXCEPTION 'ACCT_RECONCILIATION'; END IF;
  IF NOT EXISTS(SELECT 1 FROM naruv_accounting.journals j WHERE j.org_id=NEW.org_id AND j.bill_id=NEW.bill_id AND j.action='bill')
  THEN RAISE EXCEPTION 'ACCT_SOURCE_MISSING'; END IF;
  variance:=coalesce((NEW.payload->>'variance')::bigint,0);
  IF b.kind='sale' AND variance<>0 THEN RAISE EXCEPTION 'ACCT_RECONCILIATION'; END IF;
  IF NEW.amount>0 AND b.kind='sale' THEN
   INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,1,'AR',0,NEW.amount);
   IF net>0 THEN INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,2,'SALES',net,0); END IF;
   IF tax>0 THEN INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,3,'VAT_OUTPUT',tax,0); END IF;
  ELSIF NEW.amount>0 THEN
   INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,1,'AP',NEW.amount,0);
   IF net>0 THEN INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,2,'PURCHASE_CLEARING',0,net); END IF;
   IF tax>0 THEN INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,3,'VAT_INPUT',0,tax); END IF;
  END IF;
  IF variance>0 THEN
   INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,4,'PURCHASE_CLEARING',variance,0),(NEW.org_id,NEW.request_id,5,'PURCHASE_COST_VARIANCE',0,variance);
  ELSIF variance<0 THEN
   INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,4,'PURCHASE_CLEARING',0,-variance),(NEW.org_id,NEW.request_id,5,'PURCHASE_COST_VARIANCE',-variance,0);
  END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM naruv_accounting.journals j WHERE j.org_id=NEW.org_id AND j.event_id=NEW.reversal_of AND j.bill_id=NEW.bill_id AND j.action='pay')
  THEN RAISE EXCEPTION 'ACCT_SOURCE_MISSING'; END IF;
  INSERT INTO naruv_accounting.lines SELECT NEW.org_id,NEW.request_id,l.line_no,l.account,l.credit,l.debit
   FROM naruv_accounting.lines l WHERE l.org_id=NEW.org_id AND l.event_id=NEW.reversal_of;
 END IF;
 RETURN NEW;
END $$;


--
-- Name: validate_journal(); Type: FUNCTION; Schema: naruv_accounting; Owner: -
--

CREATE FUNCTION naruv_accounting.validate_journal() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE expected numeric; dr numeric; cr numeric; cnt bigint;
BEGIN
 SELECT CASE WHEN e.action='bill' THEN b.total WHEN e.action='credit' THEN e.amount::numeric+abs(coalesce((e.payload->>'variance')::numeric,0)) ELSE e.amount END INTO expected
 FROM naruv_finance.events e JOIN naruv_finance.bills b ON (b.org_id,b.bill_id)=(e.org_id,e.bill_id)
 WHERE e.org_id=NEW.org_id AND e.request_id=NEW.event_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'ACCT_SOURCE_MISSING'; END IF;
 SELECT coalesce(sum(l.debit),0),coalesce(sum(l.credit),0),count(*) INTO dr,cr,cnt
 FROM naruv_accounting.lines l WHERE l.org_id=NEW.org_id AND l.event_id=NEW.event_id;
 IF dr<>expected OR cr<>expected OR (expected>0 AND cnt NOT BETWEEN 2 AND 5)
 OR (expected=0 AND cnt<>0) THEN RAISE EXCEPTION 'ACCT_UNBALANCED'; END IF;
 RETURN NULL;
END $$;


--
-- Name: auth_change(); Type: FUNCTION; Schema: naruv_auth_fence; Owner: -
--

CREATE FUNCTION naruv_auth_fence.auth_change() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE old_actor text; new_actor text; actor text; bump boolean:=true;
BEGIN
 IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'NARUV_AUTH_TRUNCATE_DENIED'; END IF;
 IF TG_TABLE_NAME='users' THEN
  IF TG_OP<>'INSERT' THEN old_actor:=OLD.id; END IF;
  IF TG_OP<>'DELETE' THEN new_actor:=NEW.id; END IF;
  IF TG_OP='UPDATE' THEN
   IF (OLD.id,OLD.org_id,OLD.role) IS NOT DISTINCT FROM (NEW.id,NEW.org_id,NEW.role)
   THEN RETURN NEW; END IF;
  END IF;
 ELSE
  IF TG_OP<>'INSERT' THEN old_actor:=OLD.user_id; END IF;
  IF TG_OP<>'DELETE' THEN new_actor:=NEW.user_id; END IF;
  IF TG_TABLE_NAME='sessions' THEN
   IF TG_OP='INSERT' THEN bump:=false; END IF;
   IF TG_OP='UPDATE' THEN
    IF (OLD.id,OLD.user_id,OLD.token_hash,OLD.csrf_token,OLD.expires_at)
       IS NOT DISTINCT FROM (NEW.id,NEW.user_id,NEW.token_hash,NEW.csrf_token,NEW.expires_at)
    THEN RETURN NEW; END IF;
   END IF;
  END IF;
 END IF;
 FOR actor IN SELECT DISTINCT x FROM unnest(ARRAY[old_actor,new_actor]) x WHERE x IS NOT NULL ORDER BY x LOOP
  PERFORM naruv_auth_fence.lock_actor(actor);
  IF bump THEN
   INSERT INTO naruv_auth_fence.epochs AS e VALUES(actor,1)
   ON CONFLICT(actor_id) DO UPDATE SET epoch=e.epoch+1;
  END IF;
 END LOOP;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;


--
-- Name: lock_actor(text); Type: FUNCTION; Schema: naruv_auth_fence; Owner: -
--

CREATE FUNCTION naruv_auth_fence.lock_actor(p_actor text) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE generation bigint;
BEGIN
 IF p_actor IS NULL OR p_actor='' OR current_setting('transaction_isolation') <> 'read committed'
 THEN RAISE EXCEPTION 'NARUV_AUTH_FENCE_UNSAFE' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-native-auth-v1:'||p_actor,0));
 SELECT e.epoch INTO generation FROM naruv_auth_fence.epochs e WHERE e.actor_id=p_actor;
 RETURN coalesce(generation,0);
END $$;


--
-- Name: child_id(text, text, integer); Type: FUNCTION; Schema: naruv_bundle; Owner: -
--

CREATE FUNCTION naruv_bundle.child_id(p_type text, p_key text, p_line integer) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT
    SET search_path TO 'pg_catalog'
    AS $_$
 SELECT 'bundle:'||encode(sha256(convert_to(jsonb_build_array($1,$2,$3)::text,'UTF8')),'hex')
$_$;


--
-- Name: command(text, text, text, jsonb, boolean, text); Type: FUNCTION; Schema: naruv_bundle; Owner: -
--

CREATE FUNCTION naruv_bundle.command(p_bundle text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a record; a2 record; h naruv_bundle.headers; e naruv_bundle.events; prior naruv_bundle.events;
 x jsonb; rows jsonb; r jsonb; out_rows jsonb:='[]'::jsonb; idx int; ln int; cid text; rid text; bid text;
 kind text; cp text; mode text; target text; expected_action text; current_bill text; n int;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_bundle IS NULL OR p_bundle !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_action IS NULL OR p_action NOT IN ('open','fulfill','cancel','bill','pay','reverse')
 OR p_confirm IS DISTINCT FROM true OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
 OR octet_length(p_payload::text)>16384 THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO e FROM naruv_bundle.events z WHERE z.org_id=a.org_id AND z.request_id=p_request;
 IF FOUND THEN
  IF (e.bundle_id,e.actor_id,e.action,e.payload) IS DISTINCT FROM (p_bundle,a.actor_id,p_action,p_payload)
  THEN RAISE EXCEPTION 'BUNDLE_CONFLICT'; END IF;
  RETURN e.receipt;
 END IF;
 IF p_action='open' THEN
  IF p_payload-'lines'<>'{}'::jsonb OR jsonb_typeof(p_payload->'lines') IS DISTINCT FROM 'array'
  THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
  rows:=p_payload->'lines'; n:=jsonb_array_length(rows);
  IF n NOT BETWEEN 2 AND 20 THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
  IF EXISTS(SELECT 1 FROM naruv_bundle.headers z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle)
  THEN RAISE EXCEPTION 'BUNDLE_CONFLICT'; END IF;
  FOR x,idx IN SELECT value,ordinality::int FROM jsonb_array_elements(rows) WITH ORDINALITY LOOP
   cid:=naruv_bundle.child_id('document',p_bundle,idx); rid:=naruv_bundle.child_id('command',p_request,idx);
   r:=naruv_trade.command_bundle_internal(cid,rid,'open',x,true,p_csrf);
   IF idx=1 THEN
    kind:=r->>'kind';cp:=r->>'counterparty_id';mode:=r->>'vat_mode';
    INSERT INTO naruv_bundle.headers VALUES(a.org_id,p_bundle,a.actor_id,kind,cp,mode,clock_timestamp());
   ELSIF (kind,cp,mode) IS DISTINCT FROM (r->>'kind',r->>'counterparty_id',r->>'vat_mode') THEN
    RAISE EXCEPTION 'BUNDLE_MIXED_SCOPE';
   END IF;
   INSERT INTO naruv_bundle.lines VALUES(a.org_id,p_bundle,idx,cid);
   out_rows:=out_rows||jsonb_build_array(jsonb_build_object('line_no',idx,'result',r));
  END LOOP;
 ELSE
  SELECT * INTO h FROM naruv_bundle.headers z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle;
  IF NOT FOUND THEN RAISE EXCEPTION 'BUNDLE_NOT_FOUND'; END IF;
  IF p_action='cancel' THEN
   IF p_payload<>'{}'::jsonb THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
   FOR ln,cid IN SELECT z.line_no,z.doc_id FROM naruv_bundle.lines z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle ORDER BY z.line_no LOOP
    r:=naruv_trade.inspect(cid,p_csrf);
    IF r->>'state' IN ('OPEN','PARTIAL') THEN
     r:=naruv_trade.command_bundle_internal(cid,naruv_bundle.child_id('command',p_request,ln),'cancel','{}'::jsonb,true,p_csrf);
     out_rows:=out_rows||jsonb_build_array(jsonb_build_object('line_no',ln,'result',r));
    END IF;
   END LOOP;
   IF jsonb_array_length(out_rows)=0 THEN RAISE EXCEPTION 'BUNDLE_TERMINAL'; END IF;
  ELSIF p_action IN ('bill','reverse') THEN
   IF p_payload-'source_request_id'<>'{}'::jsonb OR jsonb_typeof(p_payload->'source_request_id') IS DISTINCT FROM 'string'
   THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
   target:=p_payload->>'source_request_id';
   expected_action:=CASE WHEN p_action='bill' THEN 'fulfill' ELSE 'pay' END;
   SELECT * INTO prior FROM naruv_bundle.events z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle AND z.request_id=target AND z.action=expected_action;
   IF NOT FOUND THEN RAISE EXCEPTION 'BUNDLE_NOT_FOUND'; END IF;
   FOR x IN SELECT value FROM jsonb_array_elements(prior.receipt->'lines') LOOP
    ln:=(x->>'line_no')::int;rid:=naruv_bundle.child_id('command',p_request,ln);
    IF p_action='bill' THEN
     SELECT z.doc_id INTO STRICT cid FROM naruv_bundle.lines z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle AND z.line_no=ln;
     bid:=naruv_bundle.child_id('bill',p_request,ln);
     r:=naruv_finance.command_bundle_internal(bid,rid,'bill',jsonb_build_object('doc_id',cid,'fulfillment_id',naruv_bundle.child_id('command',target,ln)),true,p_csrf);
    ELSE
     bid:=x->'result'->>'bill_id';
     r:=naruv_finance.command_bundle_internal(bid,rid,'reverse',jsonb_build_object('payment_request_id',naruv_bundle.child_id('command',target,ln)),true,p_csrf);
    END IF;
    out_rows:=out_rows||jsonb_build_array(jsonb_build_object('line_no',ln,'result',r));
   END LOOP;
  ELSE
   IF jsonb_typeof(p_payload->'lines') IS DISTINCT FROM 'array'
   OR (p_action='fulfill' AND p_payload-'lines'<>'{}'::jsonb)
   OR (p_action='pay' AND (p_payload-'lines'-'bill_request_id'<>'{}'::jsonb OR jsonb_typeof(p_payload->'bill_request_id') IS DISTINCT FROM 'string'))
   THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
   rows:=p_payload->'lines';n:=jsonb_array_length(rows);
   IF n NOT BETWEEN 1 AND 20 THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
   IF EXISTS(SELECT 1 FROM jsonb_array_elements(rows) z WHERE jsonb_typeof(z) IS DISTINCT FROM 'object'
    OR jsonb_typeof(z->'line_no') IS DISTINCT FROM 'number' OR (z->>'line_no') !~ '^([1-9]|1[0-9]|20)$')
   THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
   IF (SELECT count(DISTINCT z->>'line_no') FROM jsonb_array_elements(rows) z)<>n THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
   IF p_action='pay' THEN
    target:=p_payload->>'bill_request_id';
    SELECT * INTO prior FROM naruv_bundle.events z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle AND z.request_id=target AND z.action='bill';
    IF NOT FOUND THEN RAISE EXCEPTION 'BUNDLE_NOT_FOUND'; END IF;
   END IF;
   FOR x IN SELECT value FROM jsonb_array_elements(rows) ORDER BY (value->>'line_no')::int LOOP
    ln:=(x->>'line_no')::int;rid:=naruv_bundle.child_id('command',p_request,ln);
    SELECT z.doc_id INTO cid FROM naruv_bundle.lines z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle AND z.line_no=ln;
    IF NOT FOUND THEN RAISE EXCEPTION 'BUNDLE_NOT_FOUND'; END IF;
    IF p_action='fulfill' THEN
     r:=naruv_trade.command_bundle_internal(cid,rid,'fulfill',x-'line_no',true,p_csrf);
    ELSE
     SELECT z->'result'->>'bill_id' INTO current_bill FROM jsonb_array_elements(prior.receipt->'lines') z WHERE (z->>'line_no')::int=ln;
     IF NOT FOUND THEN RAISE EXCEPTION 'BUNDLE_NOT_FOUND'; END IF;
     r:=naruv_finance.command_bundle_internal(current_bill,rid,'pay',x-'line_no',true,p_csrf);
    END IF;
    out_rows:=out_rows||jsonb_build_array(jsonb_build_object('line_no',ln,'result',r));
   END LOOP;
  END IF;
 END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 r:=jsonb_build_object('bundle_id',p_bundle,'request_id',p_request,'action',p_action,'lines',out_rows,'production_authorized',false);
 INSERT INTO naruv_bundle.events VALUES(a.org_id,p_request,p_bundle,a.actor_id,p_action,p_payload,r,clock_timestamp());
 RETURN r;
END $_$;


--
-- Name: inspect(text, text); Type: FUNCTION; Schema: naruv_bundle; Owner: -
--

CREATE FUNCTION naruv_bundle.inspect(p_bundle text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; h naruv_bundle.headers; rows jsonb;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO h FROM naruv_bundle.headers z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle;
 IF NOT FOUND THEN RAISE EXCEPTION 'BUNDLE_NOT_FOUND'; END IF;
 SELECT jsonb_agg(jsonb_build_object('line_no',z.line_no,'result',naruv_trade.inspect(z.doc_id,p_csrf)) ORDER BY z.line_no)
 INTO rows FROM naruv_bundle.lines z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle;
 RETURN jsonb_build_object('bundle_id',p_bundle,'kind',h.kind,'counterparty_id',h.counterparty_id,'lines',rows,'production_authorized',false);
END $$;


--
-- Name: apply_customer(); Type: FUNCTION; Schema: naruv_customer_bridge; Owner: -
--

CREATE FUNCTION naruv_customer_bridge.apply_customer() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; s naruv_native_review.stages; cid text; stamp text;
BEGIN
 IF current_user IS DISTINCT FROM 'naruv_native_owner' OR NEW.entity IS DISTINCT FROM 'customer'
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT i.actor_id,i.org_id,i.actor_role INTO a FROM jw_dev.stage_identity_v84() i;
 IF NOT FOUND OR a.org_id IS DISTINCT FROM NEW.org_id OR a.actor_role IS DISTINCT FROM 'admin'
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO s FROM naruv_native_review.stages t
 WHERE t.org_id=NEW.org_id AND t.stage_id=NEW.stage_id;
 IF NOT FOUND OR (s.actor_id,s.source_id,s.entity) IS DISTINCT FROM (a.actor_id,NEW.source_id,NEW.entity)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 -- PostgreSQL derives a stable 32-hex ID from a delimiter-safe tuple; never
 -- reuse an unrelated existing customer even if a truncated digest collides.
 cid:=left(encode(sha256(convert_to(jsonb_build_array(NEW.org_id,NEW.source_id,NEW.normalized_id)::text,'UTF8')),'hex'),32);
 stamp:=to_char(clock_timestamp() AT TIME ZONE 'Asia/Seoul','YYYY-MM-DD"T"HH24:MI:SS')||'+09:00';
 INSERT INTO jw_dev.customers(id,org_id,name,business_number,contact_name,email,phone,created_at)
 VALUES(cid,NEW.org_id,NEW.data->>'name',coalesce(NEW.data->>'business_number',''),'','','',stamp);
 INSERT INTO naruv_customer_bridge.crosswalk(org_id,source_id,entity,normalized_id,source_customer_id,customer_id,stage_id)
 VALUES(NEW.org_id,NEW.source_id,NEW.entity,NEW.normalized_id,NEW.source_record_id,cid,NEW.stage_id);
 INSERT INTO jw_dev.audit_logs(id,org_id,actor_id,entity_type,entity_id,action,detail,created_at)
 VALUES(replace(gen_random_uuid()::text,'-',''),NEW.org_id,a.actor_id,'customer',cid,'create',
 jsonb_build_object('source','naruv_customer_bridge_ci','stage_id',NEW.stage_id,
 'source_id',NEW.source_id,'source_customer_id',NEW.source_record_id)::text,stamp);
 RETURN NEW;
END $$;


--
-- Name: admit_attendance(text, text, text, text, integer, integer, boolean, text); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.admit_attendance(p_worker text, p_period text, p_request text, p_day text, p_regular integer, p_additional integer, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
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
END $_$;


--
-- Name: admit_document(text, text, text, bytea, jsonb, boolean, text); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.admit_document(p_doc text, p_request text, p_format text, p_raw bytea, p_observations jsonb, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
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
 PERFORM naruv_draft.validate_observations(p_observations);
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
  OR EXISTS(SELECT 1 FROM naruv_draft.document_revisions x WHERE x.org_id=a.org_id AND x.request_id=p_request)
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
END $_$;


--
-- Name: amend_period(text, text, text, text, text, jsonb, boolean, text); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.amend_period(p_worker text, p_period text, p_request text, p_expected text, p_kind text, p_data jsonb, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
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
END $_$;


--
-- Name: archive_worker(text, text, boolean, text); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.archive_worker(p_worker text, p_request text, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
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
END $_$;


--
-- Name: document_source(text, text); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.document_source(p_id text, p_csrf text) RETURNS TABLE(revision text, original_bytes bytea, original_sha256 text, observations jsonb)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a record; a2 record; d naruv_draft.documents; r naruv_draft.document_revisions;
 current_revision text; current_observations jsonb; current_sha text; n int:=0;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_id IS NULL OR p_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' THEN RAISE EXCEPTION 'DRAFT_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-document-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO d FROM naruv_draft.documents x WHERE (x.org_id,x.document_id)=(a.org_id,p_id) AND x.active FOR SHARE;
 IF NOT FOUND THEN RETURN; END IF;
 PERFORM 1 FROM naruv_draft.document_admissions x
 WHERE (x.org_id,x.document_id)=(a.org_id,p_id) AND x.request_id=d.revision
 AND x.source_sha256=d.original_sha256 AND x.source_sha256=encode(sha256(d.original_bytes),'hex')
 AND x.observation_sha256=encode(sha256(convert_to(d.observations::text,'UTF8')),'hex');
 IF NOT FOUND THEN RAISE EXCEPTION 'DOC_CONFLICT'; END IF;
 current_revision:=d.revision;current_observations:=d.observations;
 current_sha:=encode(sha256(convert_to(current_observations::text,'UTF8')),'hex');
 FOR r IN SELECT * FROM naruv_draft.document_revisions x WHERE (x.org_id,x.document_id)=(a.org_id,p_id) ORDER BY x.version LOOP
  n:=n+1;
  IF r.version<>n OR r.previous_revision<>current_revision OR r.previous_sha256<>current_sha
  OR r.source_sha256<>d.original_sha256 OR r.observation_sha256<>encode(sha256(convert_to(r.observations::text,'UTF8')),'hex')
  THEN RAISE EXCEPTION 'DOC_CONFLICT'; END IF;
  current_revision:=r.request_id;current_sha:=r.observation_sha256;current_observations:=r.observations;
 END LOOP;
 RETURN QUERY SELECT current_revision,d.original_bytes,d.original_sha256,current_observations;
END $_$;


--
-- Name: inspect_worker(text, text); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.inspect_worker(p_worker text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
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
END $_$;


--
-- Name: list_workers(text, integer, text); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.list_workers(p_after text, p_limit integer, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
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
END $_$;


--
-- Name: pay_source(text, text, text); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.pay_source(p_worker text, p_period text, p_csrf text) RETURNS TABLE(revision text, hourly_krw bigint, additional_bps integer, days jsonb)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
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
END $_$;


--
-- Name: period_digest(text, text, text, text, bigint, integer, jsonb); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.period_digest(p_org text, p_worker text, p_period text, p_revision text, p_rate bigint, p_bps integer, p_rows jsonb) RETURNS text
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT encode(sha256(convert_to(jsonb_build_array('naruv-period-review-v1',p_org,p_worker,p_period,p_revision,p_rate,p_bps,p_rows)::text,'UTF8')),'hex')
$$;


--
-- Name: profile_envelope(text, text, jsonb, text, text); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.profile_envelope(p_worker text, p_revision text, p_envelope jsonb, p_expected text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
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
 IF EXISTS(SELECT 1 FROM naruv_draft.profile_retention r WHERE (r.org_id,r.worker_id)=(a.org_id,p_worker) AND r.purged_at IS NOT NULL)
 THEN RAISE EXCEPTION 'PROFILE_PURGED'; END IF;
 IF EXISTS(SELECT 1 FROM naruv_draft.profile_retention r WHERE (r.org_id,r.worker_id)=(a.org_id,p_worker))
 THEN RAISE EXCEPTION 'PROFILE_RETAINED'; END IF;
 IF p_envelope IS NOT NULL THEN
  IF p_revision !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
   OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object'
   OR p_envelope-ARRAY['v','key_id','nonce','ciphertext']<>'{}'::jsonb
   OR NOT (p_envelope ?& ARRAY['v','key_id','nonce','ciphertext'])
   OR p_envelope->'v' IS DISTINCT FROM '1'::jsonb
   OR jsonb_typeof(p_envelope->'key_id') IS DISTINCT FROM 'string'
   OR jsonb_typeof(p_envelope->'nonce') IS DISTINCT FROM 'string'
   OR jsonb_typeof(p_envelope->'ciphertext') IS DISTINCT FROM 'string'
   OR p_envelope->>'key_id' NOT IN ('ci-profile-key','ci-profile-key-2')
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
END $_$;


--
-- Name: purge_profile(text, text, text, text); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.purge_profile(p_worker text, p_expected text, p_approval text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a record; fresh record; r naruv_draft.profile_retention; rev text;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF a.org_id NOT IN ('ci-a','ci-b') OR p_worker IS DISTINCT FROM 'worker-1'
 OR p_expected IS NULL OR p_expected !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_approval IS NULL OR p_approval !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'PROFILE_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-profile-ci:'||a.org_id,0));
 SELECT * INTO r FROM naruv_draft.profile_retention x WHERE (x.org_id,x.worker_id)=(a.org_id,p_worker) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PROFILE_PURGE_BLOCKED'; END IF;
 IF r.purged_at IS NOT NULL OR r.legal_hold OR r.eligible_at>clock_timestamp()
 OR r.approval_sha256 IS DISTINCT FROM p_approval THEN RAISE EXCEPTION 'PROFILE_PURGE_BLOCKED'; END IF;
 SELECT x.revision INTO rev FROM naruv_draft.profile_envelopes x
 WHERE (x.org_id,x.worker_id)=(a.org_id,p_worker) FOR UPDATE;
 IF rev IS DISTINCT FROM p_expected THEN RAISE EXCEPTION 'PROFILE_STALE'; END IF;
 SELECT * INTO fresh FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (fresh.actor_id,fresh.org_id,fresh.auth_epoch,fresh.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 DELETE FROM naruv_draft.profile_envelopes x WHERE (x.org_id,x.worker_id,x.revision)=(a.org_id,p_worker,p_expected);
 IF NOT FOUND THEN RAISE EXCEPTION 'PROFILE_STALE'; END IF;
 UPDATE naruv_draft.profile_retention x SET purged_at=clock_timestamp() WHERE (x.org_id,x.worker_id)=(a.org_id,p_worker);
 RETURN jsonb_build_object('status','PURGED');
END $_$;


--
-- Name: record_statement_review(text, text, text, text, text, text, boolean, text); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.record_statement_review(p_worker text, p_period text, p_request text, p_review text, p_statement text, p_render text, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a record; a2 record; r naruv_draft.statement_review_receipts;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_worker IS NULL OR p_worker !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_period IS NULL OR p_period !~ '^2026-(0[1-9]|1[0-2])$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_review IS NULL OR p_review !~ '^[0-9a-f]{64}$'
 OR p_statement IS NULL OR p_statement !~ '^[0-9a-f]{64}$'
 OR p_render IS NULL OR p_render !~ '^[0-9a-f]{64}$'
 OR p_confirm IS DISTINCT FROM true THEN RAISE EXCEPTION 'KR_AUDIT_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-attendance-v1:'||a.org_id,0));
 PERFORM 1 FROM naruv_draft.pay_source(p_worker,p_period,p_csrf);
 IF NOT FOUND THEN RAISE EXCEPTION 'KR_AUDIT_NOT_FOUND'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO r FROM naruv_draft.statement_review_receipts x WHERE x.org_id=a.org_id AND x.request_id=p_request;
 IF FOUND THEN
  IF (r.actor_id,r.worker_id,r.period,r.review_sha256,r.statement_sha256,r.render_sha256)
  IS DISTINCT FROM (a.actor_id,p_worker,p_period,p_review,p_statement,p_render)
  THEN RAISE EXCEPTION 'KR_AUDIT_CONFLICT'; END IF;
 ELSE
  IF (SELECT count(*) FROM naruv_draft.statement_review_receipts x WHERE x.org_id=a.org_id)>=1000
  OR (SELECT count(*) FROM naruv_draft.statement_review_receipts x WHERE (x.org_id,x.worker_id,x.period)=(a.org_id,p_worker,p_period))>=32
  THEN RAISE EXCEPTION 'KR_AUDIT_CAPACITY'; END IF;
  INSERT INTO naruv_draft.statement_review_receipts(org_id,request_id,actor_id,worker_id,period,review_sha256,statement_sha256,render_sha256)
  VALUES(a.org_id,p_request,a.actor_id,p_worker,p_period,p_review,p_statement,p_render) RETURNING * INTO r;
 END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN jsonb_build_object('status','ISOLATED_STATEMENT_REVIEW_METADATA_RECORDED','request_id',r.request_id,
 'review_sha256',r.review_sha256,'statement_sha256',r.statement_sha256,'render_sha256',r.render_sha256,
 'audit_metadata_persisted',true,'delivery_authorized',false,'payment_authorized',false,
 'production_authorized',false,'statutory_validated',false);
END $_$;


--
-- Name: review_period(text, text, text, text, boolean, text); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.review_period(p_worker text, p_period text, p_request text, p_expected text, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
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
END $_$;


--
-- Name: revise_document(text, text, text, text, jsonb, boolean, text); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.revise_document(p_doc text, p_request text, p_previous text, p_source_sha text, p_observations jsonb, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a record; a2 record; s record; r naruv_draft.document_revisions; n int; obs_sha text;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_doc IS NULL OR p_doc !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_previous IS NULL OR p_previous !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_source_sha IS NULL OR p_source_sha !~ '^[0-9a-f]{64}$' OR p_confirm IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'DOC_INPUT'; END IF;
 PERFORM naruv_draft.validate_observations(p_observations);
 obs_sha:=encode(sha256(convert_to(p_observations::text,'UTF8')),'hex');
 -- document_source verifies the original and the entire bounded revision chain under the same tenant lock.
 SELECT * INTO s FROM naruv_draft.document_source(p_doc,p_csrf);
 IF NOT FOUND THEN RAISE EXCEPTION 'DOC_NOT_FOUND'; END IF;
 IF s.original_sha256<>p_source_sha THEN RAISE EXCEPTION 'DOC_CONFLICT'; END IF;
 SELECT * INTO r FROM naruv_draft.document_revisions x WHERE x.org_id=a.org_id AND x.request_id=p_request;
 IF FOUND THEN
  IF (r.actor_id,r.document_id,r.previous_revision,r.source_sha256,r.observation_sha256,r.observations)
  IS DISTINCT FROM (a.actor_id,p_doc,p_previous,p_source_sha,obs_sha,p_observations) THEN RAISE EXCEPTION 'DOC_CONFLICT'; END IF;
 ELSE
  IF s.revision<>p_previous OR s.observations=p_observations OR EXISTS(SELECT 1 FROM naruv_draft.document_admissions x WHERE x.org_id=a.org_id AND x.request_id=p_request)
  THEN RAISE EXCEPTION 'DOC_CONFLICT'; END IF;
  SELECT count(*)::int INTO n FROM naruv_draft.document_revisions x WHERE (x.org_id,x.document_id)=(a.org_id,p_doc);
  IF n>=32 THEN RAISE EXCEPTION 'DOC_CAPACITY'; END IF;
  INSERT INTO naruv_draft.document_revisions(org_id,document_id,version,request_id,previous_revision,actor_id,source_sha256,previous_sha256,observation_sha256,observations)
  VALUES(a.org_id,p_doc,n+1,p_request,p_previous,a.actor_id,p_source_sha,encode(sha256(convert_to(s.observations::text,'UTF8')),'hex'),obs_sha,p_observations)
  RETURNING * INTO r;
 END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN jsonb_build_object('status','OBSERVATIONS_REVISED','document_id',p_doc,'revision',r.request_id,'version',r.version,
 'source_sha256',p_source_sha,'posting_authorized',false,'production_authorized',false,'requires_human_review',true,'content_verified',false);
END $_$;


--
-- Name: setup_worker(text, text, text, text, bigint, integer, boolean, text); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.setup_worker(p_worker text, p_period text, p_request text, p_revision text, p_rate bigint, p_bps integer, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
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
END $_$;


--
-- Name: validate_observations(jsonb); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.validate_observations(p_observations jsonb) RETURNS void
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE v jsonb; field text; dt date;
BEGIN
 IF jsonb_typeof(p_observations) IS DISTINCT FROM 'array' OR octet_length(p_observations::text)>32768 THEN RAISE EXCEPTION 'DOC_INPUT'; END IF;
 IF jsonb_array_length(p_observations) NOT BETWEEN 1 AND 128 THEN RAISE EXCEPTION 'DOC_INPUT'; END IF;
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
   IF field='document_date' THEN
    BEGIN dt:=(v->>'value')::date; EXCEPTION WHEN datetime_field_overflow OR invalid_datetime_format THEN RAISE EXCEPTION 'DOC_INPUT'; END;
    IF to_char(dt,'YYYY-MM-DD')<>v->>'value' THEN RAISE EXCEPTION 'DOC_INPUT'; END IF;
   END IF;
  ELSE RAISE EXCEPTION 'DOC_INPUT'; END IF;
 END LOOP;

END $_$;


--
-- Name: verify_statement_review(text, text, text, text, text, text, text); Type: FUNCTION; Schema: naruv_draft; Owner: -
--

CREATE FUNCTION naruv_draft.verify_statement_review(p_worker text, p_period text, p_request text, p_review text, p_statement text, p_render text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a record; a2 record; r naruv_draft.statement_review_receipts;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_worker IS NULL OR p_worker !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_period IS NULL OR p_period !~ '^2026-(0[1-9]|1[0-2])$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_review IS NULL OR p_review !~ '^[0-9a-f]{64}$'
 OR p_statement IS NULL OR p_statement !~ '^[0-9a-f]{64}$'
 OR p_render IS NULL OR p_render !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'KR_AUDIT_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-attendance-v1:'||a.org_id,0));
 PERFORM 1 FROM naruv_draft.pay_source(p_worker,p_period,p_csrf);
 IF NOT FOUND THEN RAISE EXCEPTION 'KR_AUDIT_NOT_FOUND'; END IF;
 SELECT * INTO r FROM naruv_draft.statement_review_receipts x
 WHERE (x.org_id,x.request_id,x.actor_id,x.worker_id,x.period)=(a.org_id,p_request,a.actor_id,p_worker,p_period);
 IF NOT FOUND THEN RAISE EXCEPTION 'KR_AUDIT_NOT_FOUND'; END IF;
 IF (r.review_sha256,r.statement_sha256,r.render_sha256) IS DISTINCT FROM (p_review,p_statement,p_render)
 THEN RAISE EXCEPTION 'KR_AUDIT_CONFLICT'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN jsonb_build_object('status','ISOLATED_STATEMENT_REVIEW_METADATA_VERIFIED','request_id',r.request_id,
 'review_sha256',r.review_sha256,'statement_sha256',r.statement_sha256,'render_sha256',r.render_sha256,
 'audit_metadata_persisted',true,'delivery_authorized',false,'payment_authorized',false,
 'production_authorized',false,'statutory_validated',false);
END $_$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: bills; Type: TABLE; Schema: naruv_finance; Owner: -
--

CREATE TABLE naruv_finance.bills (
    org_id text NOT NULL,
    bill_id text NOT NULL,
    doc_id text NOT NULL,
    fulfillment_id text NOT NULL,
    kind text NOT NULL,
    actor_id text NOT NULL,
    quantity bigint NOT NULL,
    subtotal bigint NOT NULL,
    vat bigint NOT NULL,
    total bigint GENERATED ALWAYS AS ((subtotal + vat)) STORED,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT bills_check CHECK (((vat >= 0) AND (vat <= subtotal))),
    CONSTRAINT bills_kind_check CHECK ((kind = ANY (ARRAY['sale'::text, 'purchase'::text]))),
    CONSTRAINT bills_quantity_check CHECK (((quantity >= 1) AND (quantity <= 100000))),
    CONSTRAINT bills_subtotal_check CHECK (((subtotal >= 0) AND (subtotal <= '100000000000000'::bigint)))
);

ALTER TABLE ONLY naruv_finance.bills FORCE ROW LEVEL SECURITY;


--
-- Name: adjusted_snapshot(naruv_finance.bills, bigint); Type: FUNCTION; Schema: naruv_finance; Owner: -
--

CREATE FUNCTION naruv_finance.adjusted_snapshot(b naruv_finance.bills, p_paid bigint) RETURNS jsonb
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE c bigint; q bigint; due bigint; result jsonb;
BEGIN
 c:=naruv_finance.credit_sum(b.org_id,b.bill_id);q:=naruv_finance.returned_qty(b.org_id,b.bill_id);
 due:=b.total-p_paid-c;
 IF q<0 OR q>b.quantity OR c<0 OR c>b.total OR p_paid<0 OR due<0 OR (q=b.quantity AND c<>b.total)
 THEN RAISE EXCEPTION 'FIN_INTEGRITY'; END IF;
 result:=naruv_finance.snapshot(b,p_paid);
 IF q=0 THEN RETURN result; END IF;
 RETURN result||jsonb_build_object('credited',c,'returned_quantity',q,'outstanding',due,
 'state',CASE WHEN q=b.quantity THEN 'CREDITED' WHEN due=0 THEN 'SETTLED' WHEN p_paid=0 THEN 'OPEN' ELSE 'PARTIAL' END);
END $$;


--
-- Name: allocation(numeric, bigint, bigint, bigint); Type: FUNCTION; Schema: naruv_finance; Owner: -
--

CREATE FUNCTION naruv_finance.allocation(p_amount numeric, p_total bigint, p_previous bigint, p_qty bigint) RETURNS numeric
    LANGUAGE sql IMMUTABLE STRICT
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT div(2*p_amount*(p_previous+p_qty)+p_total,2*p_total)-div(2*p_amount*p_previous+p_total,2*p_total)
$$;


--
-- Name: command(text, text, text, jsonb, boolean, text); Type: FUNCTION; Schema: naruv_finance; Owner: -
--

CREATE FUNCTION naruv_finance.command(p_bill text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
BEGIN
 IF left(p_bill,7)='bundle:' OR left(p_request,7)='bundle:'
 OR left(p_payload->>'doc_id',7)='bundle:' OR left(p_payload->>'fulfillment_id',7)='bundle:'
 OR left(p_payload->>'payment_request_id',7)='bundle:' THEN RAISE EXCEPTION 'FIN_INPUT'; END IF;
 RETURN naruv_finance.command_bundle_internal(p_bill,p_request,p_action,p_payload,p_confirm,p_csrf);
END $$;


--
-- Name: command_bundle_internal(text, text, text, jsonb, boolean, text); Type: FUNCTION; Schema: naruv_finance; Owner: -
--

CREATE FUNCTION naruv_finance.command_bundle_internal(p_bill text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a record; a2 record; b naruv_finance.bills; e naruv_finance.events; original naruv_finance.events;
 d naruv_trade.documents; f naruv_trade.events; doc text; fid text; prev bigint; n bigint; done_qty bigint;
 sub bigint; tax bigint; paid_amt bigint; amt bigint:=0; pref text; rev text; result jsonb;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_bill IS NULL OR p_bill !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_action IS NULL OR p_action NOT IN ('bill','pay','reverse')
 OR p_confirm IS DISTINCT FROM true OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
 OR octet_length(p_payload::text)>4096 THEN RAISE EXCEPTION 'FIN_INPUT'; END IF;
 -- Same lock as fulfillment/cancellation; no settlement from uncommitted stock.
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO e FROM naruv_finance.events x WHERE x.org_id=a.org_id AND x.request_id=p_request;
 IF FOUND THEN
  IF (e.bill_id,e.actor_id,e.action,e.payload) IS DISTINCT FROM (p_bill,a.actor_id,p_action,p_payload)
  THEN RAISE EXCEPTION 'FIN_CONFLICT'; END IF;
  RETURN e.receipt;
 END IF;
 IF p_action='bill' THEN
  IF p_payload-'doc_id'-'fulfillment_id'<>'{}'::jsonb
  OR jsonb_typeof(p_payload->'doc_id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(p_payload->'fulfillment_id') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'FIN_INPUT'; END IF;
  doc:=p_payload->>'doc_id'; fid:=p_payload->>'fulfillment_id';
  SELECT * INTO d FROM naruv_trade.documents x WHERE x.org_id=a.org_id AND x.doc_id=doc FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'FIN_NOT_FOUND'; END IF;
  SELECT * INTO f FROM naruv_trade.events x WHERE x.org_id=a.org_id AND x.doc_id=doc AND x.request_id=fid AND x.action='fulfill';
  IF NOT FOUND THEN RAISE EXCEPTION 'FIN_NOT_FOUND'; END IF;
  -- Bind the actual inventory movement, not any client-supplied amount.
  SELECT m.quantity INTO n FROM naruv_inventory.movements m WHERE m.org_id=a.org_id AND m.request_id=f.movement_id
   AND m.source_id=d.source_id AND m.normalized_id=d.item_id
   AND m.from_warehouse IS NOT DISTINCT FROM (CASE WHEN d.kind='sale' THEN d.warehouse_id ELSE NULL END)
   AND m.to_warehouse IS NOT DISTINCT FROM (CASE WHEN d.kind='purchase' THEN d.warehouse_id ELSE NULL END);
  IF NOT FOUND OR n IS DISTINCT FROM (f.payload->>'quantity')::bigint THEN RAISE EXCEPTION 'FIN_INTEGRITY'; END IF;
  done_qty:=(f.receipt->>'fulfilled')::bigint;
  SELECT coalesce(sum(x.quantity),0)::bigint INTO prev FROM naruv_finance.bills x WHERE x.org_id=a.org_id AND x.doc_id=doc;
  IF done_qty IS NULL OR done_qty> d.fulfilled OR done_qty-n<>prev OR n<1 THEN RAISE EXCEPTION 'FIN_SEQUENCE'; END IF;
  sub:=n*d.unit_price;
  -- Cumulative half-up VAT delta, no penny drift across partial billings.
  tax:=CASE WHEN d.vat_mode='taxable' THEN (done_qty*d.unit_price+5)/10-(prev*d.unit_price+5)/10 ELSE 0 END;
  INSERT INTO naruv_finance.bills(org_id,bill_id,doc_id,fulfillment_id,kind,actor_id,quantity,subtotal,vat,created_at)
   VALUES(a.org_id,p_bill,doc,fid,d.kind,a.actor_id,n,sub,tax,clock_timestamp()) RETURNING * INTO b;
  paid_amt:=0;
 ELSE
  SELECT * INTO b FROM naruv_finance.bills x WHERE x.org_id=a.org_id AND x.bill_id=p_bill FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'FIN_NOT_FOUND'; END IF;
  paid_amt:=naruv_finance.paid(a.org_id,p_bill);
  IF paid_amt<0 OR paid_amt>b.total-naruv_finance.credit_sum(a.org_id,p_bill) THEN RAISE EXCEPTION 'FIN_INTEGRITY'; END IF;
  IF naruv_finance.returned_qty(a.org_id,p_bill)=b.quantity THEN RAISE EXCEPTION 'FIN_CONFLICT'; END IF;
  IF p_action='pay' THEN
   IF p_payload-'amount'-'reference'<>'{}'::jsonb
   OR jsonb_typeof(p_payload->'amount') IS DISTINCT FROM 'number' OR (p_payload->>'amount') !~ '^[0-9]{1,15}$'
   OR jsonb_typeof(p_payload->'reference') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'FIN_INPUT'; END IF;
   amt:=(p_payload->>'amount')::bigint; pref:=p_payload->>'reference';
   IF pref !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR amt<1 THEN RAISE EXCEPTION 'FIN_INPUT'; END IF;
   IF amt>b.total-paid_amt-naruv_finance.credit_sum(a.org_id,p_bill) THEN RAISE EXCEPTION 'FIN_OVERPAY'; END IF;
   paid_amt:=paid_amt+amt;
  ELSE
   IF p_payload-'payment_request_id'<>'{}'::jsonb OR jsonb_typeof(p_payload->'payment_request_id') IS DISTINCT FROM 'string'
   THEN RAISE EXCEPTION 'FIN_INPUT'; END IF;
   rev:=p_payload->>'payment_request_id';
   -- A refund is allocated against aggregate paid cash; prohibit ambiguous original payment reversal.
   IF EXISTS(SELECT 1 FROM naruv_finance.events x WHERE x.org_id=a.org_id AND x.bill_id=p_bill AND x.action='refund')
   THEN RAISE EXCEPTION 'FIN_CONFLICT'; END IF;
   SELECT * INTO original FROM naruv_finance.events x WHERE x.org_id=a.org_id AND x.bill_id=p_bill AND x.request_id=rev AND x.action='pay';
   IF NOT FOUND THEN RAISE EXCEPTION 'FIN_NOT_FOUND'; END IF;
   IF EXISTS(SELECT 1 FROM naruv_finance.events x WHERE x.org_id=a.org_id AND x.reversal_of=rev) THEN RAISE EXCEPTION 'FIN_CONFLICT'; END IF;
   amt:=original.amount;
   IF amt>paid_amt THEN RAISE EXCEPTION 'FIN_INTEGRITY'; END IF;
   paid_amt:=paid_amt-amt;
  END IF;
 END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 result:=naruv_finance.adjusted_snapshot(b,paid_amt)||jsonb_build_object('request_id',p_request,'action',p_action,'amount',amt);
 INSERT INTO naruv_finance.events VALUES(a.org_id,p_request,p_bill,a.actor_id,p_action,p_payload,amt,pref,rev,result,clock_timestamp());
 RETURN result;
END $_$;


--
-- Name: credit_sum(text, text); Type: FUNCTION; Schema: naruv_finance; Owner: -
--

CREATE FUNCTION naruv_finance.credit_sum(p_org text, p_bill text) RETURNS bigint
    LANGUAGE sql
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT coalesce(sum(amount),0)::bigint FROM naruv_finance.events WHERE org_id=p_org AND bill_id=p_bill AND action='credit'
$$;


--
-- Name: credited(text, text); Type: FUNCTION; Schema: naruv_finance; Owner: -
--

CREATE FUNCTION naruv_finance.credited(p_org text, p_bill text) RETURNS boolean
    LANGUAGE sql
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT EXISTS(SELECT 1 FROM naruv_finance.events WHERE org_id=p_org AND bill_id=p_bill AND action='credit')
$$;


--
-- Name: inspect(text, text); Type: FUNCTION; Schema: naruv_finance; Owner: -
--

CREATE FUNCTION naruv_finance.inspect(p_bill text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; b naruv_finance.bills; paid_amt bigint;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO b FROM naruv_finance.bills x WHERE x.org_id=a.org_id AND x.bill_id=p_bill;
 IF NOT FOUND THEN RAISE EXCEPTION 'FIN_NOT_FOUND'; END IF;
 paid_amt:=naruv_finance.paid(a.org_id,p_bill);
 RETURN naruv_finance.adjusted_snapshot(b,paid_amt);
END $$;


--
-- Name: paid(text, text); Type: FUNCTION; Schema: naruv_finance; Owner: -
--

CREATE FUNCTION naruv_finance.paid(p_org text, p_bill text) RETURNS bigint
    LANGUAGE sql
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT coalesce(sum(CASE WHEN action='pay' THEN amount WHEN action IN ('reverse','refund') THEN -amount ELSE 0 END),0)::bigint
 FROM naruv_finance.events WHERE org_id=p_org AND bill_id=p_bill
$$;


--
-- Name: returned_qty(text, text); Type: FUNCTION; Schema: naruv_finance; Owner: -
--

CREATE FUNCTION naruv_finance.returned_qty(p_org text, p_bill text) RETURNS bigint
    LANGUAGE sql
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT coalesce(sum((payload->>'quantity')::bigint),0)::bigint FROM naruv_finance.events WHERE org_id=p_org AND bill_id=p_bill AND action='credit'
$$;


--
-- Name: snapshot(naruv_finance.bills, bigint); Type: FUNCTION; Schema: naruv_finance; Owner: -
--

CREATE FUNCTION naruv_finance.snapshot(b naruv_finance.bills, p_paid bigint) RETURNS jsonb
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog'
    AS $_$
 SELECT jsonb_build_object('bill_id',($1).bill_id,'doc_id',($1).doc_id,'fulfillment_id',($1).fulfillment_id,
 'kind',($1).kind,'quantity',($1).quantity,'subtotal',($1).subtotal,'vat',($1).vat,'total',($1).total,
 'paid',$2,'outstanding',($1).total-$2,'state',CASE WHEN ($1).total=$2 THEN 'SETTLED' WHEN $2=0 THEN 'OPEN' ELSE 'PARTIAL' END,
 'production_authorized',false)
$_$;


--
-- Name: change_actor(text, boolean, text); Type: FUNCTION; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE FUNCTION naruv_hosted_identity_review.change_actor(p_actor text, p_active boolean, p_role text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE n int;
BEGIN
 IF p_active IS NULL OR p_role IS NULL OR p_role NOT IN ('admin','member') THEN RAISE EXCEPTION 'IDENTITY_INPUT' USING ERRCODE='23514'; END IF;
 UPDATE naruv_hosted_identity_review.users SET active=p_active,actor_role=p_role,epoch=epoch+1 WHERE id=p_actor;
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n<>1 THEN RAISE EXCEPTION 'IDENTITY_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 UPDATE naruv_hosted_identity_review.sessions SET revoked=true WHERE actor_id=p_actor AND NOT revoked;
 RETURN true;
END $$;


--
-- Name: issue(text, text, text, integer); Type: FUNCTION; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE FUNCTION naruv_hosted_identity_review.issue(p_actor text, p_hash text, p_csrf text, p_ttl integer) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE u naruv_hosted_identity_review.users%ROWTYPE;
BEGIN
 IF p_hash IS NULL OR p_hash !~ '^[0-9a-f]{64}$' OR p_csrf IS NULL OR length(p_csrf) NOT BETWEEN 32 AND 256 OR p_ttl IS NULL OR p_ttl NOT BETWEEN 1 AND 43200 THEN RAISE EXCEPTION 'IDENTITY_INPUT' USING ERRCODE='23514'; END IF;
 SELECT * INTO u FROM naruv_hosted_identity_review.users WHERE id=p_actor FOR UPDATE;
 IF NOT FOUND OR NOT u.active THEN RAISE EXCEPTION 'IDENTITY_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 INSERT INTO naruv_hosted_identity_review.sessions(token_hash,actor_id,epoch,csrf_token,expires_at) VALUES(p_hash,u.id,u.epoch,p_csrf,clock_timestamp()+make_interval(secs=>p_ttl));
 RETURN true;
END $_$;


--
-- Name: lock_admin(text, text); Type: FUNCTION; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE FUNCTION naruv_hosted_identity_review.lock_admin(p_tenant text, p_csrf text) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE h text; actor text; u naruv_hosted_identity_review.users%ROWTYPE; s naruv_hosted_identity_review.sessions%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'AUTH_TX_ISOLATION' USING ERRCODE='25000'; END IF;
 h:=nullif(current_setting('jw.session_hash',true),'');
 IF h IS NULL OR h !~ '^[0-9a-f]{64}$' OR p_tenant IS NULL OR p_csrf IS NULL THEN RAISE EXCEPTION 'AUTH_DENIED' USING ERRCODE='42501'; END IF;
 SELECT actor_id INTO actor FROM naruv_hosted_identity_review.sessions WHERE token_hash=h;
 IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_DENIED' USING ERRCODE='42501'; END IF;
 -- User before session, same order as change_actor; locks held until transaction end.
 SELECT * INTO u FROM naruv_hosted_identity_review.users WHERE id=actor FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO s FROM naruv_hosted_identity_review.sessions WHERE token_hash=h FOR UPDATE;
 IF NOT FOUND OR s.actor_id IS DISTINCT FROM u.id OR s.revoked OR NOT u.active OR s.epoch<>u.epoch
 OR s.expires_at<=clock_timestamp() OR s.csrf_token IS DISTINCT FROM p_csrf OR u.actor_role<>'admin'
 OR u.org_id IS DISTINCT FROM p_tenant THEN RAISE EXCEPTION 'AUTH_DENIED' USING ERRCODE='42501'; END IF;
 RETURN u.org_id;
END $_$;


--
-- Name: revoke(text); Type: FUNCTION; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE FUNCTION naruv_hosted_identity_review.revoke(p_hash text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE n int;
BEGIN
 UPDATE naruv_hosted_identity_review.sessions SET revoked=true WHERE token_hash=p_hash AND NOT revoked;
 GET DIAGNOSTICS n=ROW_COUNT; RETURN n=1;
END $$;


--
-- Name: stage_identity_v84(); Type: FUNCTION; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE FUNCTION naruv_hosted_identity_review.stage_identity_v84() RETURNS TABLE(actor_id text, org_id text, actor_role text, csrf_token text, org_name text)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT u.id,u.org_id,u.actor_role,s.csrf_token,o.name FROM naruv_hosted_identity_review.sessions s JOIN naruv_hosted_identity_review.users u ON u.id=s.actor_id JOIN naruv_hosted_identity_review.organizations o ON o.id=u.org_id
 WHERE s.token_hash=nullif(current_setting('jw.session_hash',true),'') AND s.expires_at>clock_timestamp() AND NOT s.revoked AND u.active AND s.epoch=u.epoch
$$;


--
-- Name: import_item(); Type: FUNCTION; Schema: naruv_inventory; Owner: -
--

CREATE FUNCTION naruv_inventory.import_item() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
BEGIN
 IF current_user IS DISTINCT FROM 'naruv_native_owner' OR NEW.entity IS DISTINCT FROM 'item'
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 INSERT INTO naruv_inventory.items(org_id,source_id,normalized_id,source_item_id,name,unit)
 VALUES(NEW.org_id,NEW.source_id,NEW.normalized_id,NEW.source_record_id,NEW.data->>'name',coalesce(NEW.data->>'unit',''));
 RETURN NEW;
END $$;


--
-- Name: post_movement(text, text, text, text, text, bigint, text); Type: FUNCTION; Schema: naruv_inventory; Owner: -
--

CREATE FUNCTION naruv_inventory.post_movement(p_source text, p_item text, p_request text, p_from text, p_to text, p_qty bigint, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; r jsonb;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF left(p_request,4)='doc:' OR p_from IS NULL THEN RAISE EXCEPTION 'INV_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 r:=naruv_inventory.post_movement_internal(p_source,p_item,p_request,p_from,p_to,p_qty,p_csrf);
 IF NOT EXISTS(SELECT 1 FROM naruv_valuation.entries z WHERE z.org_id=a.org_id AND z.movement_id=p_request) THEN
  PERFORM naruv_valuation.apply(a.org_id,p_request,CASE WHEN p_to IS NULL THEN 'adjustment_issue' ELSE 'transfer' END,NULL,NULL);
 END IF;
 RETURN r;
END $$;


--
-- Name: post_movement_internal(text, text, text, text, text, bigint, text); Type: FUNCTION; Schema: naruv_inventory; Owner: -
--

CREATE FUNCTION naruv_inventory.post_movement_internal(p_source text, p_item text, p_request text, p_from text, p_to text, p_qty bigint, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a record; a2 record; m naruv_inventory.movements; item text; wh text; available bigint; f bigint; t bigint;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_source IS NULL OR p_source !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_item IS NULL OR p_item !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_from IS NOT DISTINCT FROM p_to OR p_qty IS NULL OR p_qty NOT BETWEEN 1 AND 1000000000
 OR (p_from IS NOT NULL AND p_from !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$')
 OR (p_to IS NOT NULL AND p_to !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$')
 THEN RAISE EXCEPTION 'INV_INPUT'; END IF;
 item:=lower(p_item COLLATE "C");
 -- Conservative fixture lock: serialize tenant movements, including across items.
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO m FROM naruv_inventory.movements x WHERE x.org_id=a.org_id AND x.request_id=p_request;
 IF FOUND THEN
  IF (m.actor_id,m.source_id,m.normalized_id,m.from_warehouse,m.to_warehouse,m.quantity)
  IS DISTINCT FROM (a.actor_id,p_source,item,p_from,p_to,p_qty) THEN RAISE EXCEPTION 'INV_CONFLICT'; END IF;
  RETURN naruv_inventory.receipt(m);
 END IF;
 PERFORM 1 FROM naruv_inventory.items i WHERE i.org_id=a.org_id AND i.source_id=p_source AND i.normalized_id=item;
 IF NOT FOUND THEN RAISE EXCEPTION 'INV_NOT_FOUND'; END IF;
 -- No fractional stock or implicit unit conversion. Unspecified units cannot move.
 IF EXISTS(SELECT 1 FROM naruv_inventory.items i WHERE i.org_id=a.org_id AND i.source_id=p_source AND i.normalized_id=item AND btrim(i.unit)='')
 THEN RAISE EXCEPTION 'INV_UNIT_REQUIRED'; END IF;
 FOR wh IN SELECT x FROM unnest(ARRAY[p_from,p_to]) x WHERE x IS NOT NULL ORDER BY x COLLATE "C" LOOP
  PERFORM 1 FROM naruv_inventory.warehouses w WHERE w.org_id=a.org_id AND w.warehouse_id=wh AND w.active FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'INV_NOT_FOUND'; END IF;
  INSERT INTO naruv_inventory.balances VALUES(a.org_id,p_source,item,wh,0) ON CONFLICT DO NOTHING;
  SELECT b.quantity INTO available FROM naruv_inventory.balances b
   WHERE b.org_id=a.org_id AND b.source_id=p_source AND b.normalized_id=item AND b.warehouse_id=wh FOR UPDATE;
  IF wh=p_from THEN
   IF available<p_qty THEN RAISE EXCEPTION 'INV_INSUFFICIENT'; END IF;
   f:=available-p_qty;
   UPDATE naruv_inventory.balances b SET quantity=f WHERE b.org_id=a.org_id AND b.source_id=p_source AND b.normalized_id=item AND b.warehouse_id=wh;
  ELSE
   IF available>1000000000000-p_qty THEN RAISE EXCEPTION 'INV_CAPACITY'; END IF;
   t:=available+p_qty;
   UPDATE naruv_inventory.balances b SET quantity=t WHERE b.org_id=a.org_id AND b.source_id=p_source AND b.normalized_id=item AND b.warehouse_id=wh;
  END IF;
 END LOOP;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 INSERT INTO naruv_inventory.movements VALUES(a.org_id,p_request,a.actor_id,p_source,item,p_from,p_to,p_qty,f,t,clock_timestamp()) RETURNING * INTO m;
 RETURN naruv_inventory.receipt(m);
END $_$;


--
-- Name: read_stock(text, text, text, text); Type: FUNCTION; Schema: naruv_inventory; Owner: -
--

CREATE FUNCTION naruv_inventory.read_stock(p_source text, p_item text, p_warehouse text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; i naruv_inventory.items; qty bigint;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 SELECT * INTO i FROM naruv_inventory.items x WHERE x.org_id=a.org_id AND x.source_id=p_source AND x.normalized_id=lower(p_item COLLATE "C");
 IF NOT FOUND THEN RAISE EXCEPTION 'INV_NOT_FOUND'; END IF;
 PERFORM 1 FROM naruv_inventory.warehouses w WHERE w.org_id=a.org_id AND w.warehouse_id=p_warehouse AND w.active;
 IF NOT FOUND THEN RAISE EXCEPTION 'INV_NOT_FOUND'; END IF;
 SELECT b.quantity INTO qty FROM naruv_inventory.balances b WHERE b.org_id=a.org_id AND b.source_id=p_source AND b.normalized_id=i.normalized_id AND b.warehouse_id=p_warehouse;
 RETURN jsonb_build_object('item_id',i.source_item_id,'name',i.name,'unit',i.unit,'warehouse_id',p_warehouse,'quantity',coalesce(qty,0),'production_authorized',false);
END $$;


--
-- Name: movements; Type: TABLE; Schema: naruv_inventory; Owner: -
--

CREATE TABLE naruv_inventory.movements (
    org_id text NOT NULL,
    request_id text NOT NULL,
    actor_id text NOT NULL,
    source_id text NOT NULL,
    normalized_id text NOT NULL,
    from_warehouse text,
    to_warehouse text,
    quantity bigint NOT NULL,
    from_after bigint,
    to_after bigint,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT movements_check CHECK ((from_warehouse IS DISTINCT FROM to_warehouse)),
    CONSTRAINT movements_check1 CHECK (((from_warehouse IS NULL) = (from_after IS NULL))),
    CONSTRAINT movements_check2 CHECK (((to_warehouse IS NULL) = (to_after IS NULL))),
    CONSTRAINT movements_from_after_check CHECK (((from_after >= 0) AND (from_after <= '1000000000000'::bigint))),
    CONSTRAINT movements_quantity_check CHECK (((quantity >= 1) AND (quantity <= 1000000000))),
    CONSTRAINT movements_to_after_check CHECK (((to_after >= 0) AND (to_after <= '1000000000000'::bigint)))
);

ALTER TABLE ONLY naruv_inventory.movements FORCE ROW LEVEL SECURITY;


--
-- Name: receipt(naruv_inventory.movements); Type: FUNCTION; Schema: naruv_inventory; Owner: -
--

CREATE FUNCTION naruv_inventory.receipt(r naruv_inventory.movements) RETURNS jsonb
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog'
    AS $_$
 SELECT jsonb_build_object('status','REVIEW_MOVED','request_id',($1).request_id,'source_id',($1).source_id,
 'item_id',($1).normalized_id,'from_warehouse',($1).from_warehouse,'to_warehouse',($1).to_warehouse,
 'quantity',($1).quantity,'from_after',($1).from_after,'to_after',($1).to_after,'production_authorized',false)
$_$;


--
-- Name: approve(text, text, text, text, boolean, text); Type: FUNCTION; Schema: naruv_native_review; Owner: -
--

CREATE FUNCTION naruv_native_review.approve(p_id text, p_digest text, p_canonical text, p_snapshot text, p_confirmed boolean, p_csrf text) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; a2 record; s naruv_native_review.stages; old naruv_native_review.approvals; target record; stamp timestamptz;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_confirmed IS DISTINCT FROM true THEN RAISE EXCEPTION 'NARUV_CONFIRM_REQUIRED'; END IF;
 SELECT * INTO s FROM naruv_native_review.stages t WHERE t.org_id=a.org_id AND t.stage_id=p_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_STAGE_MISSING'; END IF;
 IF (s.actor_id,s.session_binding_sha256,s.auth_epoch,s.stage_sha256,s.canonical_sha256,s.snapshot_sha256) IS DISTINCT FROM (a.actor_id,a.session_binding_sha256,a.auth_epoch,p_digest,p_canonical,p_snapshot) THEN RAISE EXCEPTION 'NARUV_BINDING_CHANGED'; END IF;
 SELECT t.revision,t.existing_ids INTO target FROM jw_dev.naruv_review_sources t
 WHERE t.org_id=a.org_id AND t.source_id=s.source_id AND t.entity=s.entity AND t.active FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_SOURCE_NOT_FOUND'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.session_binding_sha256,a.auth_epoch) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.session_binding_sha256,a2.auth_epoch) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED'; END IF;
 IF target.revision IS DISTINCT FROM s.expected_revision OR ARRAY(SELECT x FROM unnest(target.existing_ids) x ORDER BY x COLLATE "C") IS DISTINCT FROM s.expected_ids
 THEN RAISE EXCEPTION 'NARUV_TARGET_CHANGED'; END IF;
 stamp:=clock_timestamp();
 IF stamp<s.created_at OR stamp>=s.expires_at THEN RAISE EXCEPTION 'NARUV_STAGE_EXPIRED'; END IF;
 SELECT * INTO old FROM naruv_native_review.approvals t WHERE t.org_id=a.org_id AND t.stage_id=p_id FOR UPDATE;
 IF FOUND THEN
  IF old.status<>'APPROVED' OR stamp<old.approved_at OR stamp>=old.expires_at THEN RAISE EXCEPTION 'NARUV_APPROVAL_TERMINAL'; END IF;
  IF (old.actor_id,old.stage_sha256,old.canonical_sha256,old.snapshot_sha256) IS DISTINCT FROM (a.actor_id,p_digest,p_canonical,p_snapshot) THEN RAISE EXCEPTION 'NARUV_BINDING_CHANGED'; END IF;
  RETURN 'ALREADY_APPROVED';
 END IF;
 INSERT INTO naruv_native_review.approvals VALUES(a.org_id,p_id,a.actor_id,p_digest,p_canonical,p_snapshot,'APPROVED',stamp,s.expires_at);
 RETURN 'APPROVED';
END $$;


--
-- Name: commit_stage(text, text, text, text, text, text); Type: FUNCTION; Schema: naruv_native_review; Owner: -
--

CREATE FUNCTION naruv_native_review.commit_stage(p_id text, p_digest text, p_canonical text, p_snapshot text, p_reservation text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a record; a2 record; s naruv_native_review.stages; ap naruv_native_review.approvals;
 r naruv_native_review.receipts; target record; new_ids text[]; v jsonb; id_key text; new_revision text;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_reservation IS NULL OR p_reservation !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' THEN RAISE EXCEPTION 'NARUV_STAGE_INPUT'; END IF;
 SELECT * INTO s FROM naruv_native_review.stages t WHERE t.org_id=a.org_id AND t.stage_id=p_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_STAGE_MISSING'; END IF;
 IF (s.actor_id,s.session_binding_sha256,s.auth_epoch,s.stage_sha256,s.canonical_sha256,s.snapshot_sha256) IS DISTINCT FROM (a.actor_id,a.session_binding_sha256,a.auth_epoch,p_digest,p_canonical,p_snapshot) THEN RAISE EXCEPTION 'NARUV_BINDING_CHANGED'; END IF;
 -- A committed receipt can be recovered even though the target revision advanced.
 SELECT * INTO r FROM naruv_native_review.receipts t WHERE t.org_id=a.org_id AND t.stage_id=p_id;
 IF FOUND THEN
  IF (r.reservation_id,r.actor_id,r.stage_sha256) IS DISTINCT FROM (p_reservation,a.actor_id,p_digest)
  THEN RAISE EXCEPTION 'NARUV_RESERVATION_CONFLICT'; END IF;
  RETURN naruv_native_review.receipt_json(r);
 END IF;
 SELECT t.revision,t.existing_ids,t.active INTO target FROM jw_dev.naruv_review_sources t
 WHERE t.org_id=a.org_id AND t.source_id=s.source_id AND t.entity=s.entity FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_SOURCE_NOT_FOUND'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.session_binding_sha256,a.auth_epoch) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.session_binding_sha256,a2.auth_epoch) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED'; END IF;
 -- Check receipt again after serialization for concurrent same-request retry.
 SELECT * INTO r FROM naruv_native_review.receipts t WHERE t.org_id=a.org_id AND t.stage_id=p_id;
 IF FOUND THEN
  IF (r.reservation_id,r.actor_id,r.stage_sha256) IS DISTINCT FROM (p_reservation,a.actor_id,p_digest)
  THEN RAISE EXCEPTION 'NARUV_RESERVATION_CONFLICT'; END IF;
  RETURN naruv_native_review.receipt_json(r);
 END IF;
 IF NOT target.active THEN RAISE EXCEPTION 'NARUV_SOURCE_NOT_FOUND'; END IF;
 SELECT * INTO ap FROM naruv_native_review.approvals t WHERE t.org_id=a.org_id AND t.stage_id=p_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_APPROVAL_REQUIRED'; END IF;
 IF (ap.actor_id,ap.stage_sha256,ap.canonical_sha256,ap.snapshot_sha256) IS DISTINCT FROM (a.actor_id,p_digest,p_canonical,p_snapshot) THEN RAISE EXCEPTION 'NARUV_BINDING_CHANGED'; END IF;
 IF ap.status<>'APPROVED' OR clock_timestamp()<ap.approved_at OR clock_timestamp()<s.created_at OR clock_timestamp()>=ap.expires_at OR clock_timestamp()>=s.expires_at
 THEN RAISE EXCEPTION 'NARUV_APPROVAL_TERMINAL'; END IF;
 IF target.revision IS DISTINCT FROM s.expected_revision OR ARRAY(SELECT x FROM unnest(target.existing_ids) x ORDER BY x COLLATE "C") IS DISTINCT FROM s.expected_ids
 THEN RAISE EXCEPTION 'NARUV_TARGET_CHANGED'; END IF;
 new_ids:=naruv_native_review.validated_ids(s.entity,s.rows_canonical::jsonb,s.expected_ids);
 id_key:=CASE WHEN s.entity='item' THEN 'source_item_id' ELSE 'source_customer_id' END;
 FOR v IN SELECT value FROM jsonb_array_elements(s.rows_canonical::jsonb) LOOP
  INSERT INTO naruv_native_review.records(org_id,source_id,entity,source_record_id,stage_id,data)
  VALUES(a.org_id,s.source_id,s.entity,v->>id_key,p_id,v);
 END LOOP;
 new_revision:='rev-'||encode(sha256(convert_to(s.expected_revision||':'||s.stage_sha256,'UTF8')),'hex');
 UPDATE jw_dev.naruv_review_sources t SET revision=new_revision,
 existing_ids=ARRAY(SELECT x FROM unnest(s.expected_ids||new_ids) x ORDER BY x COLLATE "C")
 WHERE t.org_id=a.org_id AND t.source_id=s.source_id AND t.entity=s.entity;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_TARGET_CHANGED'; END IF;
 -- Recheck after all record writes and target update, before durable receipt.
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.session_binding_sha256,a.auth_epoch)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.session_binding_sha256,a2.auth_epoch)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 IF clock_timestamp()<ap.approved_at OR clock_timestamp()<s.created_at
 OR clock_timestamp()>=ap.expires_at OR clock_timestamp()>=s.expires_at
 THEN RAISE EXCEPTION 'NARUV_APPROVAL_TERMINAL'; END IF;
 INSERT INTO naruv_native_review.receipts VALUES(a.org_id,p_id,a.actor_id,p_reservation,p_digest,p_canonical,p_snapshot,s.raw_sha256,s.rows_sha256,
 cardinality(new_ids),clock_timestamp()) RETURNING * INTO r;
 UPDATE naruv_native_review.approvals t SET status='COMMITTED' WHERE t.org_id=a.org_id AND t.stage_id=p_id;
 RETURN naruv_native_review.receipt_json(r);
END $_$;


--
-- Name: guard(text, text); Type: FUNCTION; Schema: naruv_native_review; Owner: -
--

CREATE FUNCTION naruv_native_review.guard(p_csrf text, p_kind text) RETURNS TABLE(actor_id text, org_id text, session_binding_sha256 text, auth_epoch bigint)
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a record; fresh record; generation bigint; h text; login record; business boolean; stage boolean;
BEGIN
 h:=current_setting('jw.session_hash',true);
 SELECT r.rolsuper,r.rolbypassrls,r.rolcreaterole,r.rolcreatedb INTO login FROM pg_catalog.pg_roles r WHERE r.rolname=session_user;
 IF NOT FOUND OR login.rolsuper OR login.rolbypassrls OR login.rolcreaterole OR login.rolcreatedb
 OR session_user IN ('postgres','supabase_admin','service_role','naruv_native_owner','naruv_native_stage','jw_app_dev','jw_auth_stage_v85')
 OR pg_has_role(session_user,'naruv_native_owner','MEMBER') OR pg_has_role(session_user,'jw_auth_stage_v85','MEMBER')
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 business:=pg_has_role(session_user,'jw_app_dev','MEMBER');
 stage:=pg_has_role(session_user,'naruv_native_stage','MEMBER');
 IF p_kind IS NULL OR p_kind NOT IN ('stage','business')
 OR (p_kind='stage' AND (NOT stage OR business)) OR (p_kind='business' AND (NOT business OR stage))
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT i.actor_id,i.org_id,i.actor_role,i.csrf_token INTO a FROM jw_dev.stage_identity_v84() i;
 IF NOT FOUND OR a.actor_id IS NULL OR a.org_id IS NULL OR a.actor_role IS DISTINCT FROM 'admin'
 OR h IS NULL OR h !~ '^[a-f0-9]{64}$'
 OR p_csrf IS NULL OR length(p_csrf) NOT BETWEEN 1 AND 512 OR p_csrf IS DISTINCT FROM a.csrf_token
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;

 IF naruv_hosted_identity_review.lock_admin(a.org_id,p_csrf) IS DISTINCT FROM a.org_id
 OR NOT EXISTS(SELECT 1 FROM naruv_hosted_identity_review.stage_identity_v84() z
   WHERE (z.actor_id,z.org_id,z.actor_role,z.csrf_token) IS NOT DISTINCT FROM
         (a.actor_id,a.org_id,a.actor_role,a.csrf_token))
 THEN RAISE EXCEPTION 'HOSTED_IDENTITY_MISMATCH' USING ERRCODE='42501'; END IF;
 generation:=naruv_auth_fence.lock_actor(a.actor_id);
 SELECT i.actor_id,i.org_id,i.actor_role,i.csrf_token INTO fresh FROM jw_dev.stage_identity_v84() i;
 IF NOT FOUND OR (fresh.actor_id,fresh.org_id,fresh.actor_role,fresh.csrf_token)
 IS DISTINCT FROM (a.actor_id,a.org_id,a.actor_role,a.csrf_token)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT a.actor_id,a.org_id,encode(sha256(convert_to('naruv-native-session-v1:'||h,'UTF8')),'hex'),generation;
END $_$;


--
-- Name: immutable(); Type: FUNCTION; Schema: naruv_native_review; Owner: -
--

CREATE FUNCTION naruv_native_review.immutable() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
BEGIN RAISE EXCEPTION 'NARUV_IMMUTABLE'; END $$;


--
-- Name: inspect(text, text, text); Type: FUNCTION; Schema: naruv_native_review; Owner: -
--

CREATE FUNCTION naruv_native_review.inspect(p_id text, p_reservation text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; r naruv_native_review.receipts;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 SELECT * INTO r FROM naruv_native_review.receipts t WHERE t.org_id=a.org_id AND t.stage_id=p_id AND t.actor_id=a.actor_id AND t.reservation_id=p_reservation;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_STAGE_MISSING'; END IF;
 RETURN naruv_native_review.receipt_json(r);
END $$;


--
-- Name: read_source(text, text, text); Type: FUNCTION; Schema: naruv_native_review; Owner: -
--

CREATE FUNCTION naruv_native_review.read_source(p_source text, p_entity text, p_csrf text) RETURNS TABLE(revision text, existing_ids text[])
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'stage');
 RETURN QUERY SELECT s.revision,ARRAY(SELECT x FROM unnest(s.existing_ids) x ORDER BY x COLLATE "C")
 FROM jw_dev.naruv_review_sources s WHERE s.org_id=a.org_id AND s.source_id=p_source AND s.entity=p_entity AND s.active;
END $$;


--
-- Name: receipts; Type: TABLE; Schema: naruv_native_review; Owner: -
--

CREATE TABLE naruv_native_review.receipts (
    org_id text NOT NULL,
    stage_id text NOT NULL,
    actor_id text NOT NULL,
    reservation_id text NOT NULL,
    stage_sha256 text NOT NULL,
    canonical_sha256 text NOT NULL,
    snapshot_sha256 text NOT NULL,
    raw_sha256 text NOT NULL,
    rows_sha256 text NOT NULL,
    row_count integer NOT NULL,
    completed_at timestamp with time zone NOT NULL,
    CONSTRAINT receipts_canonical_sha256_check CHECK ((canonical_sha256 ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT receipts_raw_sha256_check CHECK ((raw_sha256 ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT receipts_reservation_id_check CHECK ((reservation_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'::text)),
    CONSTRAINT receipts_row_count_check CHECK (((row_count >= 1) AND (row_count <= 1000))),
    CONSTRAINT receipts_rows_sha256_check CHECK ((rows_sha256 ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT receipts_snapshot_sha256_check CHECK ((snapshot_sha256 ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT receipts_stage_sha256_check CHECK ((stage_sha256 ~ '^[a-f0-9]{64}$'::text))
);

ALTER TABLE ONLY naruv_native_review.receipts FORCE ROW LEVEL SECURITY;


--
-- Name: receipt_json(naruv_native_review.receipts); Type: FUNCTION; Schema: naruv_native_review; Owner: -
--

CREATE FUNCTION naruv_native_review.receipt_json(r naruv_native_review.receipts) RETURNS jsonb
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog'
    AS $_$
 SELECT jsonb_build_object('status','REVIEW_COMMITTED','stage_id',($1).stage_id,'reservation_id',($1).reservation_id,
 'stage_sha256',($1).stage_sha256,'canonical_rows_sha256',($1).canonical_sha256,'target_snapshot_sha256',($1).snapshot_sha256,'raw_sha256',($1).raw_sha256,'rows_sha256',($1).rows_sha256,'row_count',($1).row_count,
 'row_import_authorized',false)
$_$;


--
-- Name: revoke(text, text, text, text, text); Type: FUNCTION; Schema: naruv_native_review; Owner: -
--

CREATE FUNCTION naruv_native_review.revoke(p_id text, p_digest text, p_canonical text, p_snapshot text, p_csrf text) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; a2 record; old naruv_native_review.approvals;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 SELECT * INTO old FROM naruv_native_review.approvals t WHERE t.org_id=a.org_id AND t.stage_id=p_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_STAGE_MISSING'; END IF;
 IF (old.actor_id,old.stage_sha256,old.canonical_sha256,old.snapshot_sha256) IS DISTINCT FROM (a.actor_id,p_digest,p_canonical,p_snapshot) THEN RAISE EXCEPTION 'NARUV_BINDING_CHANGED'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.session_binding_sha256,a.auth_epoch) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.session_binding_sha256,a2.auth_epoch) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED'; END IF;
 IF old.status='REVOKED' THEN RETURN 'ALREADY_REVOKED'; END IF;
 IF old.status<>'APPROVED' THEN RAISE EXCEPTION 'NARUV_APPROVAL_TERMINAL'; END IF;
 UPDATE naruv_native_review.approvals t SET status='REVOKED' WHERE t.org_id=a.org_id AND t.stage_id=p_id;
 RETURN 'REVOKED';
END $$;


--
-- Name: store_stage(text, text, text, text, text, integer, text, text, text, text, text, text[], text, text); Type: FUNCTION; Schema: naruv_native_review; Owner: -
--

CREATE FUNCTION naruv_native_review.store_stage(p_id text, p_source text, p_entity text, p_format text, p_raw text, p_bytes integer, p_digest text, p_canonical text, p_rows_sha text, p_snapshot text, p_revision text, p_expected text[], p_rows_text text, p_csrf text) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a record; a2 record; target record; old naruv_native_review.stages; stamp timestamptz;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'stage');
 IF p_id IS NULL OR p_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR p_format IS NULL OR p_format NOT IN ('csv','xlsx')
 OR p_raw IS NULL OR p_raw !~ '^[a-f0-9]{64}$' OR p_digest IS NULL OR p_digest !~ '^[a-f0-9]{64}$'
 OR p_canonical IS NULL OR p_canonical !~ '^[a-f0-9]{64}$'
 OR p_rows_text IS NULL OR octet_length(p_rows_text)>2097152 OR p_canonical IS DISTINCT FROM encode(sha256(convert_to(p_rows_text,'UTF8')),'hex')
 OR p_rows_sha IS NULL OR p_rows_sha !~ '^[a-f0-9]{64}$' OR p_snapshot IS NULL OR p_snapshot !~ '^[a-f0-9]{64}$'
 OR p_bytes IS NULL OR p_bytes NOT BETWEEN 1 AND 1048576
 THEN RAISE EXCEPTION 'NARUV_STAGE_INPUT'; END IF;
 -- Tenant quota lock precedes the source lock.
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-native-quota-v1:'||a.org_id,0));
 -- Serialize all writes for a tenant/source/entity. Target is never browser authority.
 SELECT s.revision,s.existing_ids INTO target FROM jw_dev.naruv_review_sources s
 WHERE s.org_id=a.org_id AND s.source_id=p_source AND s.entity=p_entity AND s.active FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_SOURCE_NOT_FOUND'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'stage');
 IF (a.actor_id,a.org_id,a.session_binding_sha256,a.auth_epoch) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.session_binding_sha256,a2.auth_epoch) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED'; END IF;
 IF target.revision IS DISTINCT FROM p_revision OR
 ARRAY(SELECT x FROM unnest(target.existing_ids) x ORDER BY x COLLATE "C") IS DISTINCT FROM p_expected
 THEN RAISE EXCEPTION 'NARUV_TARGET_CHANGED'; END IF;
 IF p_snapshot IS DISTINCT FROM naruv_native_review.target_digest(a.org_id,p_source,p_entity,p_revision,p_expected) THEN RAISE EXCEPTION 'NARUV_TARGET_CHANGED'; END IF;
 PERFORM naruv_native_review.validated_ids(p_entity,p_rows_text::jsonb,p_expected);
 SELECT * INTO old FROM naruv_native_review.stages s WHERE s.org_id=a.org_id AND s.stage_id=p_id;
 stamp:=clock_timestamp();
 IF FOUND THEN
  IF (old.actor_id,old.session_binding_sha256,old.auth_epoch,old.source_id,old.entity,old.file_format,old.raw_sha256,old.byte_count,old.stage_sha256,old.canonical_sha256,old.rows_sha256,
      old.snapshot_sha256,old.expected_revision,old.expected_ids,old.rows_canonical)
  IS DISTINCT FROM (a.actor_id,a.session_binding_sha256,a.auth_epoch,p_source,p_entity,p_format,p_raw,p_bytes,p_digest,p_canonical,p_rows_sha,p_snapshot,p_revision,p_expected,p_rows_text)
  THEN RAISE EXCEPTION 'NARUV_STAGE_CONFLICT'; END IF;
  IF stamp<old.created_at OR stamp>=old.expires_at THEN RAISE EXCEPTION 'NARUV_STAGE_EXPIRED'; END IF;
  RETURN 'ALREADY_STAGED';
 END IF;
 -- Logical UTF-8 payload budget, not physical disk usage. No automatic purge.
 IF (SELECT count(*) FROM naruv_native_review.stages s WHERE s.org_id=a.org_id)>=128
 OR (SELECT coalesce(sum(octet_length(s.rows_canonical)::bigint+octet_length(array_to_json(s.expected_ids)::text)),0)
     FROM naruv_native_review.stages s WHERE s.org_id=a.org_id)
      +octet_length(p_rows_text)+octet_length(array_to_json(p_expected)::text)>16777216
 THEN RAISE EXCEPTION 'NARUV_CAPACITY'; END IF;
 INSERT INTO naruv_native_review.stages VALUES(a.org_id,p_id,a.actor_id,a.session_binding_sha256,a.auth_epoch,p_source,p_entity,p_format,p_raw,p_bytes,p_digest,p_canonical,p_rows_sha,
  p_snapshot,p_revision,p_expected,p_rows_text,stamp,stamp+interval '15 minutes');
 RETURN 'STAGED';
END $_$;


--
-- Name: target_digest(text, text, text, text, text[]); Type: FUNCTION; Schema: naruv_native_review; Owner: -
--

CREATE FUNCTION naruv_native_review.target_digest(p_org text, p_source text, p_entity text, p_rev text, p_ids text[]) RETURNS text
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT encode(sha256(convert_to('{"entity":'||to_json(p_entity)::text||',"existing_source_ids":'||array_to_json(p_ids)::text||
 ',"organization_id":'||to_json(p_org)::text||',"revision":'||to_json(p_rev)::text||
 ',"source_id":'||to_json(p_source)::text||',"version":1}','UTF8')),'hex')
$$;


--
-- Name: validated_ids(text, jsonb, text[]); Type: FUNCTION; Schema: naruv_native_review; Owner: -
--

CREATE FUNCTION naruv_native_review.validated_ids(p_entity text, p_rows jsonb, p_existing text[]) RETURNS text[]
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE v jsonb; id_key text; opt_key text; code text; seen text[]:=ARRAY[]::text[]; added text[]:=ARRAY[]::text[];
BEGIN
 IF p_entity NOT IN ('item','customer') OR p_entity IS NULL OR p_existing IS NULL OR cardinality(p_existing)>10000
 OR array_position(p_existing,NULL) IS NOT NULL OR jsonb_typeof(p_rows) IS DISTINCT FROM 'array'
 THEN RAISE EXCEPTION 'NARUV_ROWS_INVALID'; END IF;
 IF jsonb_array_length(p_rows) NOT BETWEEN 1 AND 1000 OR octet_length(p_rows::text)>2097152
 THEN RAISE EXCEPTION 'NARUV_ROWS_INVALID'; END IF;
 IF cardinality(p_existing)+jsonb_array_length(p_rows)>10000 THEN RAISE EXCEPTION 'NARUV_CAPACITY'; END IF;
 FOREACH code IN ARRAY p_existing LOOP
  IF code !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR lower(code COLLATE "C")=ANY(seen)
  THEN RAISE EXCEPTION 'NARUV_TARGET_INVALID'; END IF;
  seen:=array_append(seen,lower(code COLLATE "C"));
 END LOOP;
 id_key:=CASE WHEN p_entity='item' THEN 'source_item_id' ELSE 'source_customer_id' END;
 opt_key:=CASE WHEN p_entity='item' THEN 'unit' ELSE 'business_number' END;
 FOR v IN SELECT value FROM jsonb_array_elements(p_rows) LOOP
  IF jsonb_typeof(v) IS DISTINCT FROM 'object' OR jsonb_typeof(v->id_key) IS DISTINCT FROM 'string'
  OR jsonb_typeof(v->'name') IS DISTINCT FROM 'string' OR v-id_key-'name'-opt_key <> '{}'::jsonb
  OR (v ? opt_key AND jsonb_typeof(v->opt_key) IS DISTINCT FROM 'string')
  OR length(v->>'name') NOT BETWEEN 1 AND 120 OR v->>'name' <> btrim(v->>'name')
  OR left(v->>'name',1) IN ('=','+','-','@')
  OR (p_entity='item' AND length(v->>opt_key)>32)
  OR (p_entity='customer' AND v->>opt_key<>'' AND v->>opt_key !~ '^([0-9]{10}|[0-9]{3}-[0-9]{2}-[0-9]{5})$')
  THEN RAISE EXCEPTION 'NARUV_ROWS_INVALID'; END IF;
  code:=v->>id_key;
  IF code !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR lower(code COLLATE "C")=ANY(seen)
  THEN RAISE EXCEPTION 'NARUV_DUPLICATE_ID'; END IF;
  seen:=array_append(seen,lower(code COLLATE "C")); added:=array_append(added,code);
 END LOOP;
 RETURN added;
END $_$;


--
-- Name: command(text, text, text, jsonb, boolean, text); Type: FUNCTION; Schema: naruv_production; Owner: -
--

CREATE FUNCTION naruv_production.command(p_key text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; a2 record; b naruv_production.boms; o naruv_production.orders; e naruv_production.events;
 c naruv_production.components; x jsonb; src text; product text; material text; wh text; bid text;
 q bigint; per bigint; result jsonb; plan jsonb; movements jsonb:='[]'::jsonb; mid text;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF NOT naruv_production.ident(p_key) OR NOT naruv_production.ident(p_request)
 OR p_action IS NULL OR p_action NOT IN ('define','open','complete','cancel')
 OR p_confirm IS DISTINCT FROM true OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
 OR octet_length(p_payload::text)>16384 THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO e FROM naruv_production.events z WHERE z.org_id=a.org_id AND z.request_id=p_request;
 IF FOUND THEN
  IF (coalesce(e.order_id,e.bom_id),e.actor_id,e.action,e.payload) IS DISTINCT FROM (p_key,a.actor_id,p_action,p_payload)
  THEN RAISE EXCEPTION 'PROD_CONFLICT'; END IF;
  RETURN e.receipt;
 END IF;
 IF p_action='define' THEN
  IF p_payload-'source_id'-'product_id'-'lines'<>'{}'::jsonb
  OR jsonb_typeof(p_payload->'source_id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(p_payload->'product_id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(p_payload->'lines') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
  src:=p_payload->>'source_id';product:=lower((p_payload->>'product_id') COLLATE "C");bid:=p_key;
  IF NOT naruv_production.ident(src) OR NOT naruv_production.ident(product)
  OR jsonb_array_length(p_payload->'lines') NOT BETWEEN 1 AND 20 THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
  IF (SELECT count(*) FROM naruv_production.boms z WHERE z.org_id=a.org_id)>=128 THEN RAISE EXCEPTION 'PROD_CAPACITY'; END IF;
  PERFORM 1 FROM naruv_inventory.items i WHERE i.org_id=a.org_id AND i.source_id=src AND i.normalized_id=product AND btrim(i.unit)<>'';
  IF NOT FOUND THEN RAISE EXCEPTION 'PROD_NOT_FOUND'; END IF;
  INSERT INTO naruv_production.boms VALUES(a.org_id,bid,src,product,a.actor_id,clock_timestamp());
  FOR x IN SELECT value FROM jsonb_array_elements(p_payload->'lines') LOOP
   IF jsonb_typeof(x) IS DISTINCT FROM 'object' OR x-'material_id'-'per_unit'<>'{}'::jsonb
   OR jsonb_typeof(x->'material_id') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
   material:=lower((x->>'material_id') COLLATE "C");per:=naruv_production.qty(x->'per_unit',10000);
   IF NOT naruv_production.ident(material) THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
   PERFORM 1 FROM naruv_inventory.items i WHERE i.org_id=a.org_id AND i.source_id=src AND i.normalized_id=material AND btrim(i.unit)<>'';
   IF NOT FOUND THEN RAISE EXCEPTION 'PROD_NOT_FOUND'; END IF;
   IF EXISTS(WITH RECURSIVE reach(item) AS (
     SELECT material UNION SELECT z.material_id FROM reach r
     JOIN naruv_production.boms h ON h.org_id=a.org_id AND h.source_id=src AND h.product_id=r.item
     JOIN naruv_production.components z ON (z.org_id,z.bom_id)=(h.org_id,h.bom_id)
    ) SELECT 1 FROM reach WHERE item=product) THEN RAISE EXCEPTION 'PROD_CYCLE'; END IF;
   INSERT INTO naruv_production.components VALUES(a.org_id,bid,src,material,per);
  END LOOP;
  result:=jsonb_build_object('bom_id',bid,'product_id',product,'source_id',src,'lines',p_payload->'lines','production_authorized',false);
 ELSE
  IF p_action='open' THEN
   IF p_payload-'bom_id'-'warehouse_id'-'quantity'<>'{}'::jsonb
   OR jsonb_typeof(p_payload->'bom_id') IS DISTINCT FROM 'string'
   OR jsonb_typeof(p_payload->'warehouse_id') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
   bid:=p_payload->>'bom_id';wh:=p_payload->>'warehouse_id';q:=naruv_production.qty(p_payload->'quantity',100000);
   IF NOT naruv_production.ident(bid) OR NOT naruv_production.ident(wh) THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
   plan:=naruv_production.plan(a.org_id,bid,wh,q);
   IF EXISTS(SELECT 1 FROM jsonb_array_elements(plan->'lines') z WHERE (z->>'shortage')::bigint>0)
   THEN RAISE EXCEPTION 'INV_INSUFFICIENT'; END IF;
   INSERT INTO naruv_production.orders VALUES(a.org_id,p_key,bid,wh,a.actor_id,q,0,'OPEN',clock_timestamp()) RETURNING * INTO o;
  ELSE
   SELECT * INTO o FROM naruv_production.orders z WHERE z.org_id=a.org_id AND z.order_id=p_key FOR UPDATE;
   IF NOT FOUND THEN RAISE EXCEPTION 'PROD_NOT_FOUND'; END IF;
   IF o.state NOT IN ('OPEN','PARTIAL') THEN RAISE EXCEPTION 'PROD_TERMINAL'; END IF;
   bid:=o.bom_id;wh:=o.warehouse_id;
   IF p_action='cancel' THEN
    IF p_payload<>'{}'::jsonb THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
    UPDATE naruv_production.orders z SET state='CANCELLED' WHERE z.org_id=a.org_id AND z.order_id=p_key RETURNING * INTO o;
   ELSE
    IF p_payload-'quantity'<>'{}'::jsonb THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
    q:=naruv_production.qty(p_payload->'quantity',100000);
    IF q>o.quantity-o.completed THEN RAISE EXCEPTION 'PROD_OVER_QUANTITY'; END IF;
    SELECT * INTO STRICT b FROM naruv_production.boms z WHERE z.org_id=a.org_id AND z.bom_id=bid;
    -- Release only this completion's reservation; all material issues and output share one transaction.
    UPDATE naruv_production.orders z SET completed=z.completed+q,state=CASE WHEN z.completed+q=z.quantity THEN 'DONE' ELSE 'PARTIAL' END
     WHERE z.org_id=a.org_id AND z.order_id=p_key RETURNING * INTO o;
    FOR c IN SELECT * FROM naruv_production.components z WHERE z.org_id=a.org_id AND z.bom_id=bid ORDER BY z.material_id LOOP
     mid:='doc:'||encode(sha256(convert_to(jsonb_build_array('production',p_request,'material',c.material_id)::text,'UTF8')),'hex');
     movements:=movements||jsonb_build_array(naruv_inventory.post_movement_internal(c.source_id,c.material_id,mid,wh,NULL,c.per_unit*q,p_csrf));
    END LOOP;
    mid:='doc:'||encode(sha256(convert_to(jsonb_build_array('production',p_request,'output',b.product_id)::text,'UTF8')),'hex');
    movements:=movements||jsonb_build_array(naruv_inventory.post_movement_internal(b.source_id,b.product_id,mid,NULL,wh,q,p_csrf));
   END IF;
  END IF;
  result:=naruv_production.snapshot(o)||jsonb_build_object('movements',movements);
 END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 result:=result||jsonb_build_object('request_id',p_request,'action',p_action);
 INSERT INTO naruv_production.events VALUES(a.org_id,p_request,bid,CASE WHEN p_action='define' THEN NULL ELSE p_key END,a.actor_id,p_action,p_payload,result,clock_timestamp());
 RETURN result;
END $$;


--
-- Name: ident(text); Type: FUNCTION; Schema: naruv_production; Owner: -
--

CREATE FUNCTION naruv_production.ident(v text) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog'
    AS $_$
 SELECT coalesce($1 ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$',false)
$_$;


--
-- Name: inspect(text, text); Type: FUNCTION; Schema: naruv_production; Owner: -
--

CREATE FUNCTION naruv_production.inspect(p_order text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; o naruv_production.orders;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 SELECT * INTO o FROM naruv_production.orders z WHERE z.org_id=a.org_id AND z.order_id=p_order;
 IF NOT FOUND THEN RAISE EXCEPTION 'PROD_NOT_FOUND'; END IF;
 RETURN naruv_production.snapshot(o);
END $$;


--
-- Name: plan(text, text, text, bigint); Type: FUNCTION; Schema: naruv_production; Owner: -
--

CREATE FUNCTION naruv_production.plan(p_org text, p_bom text, p_wh text, p_qty bigint) RETURNS jsonb
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE b naruv_production.boms; rows jsonb;
BEGIN
 SELECT * INTO b FROM naruv_production.boms x WHERE x.org_id=p_org AND x.bom_id=p_bom;
 IF NOT FOUND THEN RAISE EXCEPTION 'PROD_NOT_FOUND'; END IF;
 PERFORM 1 FROM naruv_inventory.warehouses w WHERE w.org_id=p_org AND w.warehouse_id=p_wh AND w.active FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PROD_NOT_FOUND'; END IF;
 SELECT jsonb_agg(jsonb_build_object('material_id',c.material_id,'per_unit',c.per_unit,
 'required',c.per_unit*p_qty,'stock',coalesce(s.quantity,0),
 'reserved',naruv_trade.reserved(p_org,c.source_id,c.material_id,p_wh),
 'shortage',greatest(0,c.per_unit*p_qty-coalesce(s.quantity,0)+naruv_trade.reserved(p_org,c.source_id,c.material_id,p_wh))) ORDER BY c.material_id)
 INTO rows FROM naruv_production.components c LEFT JOIN naruv_inventory.balances s
 ON (s.org_id,s.source_id,s.normalized_id,s.warehouse_id)=(c.org_id,c.source_id,c.material_id,p_wh)
 WHERE c.org_id=p_org AND c.bom_id=p_bom;
 RETURN jsonb_build_object('bom_id',p_bom,'product_id',b.product_id,'warehouse_id',p_wh,'quantity',p_qty,
 'lines',rows,'production_authorized',false);
END $$;


--
-- Name: qty(jsonb, bigint); Type: FUNCTION; Schema: naruv_production; Owner: -
--

CREATE FUNCTION naruv_production.qty(v jsonb, p_max bigint) RETURNS bigint
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE q bigint;
BEGIN
 IF jsonb_typeof(v) IS DISTINCT FROM 'number' OR (v#>>'{}') !~ '^[0-9]{1,9}$' THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
 q:=(v#>>'{}')::bigint;
 IF q<1 OR q>p_max THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
 RETURN q;
END $_$;


--
-- Name: requirements(text, jsonb, text); Type: FUNCTION; Schema: naruv_production; Owner: -
--

CREATE FUNCTION naruv_production.requirements(p_bom text, p_payload jsonb, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; q bigint; wh text;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF jsonb_typeof(p_payload) IS DISTINCT FROM 'object' OR p_payload-'warehouse_id'-'quantity'<>'{}'::jsonb
 OR jsonb_typeof(p_payload->'warehouse_id') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
 wh:=p_payload->>'warehouse_id';q:=naruv_production.qty(p_payload->'quantity',100000);
 IF NOT naruv_production.ident(p_bom) OR NOT naruv_production.ident(wh) THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 RETURN naruv_production.plan(a.org_id,p_bom,wh,q);
END $$;


--
-- Name: orders; Type: TABLE; Schema: naruv_production; Owner: -
--

CREATE TABLE naruv_production.orders (
    org_id text NOT NULL,
    order_id text NOT NULL,
    bom_id text NOT NULL,
    warehouse_id text NOT NULL,
    actor_id text NOT NULL,
    quantity bigint NOT NULL,
    completed bigint NOT NULL,
    state text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT orders_check CHECK (((completed >= 0) AND (completed <= quantity))),
    CONSTRAINT orders_check1 CHECK ((((state = 'OPEN'::text) AND (completed = 0)) OR ((state = 'PARTIAL'::text) AND (completed > 0) AND (completed < quantity)) OR ((state = 'DONE'::text) AND (completed = quantity)) OR ((state = 'CANCELLED'::text) AND (completed < quantity)))),
    CONSTRAINT orders_quantity_check CHECK (((quantity >= 1) AND (quantity <= 100000))),
    CONSTRAINT orders_state_check CHECK ((state = ANY (ARRAY['OPEN'::text, 'PARTIAL'::text, 'DONE'::text, 'CANCELLED'::text])))
);

ALTER TABLE ONLY naruv_production.orders FORCE ROW LEVEL SECURITY;


--
-- Name: snapshot(naruv_production.orders); Type: FUNCTION; Schema: naruv_production; Owner: -
--

CREATE FUNCTION naruv_production.snapshot(o naruv_production.orders) RETURNS jsonb
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog'
    AS $_$
 SELECT jsonb_build_object('order_id',($1).order_id,'bom_id',($1).bom_id,'warehouse_id',($1).warehouse_id,
 'quantity',($1).quantity,'completed',($1).completed,'state',($1).state,
 'remaining',CASE WHEN ($1).state='CANCELLED' THEN 0 ELSE ($1).quantity-($1).completed END,'production_authorized',false)
$_$;


--
-- Name: allocate_vat(); Type: FUNCTION; Schema: naruv_quote_bundle; Owner: -
--

CREATE FUNCTION naruv_quote_bundle.allocate_vat() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE qid text; mode text; prev numeric;
BEGIN
 SELECT d.quote_id,d.vat_mode INTO qid,mode FROM naruv_trade.documents d
 WHERE d.org_id=NEW.org_id AND d.doc_id=NEW.doc_id AND d.quote_line_id IS NOT NULL;
 IF NOT FOUND THEN RETURN NEW; END IF;
 SELECT coalesce(sum(b.subtotal),0) INTO prev FROM naruv_finance.bills b JOIN naruv_trade.documents d ON (b.org_id,b.doc_id)=(d.org_id,d.doc_id)
 WHERE d.org_id=NEW.org_id AND d.quote_id=qid AND d.quote_line_id IS NOT NULL;
 NEW.vat:=CASE WHEN mode='taxable' THEN floor((prev+NEW.subtotal+5)/10)-floor((prev+5)/10) ELSE 0 END;
 RETURN NEW;
END $$;


--
-- Name: convert(text, text, jsonb, boolean, text); Type: FUNCTION; Schema: naruv_quote_bundle; Owner: -
--

CREATE FUNCTION naruv_quote_bundle.convert(p_bundle text, p_request text, p_payload jsonb, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a record; a2 record; e naruv_bundle.events; s jsonb; qid text; digest text; mappings jsonb;
 x jsonb; m jsonb; idx int; cid text; rid text; src text; itm text; wh text; qty bigint; price bigint;
 stock bigint; d naruv_trade.documents; result jsonb; out_rows jsonb:='[]'::jsonb;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_bundle IS NULL OR p_bundle !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_confirm IS DISTINCT FROM true OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
 OR p_payload-'quote_id'-'snapshot_sha256'-'lines'<>'{}'::jsonb OR octet_length(p_payload::text)>16384
 OR jsonb_typeof(p_payload->'quote_id') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p_payload->'snapshot_sha256') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p_payload->'lines') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'QB_INPUT'; END IF;
 qid:=p_payload->>'quote_id';digest:=p_payload->>'snapshot_sha256';mappings:=p_payload->'lines';
 IF qid !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR digest !~ '^[a-f0-9]{64}$' OR jsonb_array_length(mappings) NOT BETWEEN 2 AND 20
 THEN RAISE EXCEPTION 'QB_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-quote-v1:'||qid,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO e FROM naruv_bundle.events z WHERE z.org_id=a.org_id AND z.request_id=p_request;
 IF FOUND THEN
  IF (e.bundle_id,e.actor_id,e.action,e.payload) IS DISTINCT FROM (p_bundle,a.actor_id,'open'::text,p_payload)
  THEN RAISE EXCEPTION 'QB_CONFLICT'; END IF;
  RETURN e.receipt;
 END IF;
 s:=naruv_quote_bundle.snapshot(a.org_id,qid);
 IF digest<>encode(sha256(convert_to(s::text,'UTF8')),'hex') THEN RAISE EXCEPTION 'QB_STALE'; END IF;
 IF EXISTS(SELECT 1 FROM naruv_quote_bundle.conversions z WHERE z.org_id=a.org_id AND z.quote_id=qid)
 OR EXISTS(SELECT 1 FROM naruv_trade.documents z WHERE z.org_id=a.org_id AND z.quote_id=qid)
 OR EXISTS(SELECT 1 FROM naruv_bundle.headers z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle)
 THEN RAISE EXCEPTION 'QB_CONFLICT'; END IF;
 IF jsonb_array_length(mappings)<>jsonb_array_length(s->'lines')
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(mappings) z WHERE jsonb_typeof(z) IS DISTINCT FROM 'object'
 OR z-'quote_line_id'-'source_id'-'item_id'-'warehouse_id'<>'{}'::jsonb
 OR jsonb_typeof(z->'quote_line_id') IS DISTINCT FROM 'string' OR jsonb_typeof(z->'source_id') IS DISTINCT FROM 'string'
 OR jsonb_typeof(z->'item_id') IS DISTINCT FROM 'string' OR jsonb_typeof(z->'warehouse_id') IS DISTINCT FROM 'string')
 OR (SELECT count(DISTINCT z->>'quote_line_id') FROM jsonb_array_elements(mappings) z)<>jsonb_array_length(mappings)
 THEN RAISE EXCEPTION 'QB_INPUT'; END IF;
 INSERT INTO naruv_bundle.headers VALUES(a.org_id,p_bundle,a.actor_id,'sale',s->>'customer_id',s->>'vat_mode',clock_timestamp());
 FOR x,idx IN SELECT value,ordinality::int FROM jsonb_array_elements(s->'lines') WITH ORDINALITY LOOP
  SELECT z INTO m FROM jsonb_array_elements(mappings) z WHERE z->>'quote_line_id'=x->>'quote_line_id';
  IF NOT FOUND THEN RAISE EXCEPTION 'QB_INPUT'; END IF;
  src:=m->>'source_id';itm:=lower((m->>'item_id') COLLATE "C");wh:=m->>'warehouse_id';
  IF src !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR itm !~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' OR wh !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
  THEN RAISE EXCEPTION 'QB_INPUT'; END IF;
  IF NOT EXISTS(SELECT 1 FROM naruv_inventory.items i WHERE i.org_id=a.org_id AND i.source_id=src AND i.normalized_id=itm AND i.name=x->>'name' AND btrim(i.unit)<>'')
  THEN RAISE EXCEPTION 'QB_MAPPING'; END IF;
  PERFORM 1 FROM naruv_inventory.warehouses w WHERE w.org_id=a.org_id AND w.warehouse_id=wh AND w.active FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'QB_NOT_FOUND'; END IF;
  qty:=(x->>'quantity')::bigint;price:=(x->>'unit_price')::bigint;
  SELECT b.quantity INTO stock FROM naruv_inventory.balances b WHERE b.org_id=a.org_id AND b.source_id=src AND b.normalized_id=itm AND b.warehouse_id=wh;
  IF coalesce(stock,0)-naruv_trade.reserved(a.org_id,src,itm,wh)<qty THEN RAISE EXCEPTION 'INV_INSUFFICIENT'; END IF;
  cid:=naruv_bundle.child_id('document',p_bundle,idx);rid:=naruv_bundle.child_id('command',p_request,idx);
  INSERT INTO naruv_trade.documents(org_id,doc_id,actor_id,kind,quote_id,counterparty_id,source_id,item_id,warehouse_id,quantity,unit_price,vat_mode,fulfilled,state,created_at,quote_line_id)
  VALUES(a.org_id,cid,a.actor_id,'sale',qid,s->>'customer_id',src,itm,wh,qty,price,s->>'vat_mode',0,'OPEN',clock_timestamp(),x->>'quote_line_id') RETURNING * INTO d;
  result:=naruv_trade.snapshot(d)||jsonb_build_object('request_id',rid,'action','open','movement',NULL,'quote_line_id',x->>'quote_line_id');
  INSERT INTO naruv_trade.events(org_id,request_id,doc_id,actor_id,action,payload,movement_id,receipt,created_at) VALUES(a.org_id,rid,cid,a.actor_id,'open',m,NULL,result,clock_timestamp());
  INSERT INTO naruv_bundle.lines VALUES(a.org_id,p_bundle,idx,cid);
  out_rows:=out_rows||jsonb_build_array(jsonb_build_object('line_no',idx,'result',result));
 END LOOP;
 INSERT INTO naruv_quote_bundle.conversions VALUES(a.org_id,qid,p_bundle,a.actor_id,digest,s,clock_timestamp());
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 result:=jsonb_build_object('bundle_id',p_bundle,'request_id',p_request,'action','open','lines',out_rows,
 'quote_id',qid,'snapshot_sha256',digest,'subtotal',s->'subtotal','vat',s->'vat','total',s->'total','production_authorized',false);
 INSERT INTO naruv_bundle.events VALUES(a.org_id,p_request,p_bundle,a.actor_id,'open',p_payload,result,clock_timestamp());
 RETURN result;
END $_$;


--
-- Name: preview(text, text); Type: FUNCTION; Schema: naruv_quote_bundle; Owner: -
--

CREATE FUNCTION naruv_quote_bundle.preview(p_quote text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; s jsonb;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-quote-v1:'||p_quote,0));
 s:=naruv_quote_bundle.snapshot(a.org_id,p_quote);
 RETURN jsonb_build_object('snapshot',s,'snapshot_sha256',encode(sha256(convert_to(s::text,'UTF8')),'hex'),'production_authorized',false);
END $$;


--
-- Name: snapshot(text, text); Type: FUNCTION; Schema: naruv_quote_bundle; Owner: -
--

CREATE FUNCTION naruv_quote_bundle.snapshot(p_org text, p_quote text) RETURNS jsonb
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE q record; lines jsonb; n bigint; sub numeric; tax numeric;
BEGIN
 SELECT x.id,x.customer_id,x.status,x.vat_mode,x.updated_at,x.title,x.doc_no,x.customer_name_snapshot INTO q
 FROM jw_dev.quotes x WHERE x.org_id=p_org AND x.id=p_quote;
 IF NOT FOUND THEN RAISE EXCEPTION 'QB_NOT_FOUND'; END IF;
 IF q.status<>'draft' OR q.vat_mode NOT IN ('taxable','exempt') THEN RAISE EXCEPTION 'QB_SCOPE'; END IF;
 SELECT count(*),coalesce(sum(quantity::numeric*unit_price),0),
 jsonb_agg(jsonb_build_object('quote_line_id',id,'position',position,'name',name,'quantity',quantity,'unit_price',unit_price) ORDER BY position,id)
 INTO n,sub,lines FROM jw_dev.quote_items WHERE quote_id=p_quote;
 IF n NOT BETWEEN 2 AND 20 OR sub>2000000000000000 OR EXISTS(
 SELECT 1 FROM jw_dev.quote_items WHERE quote_id=p_quote AND (quantity NOT BETWEEN 1 AND 100000 OR unit_price NOT BETWEEN 0 AND 1000000000 OR btrim(name)=''))
 OR (SELECT count(DISTINCT position) FROM jw_dev.quote_items WHERE quote_id=p_quote)<>n
 THEN RAISE EXCEPTION 'QB_SCOPE'; END IF;
 tax:=CASE WHEN q.vat_mode='taxable' THEN floor((sub+5)/10) ELSE 0 END;
 RETURN to_jsonb(q)||jsonb_build_object('lines',lines,'subtotal',sub,'vat',tax,'total',sub+tax);
END $$;


--
-- Name: freeze(); Type: FUNCTION; Schema: naruv_quote_fence; Owner: -
--

CREATE FUNCTION naruv_quote_fence."freeze"() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE old_id text; new_id text; qid text;
BEGIN
 IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'QB_SOURCE_FROZEN'; END IF;
 IF TG_TABLE_NAME='quotes' THEN
  IF TG_OP<>'INSERT' THEN old_id:=OLD.id; END IF;
  IF TG_OP<>'DELETE' THEN new_id:=NEW.id; END IF;
 ELSE
  IF TG_OP<>'INSERT' THEN old_id:=OLD.quote_id; END IF;
  IF TG_OP<>'DELETE' THEN new_id:=NEW.quote_id; END IF;
 END IF;
 FOR qid IN SELECT DISTINCT x FROM unnest(ARRAY[old_id,new_id]) x WHERE x IS NOT NULL ORDER BY x LOOP
  PERFORM pg_advisory_xact_lock(hashtextextended('naruv-quote-v1:'||qid,0));
  IF EXISTS(SELECT 1 FROM naruv_quote_bundle.conversions c WHERE c.quote_id=qid) THEN RAISE EXCEPTION 'QB_SOURCE_FROZEN'; END IF;
 END LOOP;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;


--
-- Name: change_actor(text, boolean, text); Type: FUNCTION; Schema: naruv_sync_ci; Owner: -
--

CREATE FUNCTION naruv_sync_ci.change_actor(p_actor text, p_active boolean, p_role text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE h record; l record;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'SYNC_INPUT' USING ERRCODE='23514'; END IF;
 IF NOT naruv_hosted_identity_review.change_actor(p_actor,p_active,p_role) THEN RAISE EXCEPTION 'SYNC_CHANGE'; END IF;
 SELECT id,org_id INTO h FROM naruv_hosted_identity_review.users WHERE id=p_actor;
 SELECT id,org_id INTO l FROM jw_dev.users WHERE id=p_actor;
 IF NOT FOUND OR (h.id,h.org_id) IS DISTINCT FROM (l.id,l.org_id) THEN RAISE EXCEPTION 'SYNC_IDENTITY_DRIFT' USING ERRCODE='42501'; END IF;
 UPDATE jw_dev.users SET role=p_role WHERE id=p_actor;
 DELETE FROM jw_dev.sessions WHERE user_id=p_actor;
 IF p_active THEN DELETE FROM jw_dev.staff_disabled WHERE user_id=p_actor;
 ELSE INSERT INTO jw_dev.staff_disabled(user_id) VALUES(p_actor) ON CONFLICT DO NOTHING; END IF;
 RETURN true;
END $$;


--
-- Name: issue(text, text, text, text, integer); Type: FUNCTION; Schema: naruv_sync_ci; Owner: -
--

CREATE FUNCTION naruv_sync_ci.issue(p_id text, p_actor text, p_hash text, p_csrf text, p_ttl integer) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE h record; l record; expiry timestamptz;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR p_id IS NULL OR p_id !~ '^[A-Za-z0-9-]{1,128}$' THEN RAISE EXCEPTION 'SYNC_INPUT' USING ERRCODE='23514'; END IF;
 -- Hosted issue locks user first; legacy trigger subsequently takes native fence.
 IF NOT naruv_hosted_identity_review.issue(p_actor,p_hash,p_csrf,p_ttl) THEN RAISE EXCEPTION 'SYNC_ISSUE'; END IF;
 SELECT id,org_id,actor_role,active INTO h FROM naruv_hosted_identity_review.users WHERE id=p_actor;
 SELECT id,org_id,role INTO l FROM jw_dev.users WHERE id=p_actor;
 IF NOT FOUND OR NOT h.active OR (h.id,h.org_id,h.actor_role) IS DISTINCT FROM (l.id,l.org_id,l.role)
 OR EXISTS(SELECT 1 FROM jw_dev.staff_disabled WHERE user_id=p_actor) THEN RAISE EXCEPTION 'SYNC_IDENTITY_DRIFT' USING ERRCODE='42501'; END IF;
 SELECT expires_at INTO STRICT expiry FROM naruv_hosted_identity_review.sessions WHERE token_hash=p_hash AND actor_id=p_actor AND NOT revoked;
 INSERT INTO jw_dev.sessions(id,token_hash,user_id,expires_at,csrf_token,created_at)
 VALUES(p_id,p_hash,p_actor,expiry::text,p_csrf,clock_timestamp()::text);
 RETURN true;
END $_$;


--
-- Name: revoke(text); Type: FUNCTION; Schema: naruv_sync_ci; Owner: -
--

CREATE FUNCTION naruv_sync_ci.revoke(p_hash text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a text; n int;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR p_hash IS NULL OR p_hash !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'SYNC_INPUT' USING ERRCODE='23514'; END IF;
 SELECT actor_id INTO a FROM naruv_hosted_identity_review.sessions WHERE token_hash=p_hash;
 IF NOT FOUND THEN RAISE EXCEPTION 'SYNC_UNKNOWN' USING ERRCODE='42501'; END IF;
 IF NOT naruv_hosted_identity_review.revoke(p_hash) THEN
   IF EXISTS(SELECT 1 FROM jw_dev.sessions WHERE token_hash=p_hash) THEN RAISE EXCEPTION 'SYNC_DRIFT' USING ERRCODE='42501'; END IF;
   RETURN false;
 END IF;
 DELETE FROM jw_dev.sessions WHERE token_hash=p_hash AND user_id=a;
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n<>1 THEN RAISE EXCEPTION 'SYNC_DRIFT' USING ERRCODE='42501'; END IF;
 RETURN true;
END $_$;


--
-- Name: balance_guard(); Type: FUNCTION; Schema: naruv_trade; Owner: -
--

CREATE FUNCTION naruv_trade.balance_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
BEGIN
 IF NEW.quantity<naruv_trade.reserved(NEW.org_id,NEW.source_id,NEW.normalized_id,NEW.warehouse_id)
 THEN RAISE EXCEPTION 'INV_INSUFFICIENT'; END IF;
 RETURN NEW;
END $$;


--
-- Name: command(text, text, text, jsonb, boolean, text); Type: FUNCTION; Schema: naruv_trade; Owner: -
--

CREATE FUNCTION naruv_trade.command(p_doc text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
BEGIN
 IF left(p_doc,7)='bundle:' OR left(p_request,7)='bundle:' THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
 RETURN naruv_trade.command_bundle_internal(p_doc,p_request,p_action,p_payload,p_confirm,p_csrf);
END $$;


--
-- Name: command_bundle_internal(text, text, text, jsonb, boolean, text); Type: FUNCTION; Schema: naruv_trade; Owner: -
--

CREATE FUNCTION naruv_trade.command_bundle_internal(p_doc text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a record; a2 record; e naruv_trade.events; d naruv_trade.documents;
 kind text; qid text; cp text; src text; itm text; wh text; mode text; q bigint; price bigint;
 n bigint; stock bigint; moved jsonb; mid text; result jsonb; qt record;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_doc IS NULL OR p_doc !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_action IS NULL OR p_action NOT IN ('open','fulfill','cancel')
 OR p_confirm IS DISTINCT FROM true OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
 OR octet_length(p_payload::text)>4096 THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO e FROM naruv_trade.events x WHERE x.org_id=a.org_id AND x.request_id=p_request;
 IF FOUND THEN
  IF (e.doc_id,e.actor_id,e.action,e.payload) IS DISTINCT FROM (p_doc,a.actor_id,p_action,p_payload)
  THEN RAISE EXCEPTION 'TRADE_CONFLICT'; END IF;
  RETURN e.receipt;
 END IF;
 IF p_action='open' THEN
  kind:=p_payload->>'kind'; src:=p_payload->>'source_id'; itm:=lower((p_payload->>'item_id') COLLATE "C"); wh:=p_payload->>'warehouse_id';
  IF kind IS NULL OR kind NOT IN ('sale','purchase') OR src IS NULL OR src !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
  OR itm IS NULL OR itm !~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' OR wh IS NULL OR wh !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
  OR jsonb_typeof(p_payload->'kind') IS DISTINCT FROM 'string' OR jsonb_typeof(p_payload->'source_id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(p_payload->'item_id') IS DISTINCT FROM 'string' OR jsonb_typeof(p_payload->'warehouse_id') IS DISTINCT FROM 'string'
  THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
  PERFORM 1 FROM naruv_inventory.items i WHERE i.org_id=a.org_id AND i.source_id=src AND i.normalized_id=itm AND btrim(i.unit)<>'';
  IF NOT FOUND THEN RAISE EXCEPTION 'TRADE_NOT_FOUND'; END IF;
  PERFORM 1 FROM naruv_inventory.warehouses w WHERE w.org_id=a.org_id AND w.warehouse_id=wh AND w.active FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'TRADE_NOT_FOUND'; END IF;
  IF kind='sale' THEN
   IF p_payload-'kind'-'source_id'-'item_id'-'warehouse_id'-'quote_id'<>'{}'::jsonb
   OR jsonb_typeof(p_payload->'quote_id') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
   qid:=p_payload->>'quote_id';
   -- Only single-line V92 draft quotes in this lab; no mutation of the legacy quote.
   SELECT x.customer_id,x.vat_mode,x.status,li.name,li.quantity,li.unit_price INTO qt
   FROM jw_dev.quotes x JOIN jw_dev.quote_items li ON li.quote_id=x.id
   WHERE x.org_id=a.org_id AND x.id=qid;
   IF NOT FOUND THEN RAISE EXCEPTION 'TRADE_NOT_FOUND'; END IF;
   IF qt.status<>'draft' OR (SELECT count(*) FROM jw_dev.quote_items li WHERE li.quote_id=qid)<>1
   THEN RAISE EXCEPTION 'TRADE_QUOTE_SCOPE'; END IF;
   IF NOT EXISTS(SELECT 1 FROM naruv_inventory.items i WHERE i.org_id=a.org_id AND i.source_id=src AND i.normalized_id=itm AND i.name=qt.name)
   THEN RAISE EXCEPTION 'TRADE_QUOTE_SCOPE'; END IF;
   cp:=qt.customer_id; mode:=qt.vat_mode; q:=qt.quantity; price:=qt.unit_price;
   SELECT b.quantity INTO stock FROM naruv_inventory.balances b WHERE b.org_id=a.org_id AND b.source_id=src AND b.normalized_id=itm AND b.warehouse_id=wh;
   IF coalesce(stock,0)-naruv_trade.reserved(a.org_id,src,itm,wh)<q THEN RAISE EXCEPTION 'INV_INSUFFICIENT'; END IF;
  ELSE
   IF p_payload-'kind'-'source_id'-'item_id'-'warehouse_id'-'counterparty_id'-'quantity'-'unit_price'-'vat_mode'<>'{}'::jsonb
   OR jsonb_typeof(p_payload->'counterparty_id') IS DISTINCT FROM 'string'
   OR jsonb_typeof(p_payload->'quantity') IS DISTINCT FROM 'number' OR (p_payload->>'quantity') !~ '^[0-9]{1,6}$'
   OR jsonb_typeof(p_payload->'unit_price') IS DISTINCT FROM 'number' OR (p_payload->>'unit_price') !~ '^[0-9]{1,10}$'
   OR jsonb_typeof(p_payload->'vat_mode') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
   cp:=p_payload->>'counterparty_id'; q:=(p_payload->>'quantity')::bigint; price:=(p_payload->>'unit_price')::bigint; mode:=p_payload->>'vat_mode';
   -- Existing counterparty catalog only; supplier classification is outside this proof.
   PERFORM 1 FROM jw_dev.customers c WHERE c.org_id=a.org_id AND c.id=cp;
   IF NOT FOUND THEN RAISE EXCEPTION 'TRADE_NOT_FOUND'; END IF;
  END IF;
  IF q IS NULL OR q NOT BETWEEN 1 AND 100000 OR price IS NULL OR price NOT BETWEEN 0 AND 1000000000 OR mode IS NULL OR mode NOT IN ('taxable','exempt')
  THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
  INSERT INTO naruv_trade.documents VALUES(a.org_id,p_doc,a.actor_id,kind,qid,cp,src,itm,wh,q,price,mode,0,'OPEN',clock_timestamp()) RETURNING * INTO d;
 ELSE
  SELECT * INTO d FROM naruv_trade.documents x WHERE x.org_id=a.org_id AND x.doc_id=p_doc FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'TRADE_NOT_FOUND'; END IF;
  IF d.state NOT IN ('OPEN','PARTIAL') THEN RAISE EXCEPTION 'TRADE_TERMINAL'; END IF;
  IF p_action='cancel' THEN
   IF p_payload<>'{}'::jsonb THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
   UPDATE naruv_trade.documents x SET state='CANCELLED' WHERE x.org_id=a.org_id AND x.doc_id=p_doc RETURNING * INTO d;
  ELSE
   IF p_payload-'quantity'<>'{}'::jsonb OR jsonb_typeof(p_payload->'quantity') IS DISTINCT FROM 'number'
   OR (p_payload->>'quantity') !~ '^[0-9]{1,6}$' THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
   n:=(p_payload->>'quantity')::bigint;
   IF n<1 OR n>d.quantity-d.fulfilled THEN RAISE EXCEPTION 'TRADE_OVER_QUANTITY'; END IF;
   -- Release only the delivered portion before the stock update; same transaction.
   UPDATE naruv_trade.documents x SET fulfilled=x.fulfilled+n,state=CASE WHEN x.fulfilled+n=x.quantity THEN 'DONE' ELSE 'PARTIAL' END
    WHERE x.org_id=a.org_id AND x.doc_id=p_doc RETURNING * INTO d;
   mid:='doc:'||encode(sha256(convert_to(p_request,'UTF8')),'hex');
   moved:=naruv_inventory.post_movement_internal(d.source_id,d.item_id,mid,
     CASE WHEN d.kind='sale' THEN d.warehouse_id ELSE NULL END,
     CASE WHEN d.kind='purchase' THEN d.warehouse_id ELSE NULL END,n,p_csrf);
  END IF;
 END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 result:=naruv_trade.snapshot(d)||jsonb_build_object('request_id',p_request,'action',p_action,'movement',moved);
 INSERT INTO naruv_trade.events VALUES(a.org_id,p_request,p_doc,a.actor_id,p_action,p_payload,mid,result,clock_timestamp());
 RETURN result;
END $_$;


--
-- Name: inspect(text, text); Type: FUNCTION; Schema: naruv_trade; Owner: -
--

CREATE FUNCTION naruv_trade.inspect(p_doc text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; d naruv_trade.documents;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 SELECT * INTO d FROM naruv_trade.documents x WHERE x.org_id=a.org_id AND x.doc_id=p_doc;
 IF NOT FOUND THEN RAISE EXCEPTION 'TRADE_NOT_FOUND'; END IF;
 RETURN naruv_trade.snapshot(d);
END $$;


--
-- Name: reserved(text, text, text, text); Type: FUNCTION; Schema: naruv_trade; Owner: -
--

CREATE FUNCTION naruv_trade.reserved(p_org text, p_source text, p_item text, p_wh text) RETURNS bigint
    LANGUAGE sql
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT (
  coalesce((SELECT sum(quantity-fulfilled) FROM naruv_trade.documents d
   WHERE d.org_id=p_org AND d.source_id=p_source AND d.item_id=p_item AND d.warehouse_id=p_wh
   AND d.kind='sale' AND d.state IN ('OPEN','PARTIAL')),0)
  +coalesce((SELECT sum((o.quantity-o.completed)*c.per_unit)
   FROM naruv_production.orders o JOIN naruv_production.components c USING(org_id,bom_id)
   WHERE o.org_id=p_org AND c.source_id=p_source AND c.material_id=p_item AND o.warehouse_id=p_wh
   AND o.state IN ('OPEN','PARTIAL')),0))::bigint
$$;


--
-- Name: documents; Type: TABLE; Schema: naruv_trade; Owner: -
--

CREATE TABLE naruv_trade.documents (
    org_id text NOT NULL,
    doc_id text NOT NULL,
    actor_id text NOT NULL,
    kind text NOT NULL,
    quote_id text,
    counterparty_id text NOT NULL,
    source_id text NOT NULL,
    item_id text NOT NULL,
    warehouse_id text NOT NULL,
    quantity bigint NOT NULL,
    unit_price bigint NOT NULL,
    vat_mode text NOT NULL,
    fulfilled bigint DEFAULT 0 NOT NULL,
    state text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    quote_line_id text,
    CONSTRAINT documents_check CHECK (((fulfilled >= 0) AND (fulfilled <= quantity))),
    CONSTRAINT documents_check1 CHECK (((kind = 'sale'::text) = (quote_id IS NOT NULL))),
    CONSTRAINT documents_check2 CHECK ((((state = 'OPEN'::text) AND (fulfilled = 0)) OR ((state = 'PARTIAL'::text) AND (fulfilled > 0) AND (fulfilled < quantity)) OR ((state = 'DONE'::text) AND (fulfilled = quantity)) OR ((state = 'CANCELLED'::text) AND (fulfilled < quantity)))),
    CONSTRAINT documents_check3 CHECK (((quote_line_id IS NULL) OR ((kind = 'sale'::text) AND ("left"(doc_id, 7) = 'bundle:'::text)))),
    CONSTRAINT documents_kind_check CHECK ((kind = ANY (ARRAY['sale'::text, 'purchase'::text]))),
    CONSTRAINT documents_quantity_check CHECK (((quantity >= 1) AND (quantity <= 100000))),
    CONSTRAINT documents_state_check CHECK ((state = ANY (ARRAY['OPEN'::text, 'PARTIAL'::text, 'DONE'::text, 'CANCELLED'::text]))),
    CONSTRAINT documents_unit_price_check CHECK (((unit_price >= 0) AND (unit_price <= 1000000000))),
    CONSTRAINT documents_vat_mode_check CHECK ((vat_mode = ANY (ARRAY['taxable'::text, 'exempt'::text])))
);

ALTER TABLE ONLY naruv_trade.documents FORCE ROW LEVEL SECURITY;


--
-- Name: snapshot(naruv_trade.documents); Type: FUNCTION; Schema: naruv_trade; Owner: -
--

CREATE FUNCTION naruv_trade.snapshot(d naruv_trade.documents) RETURNS jsonb
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog'
    AS $_$
 SELECT jsonb_build_object('doc_id',($1).doc_id,'kind',($1).kind,'quote_id',($1).quote_id,
 'counterparty_id',($1).counterparty_id,'source_id',($1).source_id,'item_id',($1).item_id,'warehouse_id',($1).warehouse_id,
 'quantity',($1).quantity,'unit_price',($1).unit_price,'vat_mode',($1).vat_mode,
 'fulfilled',($1).fulfilled,'remaining',CASE WHEN ($1).state='CANCELLED' THEN 0 ELSE ($1).quantity-($1).fulfilled END,
 'state',($1).state,'subtotal',($1).quantity*($1).unit_price,
 'vat',CASE WHEN ($1).vat_mode='taxable' THEN (($1).quantity*($1).unit_price+5)/10 ELSE 0 END,
 'production_authorized',false)
$_$;


--
-- Name: apply(text, text, text, text, numeric); Type: FUNCTION; Schema: naruv_valuation; Owner: -
--

CREATE FUNCTION naruv_valuation.apply(p_org text, p_mid text, p_kind text, p_event text, p_incoming numeric) RETURNS numeric
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE m naruv_inventory.movements; b naruv_valuation.balances; amount numeric; fv numeric; tv numeric;
BEGIN
 SELECT * INTO m FROM naruv_inventory.movements z WHERE z.org_id=p_org AND z.request_id=p_mid;
 IF NOT FOUND THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 IF (p_kind IN ('opening','purchase','output','sale_return') AND (m.from_warehouse IS NOT NULL OR m.to_warehouse IS NULL OR p_incoming IS NULL))
 OR (p_kind IN ('sale','material','adjustment_issue','purchase_return') AND (m.from_warehouse IS NULL OR m.to_warehouse IS NOT NULL OR p_incoming IS NOT NULL))
 OR (p_kind='transfer' AND (m.from_warehouse IS NULL OR m.to_warehouse IS NULL OR p_incoming IS NOT NULL))
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 amount:=p_incoming;
 IF m.from_warehouse IS NOT NULL THEN
  SELECT * INTO b FROM naruv_valuation.balances z WHERE (z.org_id,z.source_id,z.item_id,z.warehouse_id)=(p_org,m.source_id,m.normalized_id,m.from_warehouse) FOR UPDATE;
  IF NOT FOUND OR b.quantity<>m.from_after+m.quantity THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  -- Whole KRW moving-average amount, final issue drains the exact remainder.
  amount:=CASE WHEN b.quantity=m.quantity THEN b.value_krw ELSE div(2*b.value_krw*m.quantity+b.quantity,2*b.quantity) END;
  fv:=b.value_krw-amount;
  UPDATE naruv_valuation.balances z SET quantity=m.from_after,value_krw=fv
   WHERE (z.org_id,z.source_id,z.item_id,z.warehouse_id)=(p_org,m.source_id,m.normalized_id,m.from_warehouse);
 END IF;
 IF amount IS NULL OR amount<0 OR amount<>trunc(amount) OR amount>1000000000000000000000 THEN RAISE EXCEPTION 'COST_CAPACITY'; END IF;
 IF m.to_warehouse IS NOT NULL THEN
  INSERT INTO naruv_valuation.balances VALUES(p_org,m.source_id,m.normalized_id,m.to_warehouse,0,0) ON CONFLICT DO NOTHING;
  SELECT * INTO STRICT b FROM naruv_valuation.balances z WHERE (z.org_id,z.source_id,z.item_id,z.warehouse_id)=(p_org,m.source_id,m.normalized_id,m.to_warehouse) FOR UPDATE;
  IF b.quantity<>m.to_after-m.quantity THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  tv:=b.value_krw+amount;
  IF tv>1000000000000000000000 THEN RAISE EXCEPTION 'COST_CAPACITY'; END IF;
  UPDATE naruv_valuation.balances z SET quantity=m.to_after,value_krw=tv
   WHERE (z.org_id,z.source_id,z.item_id,z.warehouse_id)=(p_org,m.source_id,m.normalized_id,m.to_warehouse);
 END IF;
 INSERT INTO naruv_valuation.entries VALUES(p_org,p_mid,p_kind,p_event,amount,fv,tv);
 RETURN amount;
END $$;


--
-- Name: audit_ledger(text); Type: FUNCTION; Schema: naruv_valuation; Owner: -
--

CREATE FUNCTION naruv_valuation.audit_ledger(p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; a2 record; n bigint; bill record; stock_value numeric; journal_value numeric; wip numeric;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM
 (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT count(*) INTO n FROM naruv_finance.bills b WHERE b.org_id=a.org_id;
 IF n>1000 THEN RAISE EXCEPTION 'COST_CAPACITY'; END IF;
 IF EXISTS(SELECT 1 FROM naruv_inventory.balances b LEFT JOIN naruv_valuation.balances v
 ON (b.org_id,b.source_id,b.normalized_id,b.warehouse_id)=(v.org_id,v.source_id,v.item_id,v.warehouse_id)
 WHERE b.org_id=a.org_id AND b.quantity<>coalesce(v.quantity,0))
 OR EXISTS(SELECT 1 FROM naruv_inventory.movements m LEFT JOIN naruv_valuation.entries e
 ON (m.org_id,m.request_id)=(e.org_id,e.movement_id)
 LEFT JOIN naruv_valuation.cost_journals j ON (e.org_id,e.movement_id)=(j.org_id,j.movement_id)
 WHERE m.org_id=a.org_id AND (e.movement_id IS NULL OR j.movement_id IS NULL))
 OR EXISTS(SELECT 1 FROM naruv_valuation.entries e JOIN naruv_valuation.cost_journals j USING(org_id,movement_id)
 JOIN naruv_inventory.movements m ON (m.org_id,m.request_id)=(e.org_id,e.movement_id)
 CROSS JOIN LATERAL naruv_valuation.expected_posting(e.kind,e.amount_krw) x
 WHERE e.org_id=a.org_id AND (j.debit_account,j.credit_account,j.amount_krw,j.period_start)
 IS DISTINCT FROM (x.dr,x.cr,x.amount,date_trunc('month',m.created_at AT TIME ZONE 'Asia/Seoul')::date))
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 -- Rebuild signed quantities and cost per warehouse from immutable movements.
 IF EXISTS(
  WITH signed AS (
   SELECT m.source_id,m.normalized_id,m.from_warehouse AS wh,-m.quantity::numeric AS q,-e.amount_krw AS v
    FROM naruv_inventory.movements m JOIN naruv_valuation.entries e ON (m.org_id,m.request_id)=(e.org_id,e.movement_id)
    WHERE m.org_id=a.org_id AND m.from_warehouse IS NOT NULL
   UNION ALL
   SELECT m.source_id,m.normalized_id,m.to_warehouse,m.quantity::numeric,e.amount_krw
    FROM naruv_inventory.movements m JOIN naruv_valuation.entries e ON (m.org_id,m.request_id)=(e.org_id,e.movement_id)
    WHERE m.org_id=a.org_id AND m.to_warehouse IS NOT NULL
  ), totals AS (SELECT source_id,normalized_id,wh,sum(q) AS q,sum(v) AS v FROM signed GROUP BY source_id,normalized_id,wh),
  balances AS (SELECT source_id,item_id,warehouse_id,quantity,value_krw FROM naruv_valuation.balances WHERE org_id=a.org_id)
  SELECT 1 FROM totals t FULL JOIN balances b ON (t.source_id,t.normalized_id,t.wh)=(b.source_id,b.item_id,b.warehouse_id)
  WHERE t.wh IS NULL OR b.warehouse_id IS NULL OR (t.q,t.v) IS DISTINCT FROM (b.quantity::numeric,b.value_krw)
 ) THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 SELECT coalesce(sum(value_krw),0) INTO stock_value FROM naruv_valuation.balances WHERE org_id=a.org_id;
 SELECT coalesce(sum(CASE WHEN debit_account='INVENTORY' THEN amount_krw WHEN credit_account='INVENTORY' THEN -amount_krw ELSE 0 END),0),
 coalesce(sum(CASE WHEN debit_account='WIP' THEN amount_krw WHEN credit_account='WIP' THEN -amount_krw ELSE 0 END),0)
 INTO journal_value,wip FROM naruv_valuation.cost_journals WHERE org_id=a.org_id;
 IF stock_value<>journal_value OR wip<>0 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 FOR bill IN SELECT bill_id FROM naruv_finance.bills WHERE org_id=a.org_id ORDER BY bill_id LOOP
  PERFORM naruv_valuation.reconcile_bill(bill.bill_id,p_csrf);
 END LOOP;
 RETURN jsonb_build_object('inventory_krw',stock_value::text,'journal_inventory_krw',journal_value::text,
 'wip_krw',wip::text,'bill_count',n,'status','RECONCILED','production_authorized',false,'statutory_posted',false);
END $$;


--
-- Name: check_movement(); Type: FUNCTION; Schema: naruv_valuation; Owner: -
--

CREATE FUNCTION naruv_valuation.check_movement() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE wh text; e naruv_valuation.entries;
BEGIN
 SELECT * INTO e FROM naruv_valuation.entries z WHERE z.org_id=NEW.org_id AND z.movement_id=NEW.request_id;
 IF NOT FOUND OR (e.from_value IS NULL)<>(NEW.from_warehouse IS NULL) OR (e.to_value IS NULL)<>(NEW.to_warehouse IS NULL)
 THEN RAISE EXCEPTION 'COST_UNPOSTED'; END IF;
 FOR wh IN SELECT x FROM unnest(ARRAY[NEW.from_warehouse,NEW.to_warehouse]) x WHERE x IS NOT NULL LOOP
  IF NOT EXISTS(SELECT 1 FROM naruv_inventory.balances b JOIN naruv_valuation.balances v
   ON (b.org_id,b.source_id,b.normalized_id,b.warehouse_id)=(v.org_id,v.source_id,v.item_id,v.warehouse_id)
   WHERE (b.org_id,b.source_id,b.normalized_id,b.warehouse_id)=(NEW.org_id,NEW.source_id,NEW.normalized_id,wh)
   AND b.quantity=v.quantity) THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 END LOOP;
 RETURN NULL;
END $$;


--
-- Name: expected_posting(text, numeric); Type: FUNCTION; Schema: naruv_valuation; Owner: -
--

CREATE FUNCTION naruv_valuation.expected_posting(p_kind text, p_amount numeric, OUT dr text, OUT cr text, OUT amount numeric) RETURNS record
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'pg_catalog'
    AS $$
BEGIN
 amount:=CASE WHEN p_kind='transfer' THEN 0 ELSE p_amount END;
 IF amount=0 THEN RETURN; END IF;
 dr:=CASE p_kind WHEN 'opening' THEN 'INVENTORY' WHEN 'purchase' THEN 'INVENTORY'
 WHEN 'sale' THEN 'COGS' WHEN 'adjustment_issue' THEN 'ADJUSTMENT_EXPENSE'
 WHEN 'material' THEN 'WIP' WHEN 'output' THEN 'INVENTORY' WHEN 'sale_return' THEN 'INVENTORY' WHEN 'purchase_return' THEN 'PURCHASE_CLEARING' END;
 cr:=CASE p_kind WHEN 'opening' THEN 'OPENING_EQUITY' WHEN 'purchase' THEN 'PURCHASE_CLEARING'
 WHEN 'sale' THEN 'INVENTORY' WHEN 'adjustment_issue' THEN 'INVENTORY'
 WHEN 'material' THEN 'INVENTORY' WHEN 'output' THEN 'WIP' WHEN 'sale_return' THEN 'COGS' WHEN 'purchase_return' THEN 'INVENTORY' END;
 IF dr IS NULL OR cr IS NULL THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
END $$;


--
-- Name: inspect(text, text, text, text); Type: FUNCTION; Schema: naruv_valuation; Owner: -
--

CREATE FUNCTION naruv_valuation.inspect(p_src text, p_item text, p_wh text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; r jsonb; v naruv_valuation.balances; q bigint;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 r:=naruv_inventory.read_stock(p_src,p_item,p_wh,p_csrf);q:=(r->>'quantity')::bigint;
 SELECT * INTO v FROM naruv_valuation.balances z WHERE (z.org_id,z.source_id,z.item_id,z.warehouse_id)=(a.org_id,p_src,lower(p_item COLLATE "C"),p_wh);
 IF q<>coalesce(v.quantity,0) THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 RETURN r||jsonb_build_object('value_krw',coalesce(v.value_krw,0)::text,'method','WAREHOUSE_MOVING_AVERAGE','statutory_posted',false);
END $$;


--
-- Name: overview(text); Type: FUNCTION; Schema: naruv_valuation; Owner: -
--

CREATE FUNCTION naruv_valuation.overview(p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; a2 record; proof jsonb; due_sale numeric; due_purchase numeric; paid_sale numeric; paid_purchase numeric; n_sale bigint; n_purchase bigint; n_open bigint; n_products bigint; n_wh bigint;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM
 (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 proof:=naruv_valuation.audit_ledger(p_csrf);
 SELECT count(*) FILTER(WHERE b.kind='sale'),count(*) FILTER(WHERE b.kind='purchase'),
 coalesce(sum(b.total-naruv_finance.paid(b.org_id,b.bill_id)-naruv_finance.credit_sum(b.org_id,b.bill_id)) FILTER(WHERE b.kind='sale'),0),
 coalesce(sum(b.total-naruv_finance.paid(b.org_id,b.bill_id)-naruv_finance.credit_sum(b.org_id,b.bill_id)) FILTER(WHERE b.kind='purchase'),0),
 coalesce(sum(naruv_finance.paid(b.org_id,b.bill_id)) FILTER(WHERE b.kind='sale'),0),
 coalesce(sum(naruv_finance.paid(b.org_id,b.bill_id)) FILTER(WHERE b.kind='purchase'),0)
 INTO n_sale,n_purchase,due_sale,due_purchase,paid_sale,paid_purchase
 FROM naruv_finance.bills b WHERE b.org_id=a.org_id;
 SELECT count(*) INTO n_open FROM naruv_trade.documents d WHERE d.org_id=a.org_id AND d.state IN ('OPEN','PARTIAL');
 SELECT count(*) INTO n_products FROM naruv_inventory.items i WHERE i.org_id=a.org_id;
 SELECT count(*) INTO n_wh FROM naruv_inventory.warehouses w WHERE w.org_id=a.org_id AND w.active;
 RETURN proof||jsonb_build_object('sales_bill_count',n_sale,'purchase_bill_count',n_purchase,
 'receivable_krw',due_sale::text,'payable_krw',due_purchase::text,'sale_paid_krw',paid_sale::text,'purchase_paid_krw',paid_purchase::text,
 'open_trade_count',n_open,'item_count',n_products,'active_warehouse_count',n_wh,'scope','ISOLATED_SYNTHETIC_ONLY');
END $$;


--
-- Name: post_cost_journal(); Type: FUNCTION; Schema: naruv_valuation; Owner: -
--

CREATE FUNCTION naruv_valuation.post_cost_journal() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE m naruv_inventory.movements; p naruv_accounting.periods; mon date; expected record;
BEGIN
 SELECT * INTO STRICT m FROM naruv_inventory.movements z WHERE z.org_id=NEW.org_id AND z.request_id=NEW.movement_id;
 mon:=date_trunc('month',m.created_at AT TIME ZONE 'Asia/Seoul')::date;
 SELECT * INTO p FROM naruv_accounting.periods z WHERE z.org_id=NEW.org_id AND z.period_start=mon FOR UPDATE;
 IF NOT FOUND OR p.closed_at IS NOT NULL THEN RAISE EXCEPTION 'COST_PERIOD_CLOSED'; END IF;
 SELECT * INTO expected FROM naruv_valuation.expected_posting(NEW.kind,NEW.amount_krw);
 INSERT INTO naruv_valuation.cost_journals VALUES(NEW.org_id,NEW.movement_id,mon,expected.dr,expected.cr,expected.amount);
 RETURN NEW;
END $$;


--
-- Name: production_post(); Type: FUNCTION; Schema: naruv_valuation; Owner: -
--

CREATE FUNCTION naruv_valuation.production_post() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE o naruv_production.orders; b naruv_production.boms; c naruv_production.components; m naruv_inventory.movements;
 mid text; amount numeric:=0; q bigint;
BEGIN
 IF NEW.action<>'complete' THEN RETURN NEW; END IF;
 SELECT * INTO STRICT o FROM naruv_production.orders z WHERE z.org_id=NEW.org_id AND z.order_id=NEW.order_id;
 SELECT * INTO STRICT b FROM naruv_production.boms z WHERE z.org_id=NEW.org_id AND z.bom_id=o.bom_id;
 q:=(NEW.payload->>'quantity')::bigint;
 FOR c IN SELECT * FROM naruv_production.components z WHERE z.org_id=NEW.org_id AND z.bom_id=o.bom_id ORDER BY z.material_id LOOP
  mid:='doc:'||encode(sha256(convert_to(jsonb_build_array('production',NEW.request_id,'material',c.material_id)::text,'UTF8')),'hex');
  SELECT * INTO STRICT m FROM naruv_inventory.movements z WHERE z.org_id=NEW.org_id AND z.request_id=mid;
  IF (m.source_id,m.normalized_id,m.actor_id,m.quantity,m.from_warehouse,m.to_warehouse)
   IS DISTINCT FROM (c.source_id,c.material_id,NEW.actor_id,c.per_unit*q,o.warehouse_id,NULL::text)
  THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  amount:=amount+naruv_valuation.apply(NEW.org_id,mid,'material',NEW.request_id,NULL);
 END LOOP;
 mid:='doc:'||encode(sha256(convert_to(jsonb_build_array('production',NEW.request_id,'output',b.product_id)::text,'UTF8')),'hex');
 SELECT * INTO STRICT m FROM naruv_inventory.movements z WHERE z.org_id=NEW.org_id AND z.request_id=mid;
 IF (m.source_id,m.normalized_id,m.actor_id,m.quantity,m.from_warehouse,m.to_warehouse)
  IS DISTINCT FROM (b.source_id,b.product_id,NEW.actor_id,q,NULL::text,o.warehouse_id)
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 PERFORM naruv_valuation.apply(NEW.org_id,mid,'output',NEW.request_id,amount);
 RETURN NEW;
END $$;


--
-- Name: receive(text, text, jsonb, boolean, text); Type: FUNCTION; Schema: naruv_valuation; Owner: -
--

CREATE FUNCTION naruv_valuation.receive(p_item text, p_request text, p_payload jsonb, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE a record; m naruv_inventory.movements; e naruv_valuation.entries; r jsonb; src text; wh text; mid text; q bigint; price numeric; amount numeric;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF NOT naruv_production.ident(p_item) OR NOT naruv_production.ident(p_request)
 OR p_confirm IS DISTINCT FROM true OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
 OR p_payload-'source_id'-'warehouse_id'-'quantity'-'unit_cost'<>'{}'::jsonb
 OR jsonb_typeof(p_payload->'source_id') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p_payload->'warehouse_id') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p_payload->'unit_cost') IS DISTINCT FROM 'number' OR (p_payload->>'unit_cost') !~ '^[0-9]{1,10}$'
 THEN RAISE EXCEPTION 'COST_INPUT'; END IF;
 src:=p_payload->>'source_id';wh:=p_payload->>'warehouse_id';
 IF jsonb_typeof(p_payload->'quantity') IS DISTINCT FROM 'number' OR (p_payload->>'quantity') !~ '^[0-9]{1,10}$' THEN RAISE EXCEPTION 'COST_INPUT'; END IF;
 q:=(p_payload->>'quantity')::bigint;
 IF q NOT BETWEEN 1 AND 1000000000 THEN RAISE EXCEPTION 'COST_INPUT'; END IF;
 price:=(p_payload->>'unit_cost')::numeric;
 IF NOT naruv_production.ident(src) OR NOT naruv_production.ident(wh) OR price>1000000000 THEN RAISE EXCEPTION 'COST_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 mid:='doc:'||encode(sha256(convert_to(jsonb_build_array('cost-opening',p_request)::text,'UTF8')),'hex');
 SELECT * INTO e FROM naruv_valuation.entries z WHERE z.org_id=a.org_id AND z.movement_id=mid;
 IF FOUND THEN
  SELECT * INTO STRICT m FROM naruv_inventory.movements z WHERE z.org_id=a.org_id AND z.request_id=mid;
  IF (m.actor_id,m.source_id,m.normalized_id,m.to_warehouse,m.quantity,e.kind,e.amount_krw)
   IS DISTINCT FROM (a.actor_id,src,lower(p_item COLLATE "C"),wh,q,'opening'::text,q*price)
  THEN RAISE EXCEPTION 'COST_CONFLICT'; END IF;
  r:=naruv_inventory.receipt(m);amount:=e.amount_krw;
 ELSE
  r:=naruv_inventory.post_movement_internal(src,p_item,mid,NULL,wh,q,p_csrf);
  amount:=naruv_valuation.apply(a.org_id,mid,'opening',NULL,q*price);
 END IF;
 RETURN r||jsonb_build_object('cost_krw',amount::text,'opening_request_id',p_request);
END $_$;


--
-- Name: reconcile_bill(text, text); Type: FUNCTION; Schema: naruv_valuation; Owner: -
--

CREATE FUNCTION naruv_valuation.reconcile_bill(p_bill text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; a2 record; b naruv_finance.bills; f naruv_trade.events;
 d naruv_trade.documents; m naruv_inventory.movements; e naruv_valuation.entries;
 j jsonb; cj naruv_valuation.cost_journals; clearing numeric; sales numeric; credited boolean; ce naruv_finance.events; re naruv_valuation.entries; rm naruv_inventory.movements; q bigint:=0; rq bigint; rn numeric:=0; rv numeric:=0; rc numeric:=0; en numeric; ev numeric; ec numeric; variance numeric; vs numeric:=0; rf naruv_finance.events; refund_amount bigint; refund_id text; refund_total numeric:=0; vat_balance numeric; cash_balance numeric; variance_balance numeric;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF NOT naruv_production.ident(p_bill) THEN RAISE EXCEPTION 'COST_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM
 (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO b FROM naruv_finance.bills z WHERE z.org_id=a.org_id AND z.bill_id=p_bill;
 IF NOT FOUND THEN RAISE EXCEPTION 'INV_NOT_FOUND'; END IF;
 SELECT * INTO d FROM naruv_trade.documents z WHERE z.org_id=a.org_id AND z.doc_id=b.doc_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 SELECT * INTO f FROM naruv_trade.events z WHERE z.org_id=a.org_id AND z.request_id=b.fulfillment_id AND z.doc_id=b.doc_id AND z.action='fulfill';
 IF NOT FOUND THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 SELECT * INTO m FROM naruv_inventory.movements z WHERE z.org_id=a.org_id AND z.request_id=f.movement_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 SELECT * INTO e FROM naruv_valuation.entries z WHERE z.org_id=a.org_id AND z.movement_id=m.request_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 IF (b.kind,b.quantity,b.subtotal,m.source_id,m.normalized_id,m.actor_id,e.kind,e.source_event_id)
 IS DISTINCT FROM (d.kind,m.quantity,m.quantity*d.unit_price,d.source_id,d.item_id,f.actor_id,d.kind,f.request_id)
 OR m.from_warehouse IS DISTINCT FROM (CASE WHEN d.kind='sale' THEN d.warehouse_id ELSE NULL END)
 OR m.to_warehouse IS DISTINCT FROM (CASE WHEN d.kind='purchase' THEN d.warehouse_id ELSE NULL END)
 OR (b.kind='purchase' AND e.amount_krw<>b.subtotal)
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 SELECT * INTO cj FROM naruv_valuation.cost_journals z WHERE z.org_id=a.org_id AND z.movement_id=m.request_id;
 IF NOT FOUND OR cj.amount_krw<>e.amount_krw
 OR (e.amount_krw>0 AND (cj.debit_account,cj.credit_account) IS DISTINCT FROM
 (CASE WHEN b.kind='purchase' THEN 'INVENTORY' ELSE 'COGS' END,
  CASE WHEN b.kind='purchase' THEN 'PURCHASE_CLEARING' ELSE 'INVENTORY' END))
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 j:=naruv_accounting.inspect_bill(p_bill,p_csrf);
 SELECT coalesce(sum(l.debit::numeric-l.credit) FILTER(WHERE l.account='PURCHASE_CLEARING'),0),
 coalesce(sum(l.credit::numeric-l.debit) FILTER(WHERE l.account='SALES'),0)
 INTO clearing,sales FROM naruv_accounting.lines l JOIN naruv_accounting.journals h USING(org_id,event_id)
 WHERE h.org_id=a.org_id AND h.bill_id=p_bill;
 FOR ce IN SELECT * FROM naruv_finance.events z WHERE z.org_id=a.org_id AND z.bill_id=p_bill AND z.action='credit'
 ORDER BY (z.payload->>'prior_quantity')::bigint LOOP
  rq:=(ce.payload->>'quantity')::bigint;
  IF rq IS NULL OR rq<1 OR q+rq>b.quantity OR (ce.payload->>'prior_quantity')::bigint IS DISTINCT FROM q THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  en:=naruv_finance.allocation(b.subtotal,b.quantity,q,rq);
  ev:=naruv_finance.allocation(b.vat,b.quantity,q,rq);
  ec:=naruv_finance.allocation(e.amount_krw,b.quantity,q,rq);
  SELECT * INTO re FROM naruv_valuation.entries z WHERE z.org_id=a.org_id AND z.movement_id=ce.payload->>'movement_id';
  variance:=coalesce((ce.payload->>'variance')::numeric,0);
  IF NOT FOUND OR (re.kind,re.source_event_id,re.amount_krw,ce.amount,(ce.payload->>'net')::numeric,(ce.payload->>'vat')::numeric)
   IS DISTINCT FROM (b.kind||'_return',ce.request_id,ec-variance,(en+ev)::bigint,en,ev)
   OR (b.kind='sale' AND variance<>0) THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  vs:=vs+variance;
  refund_amount:=coalesce((ce.payload->>'refund_amount')::bigint,0);refund_id:=ce.payload->>'refund_id';
  IF refund_amount>0 THEN
   SELECT * INTO rf FROM naruv_finance.events z WHERE z.org_id=a.org_id AND z.request_id=refund_id;
   IF NOT FOUND OR (rf.action,rf.bill_id,rf.actor_id,rf.amount,rf.payload->>'credit_request_id')
    IS DISTINCT FROM ('refund'::text,p_bill,ce.actor_id,refund_amount,ce.request_id) THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  ELSIF refund_id IS NOT NULL THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  refund_total:=refund_total+refund_amount;
  SELECT * INTO rm FROM naruv_inventory.movements z WHERE z.org_id=a.org_id AND z.request_id=re.movement_id;
  IF NOT FOUND OR (rm.source_id,rm.normalized_id,rm.from_warehouse,rm.to_warehouse,rm.quantity,rm.actor_id)
   IS DISTINCT FROM (m.source_id,m.normalized_id,m.to_warehouse,m.from_warehouse,rq,ce.actor_id) THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  q:=q+rq;rn:=rn+en;rv:=rv+ev;rc:=rc+ec;
 END LOOP;
 IF refund_total<>(SELECT coalesce(sum(amount),0) FROM naruv_finance.events WHERE org_id=a.org_id AND bill_id=p_bill AND action='refund')
 OR EXISTS(SELECT 1 FROM naruv_finance.events x WHERE x.org_id=a.org_id AND x.bill_id=p_bill AND x.action='refund'
 AND NOT EXISTS(SELECT 1 FROM naruv_finance.events z WHERE z.org_id=x.org_id AND z.bill_id=x.bill_id AND z.action='credit' AND z.request_id=x.payload->>'credit_request_id' AND z.payload->>'refund_id'=x.request_id))
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 SELECT coalesce(sum(CASE WHEN b.kind='sale' AND l.account='VAT_OUTPUT' THEN l.credit-l.debit WHEN b.kind='purchase' AND l.account='VAT_INPUT' THEN l.debit-l.credit ELSE 0 END),0),
 coalesce(sum(CASE WHEN l.account='CASH_CLEARING' THEN CASE WHEN b.kind='sale' THEN l.debit-l.credit ELSE l.credit-l.debit END ELSE 0 END),0),
 coalesce(sum(CASE WHEN l.account='PURCHASE_COST_VARIANCE' THEN l.credit-l.debit ELSE 0 END),0)
 INTO vat_balance,cash_balance,variance_balance FROM naruv_accounting.lines l JOIN naruv_accounting.journals h USING(org_id,event_id)
 WHERE h.org_id=a.org_id AND h.bill_id=p_bill;
 IF vat_balance<>b.vat-rv OR cash_balance<>naruv_finance.paid(a.org_id,p_bill) OR variance_balance<>vs THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 credited:=q=b.quantity;
 IF clearing<>(CASE WHEN b.kind='purchase' THEN b.subtotal-rn+vs ELSE 0 END)
 OR sales<>(CASE WHEN b.kind='sale' THEN b.subtotal-rn ELSE 0 END)
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 RETURN jsonb_build_object('bill_id',p_bill,'fulfillment_id',b.fulfillment_id,'kind',b.kind,
 'net_krw',(b.subtotal-rn)::text,'inventory_cost_krw',(e.amount_krw-rc)::text,
 'purchase_clearing_difference_krw',CASE WHEN b.kind='purchase' THEN (clearing-e.amount_krw+rc-vs)::text ELSE NULL END,
 'sales_margin_krw',CASE WHEN b.kind='sale' THEN (sales-e.amount_krw+rc)::text ELSE NULL END,
 'credited',credited,'returned_quantity',q,'purchase_cost_variance_krw',vs::text,'credited_krw',(rn+rv)::text,'outstanding_krw',j->>'outstanding','cost_journal_posted',true,'statutory_posted',false,'production_authorized',false);
END $$;


--
-- Name: return_adjusted(text, text, bigint, boolean, text, boolean, text); Type: FUNCTION; Schema: naruv_valuation; Owner: -
--

CREATE FUNCTION naruv_valuation.return_adjusted(p_bill text, p_request text, p_qty bigint, p_advanced boolean, p_ref text, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; a2 record; b naruv_finance.bills; f naruv_trade.events; m naruv_inventory.movements;
 e naruv_valuation.entries; prior naruv_finance.events; mid text; amt numeric; r jsonb; q bigint; prev bigint; net bigint; tax bigint; cost numeric; paid bigint; credit bigint; refund bigint; refund_id text; variance numeric;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF NOT naruv_production.ident(p_bill) OR NOT naruv_production.ident(p_request) OR p_confirm IS DISTINCT FROM true OR (p_qty IS NOT NULL AND p_qty NOT BETWEEN 1 AND 100000)
 OR p_advanced IS NULL OR (p_ref IS NOT NULL AND NOT naruv_production.ident(p_ref))
 THEN RAISE EXCEPTION 'COST_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM
 (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO prior FROM naruv_finance.events z WHERE z.org_id=a.org_id AND z.request_id=p_request;
 IF FOUND THEN
  IF (prior.action,prior.bill_id,prior.actor_id,(prior.payload->>'requested_quantity')::bigint,coalesce((prior.payload->>'advanced')::boolean,false),prior.payload->>'refund_reference') IS DISTINCT FROM ('credit'::text,p_bill,a.actor_id,p_qty,p_advanced,p_ref)
  THEN RAISE EXCEPTION 'COST_CONFLICT'; END IF;
  RETURN prior.receipt;
 END IF;
 SELECT * INTO b FROM naruv_finance.bills z WHERE z.org_id=a.org_id AND z.bill_id=p_bill FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'INV_NOT_FOUND'; END IF;
 prev:=naruv_finance.returned_qty(a.org_id,p_bill);q:=coalesce(p_qty,b.quantity);
 paid:=naruv_finance.paid(a.org_id,p_bill);credit:=naruv_finance.credit_sum(a.org_id,p_bill);
 IF q<1 OR prev+q>b.quantity THEN RAISE EXCEPTION 'COST_RETURN_CONFLICT'; END IF;
 net:=naruv_finance.allocation(b.subtotal,b.quantity,prev,q)::bigint;
 tax:=naruv_finance.allocation(b.vat,b.quantity,prev,q)::bigint;
 refund:=greatest(0,paid+credit+net+tax-b.total);
 IF (refund>0 AND (NOT p_advanced OR p_ref IS NULL)) OR (refund=0 AND p_ref IS NOT NULL)
 THEN RAISE EXCEPTION 'COST_RETURN_CONFLICT'; END IF;
 PERFORM naruv_valuation.reconcile_bill(p_bill,p_csrf);
 SELECT * INTO STRICT f FROM naruv_trade.events z WHERE z.org_id=a.org_id AND z.request_id=b.fulfillment_id;
 SELECT * INTO STRICT m FROM naruv_inventory.movements z WHERE z.org_id=a.org_id AND z.request_id=f.movement_id;
 SELECT * INTO STRICT e FROM naruv_valuation.entries z WHERE z.org_id=a.org_id AND z.movement_id=m.request_id;
 mid:='doc:'||encode(sha256(convert_to(jsonb_build_array('cost-return',p_request)::text,'UTF8')),'hex');
 cost:=naruv_finance.allocation(e.amount_krw,b.quantity,prev,q);
 PERFORM naruv_inventory.post_movement_internal(m.source_id,m.normalized_id,mid,m.to_warehouse,m.from_warehouse,q,p_csrf);
 amt:=naruv_valuation.apply(a.org_id,mid,b.kind||'_return',p_request,CASE WHEN b.kind='sale' THEN cost ELSE NULL END);
 variance:=cost-amt;
 IF variance<>0 AND (NOT p_advanced OR b.kind<>'purchase' OR abs(variance)>110000000000000)
 THEN RAISE EXCEPTION 'COST_RETURN_CONFLICT'; END IF;
 IF refund>0 THEN
  refund_id:='refund:'||encode(sha256(convert_to(jsonb_build_array(p_request)::text,'UTF8')),'hex');
  IF refund_id=p_request OR EXISTS(SELECT 1 FROM naruv_finance.events z WHERE z.org_id=a.org_id AND (z.request_id=refund_id OR z.payment_ref=p_ref))
  THEN RAISE EXCEPTION 'COST_CONFLICT'; END IF;
  INSERT INTO naruv_finance.events VALUES(a.org_id,refund_id,p_bill,a.actor_id,'refund',
    jsonb_build_object('credit_request_id',p_request,'reference',p_ref),refund,p_ref,NULL,
    jsonb_build_object('amount',refund,'production_authorized',false,'external_transfer_executed',false),clock_timestamp());
  paid:=paid-refund;
 END IF;
 r:=naruv_finance.snapshot(b,paid)||jsonb_build_object('credited',credit+net+tax,'outstanding',b.total-paid-credit-net-tax,
 'state',CASE WHEN prev+q=b.quantity THEN 'CREDITED' WHEN b.total-paid-credit-net-tax=0 THEN 'SETTLED' WHEN paid=0 THEN 'OPEN' ELSE 'PARTIAL' END,
 'request_id',p_request,'movement_id',mid,'returned_quantity',q,'cumulative_returned_quantity',prev+q,'returned_cost_krw',amt::text,'refund_recorded_krw',refund::text,'purchase_cost_variance_krw',variance::text,'external_transfer_executed',false,'statutory_posted',false);
 INSERT INTO naruv_finance.events VALUES(a.org_id,p_request,p_bill,a.actor_id,'credit',
 jsonb_build_object('movement_id',mid,'requested_quantity',p_qty,'prior_quantity',prev,'quantity',q,'net',net,'vat',tax,'variance',variance,'advanced',p_advanced,'refund_reference',p_ref,'refund_id',refund_id,'refund_amount',refund),
 net+tax,NULL,NULL,r,clock_timestamp());
 PERFORM naruv_valuation.reconcile_bill(p_bill,p_csrf);
 RETURN r;
END $$;


--
-- Name: return_bill(text, text, boolean, text); Type: FUNCTION; Schema: naruv_valuation; Owner: -
--

CREATE FUNCTION naruv_valuation.return_bill(p_bill text, p_request text, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT naruv_valuation.return_quantity(p_bill,p_request,NULL::bigint,p_confirm,p_csrf)
$$;


--
-- Name: return_quantity(text, text, bigint, boolean, text); Type: FUNCTION; Schema: naruv_valuation; Owner: -
--

CREATE FUNCTION naruv_valuation.return_quantity(p_bill text, p_request text, p_qty bigint, p_confirm boolean, p_csrf text) RETURNS jsonb
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT naruv_valuation.return_adjusted(p_bill,p_request,p_qty,false,NULL::text,p_confirm,p_csrf)
$$;


--
-- Name: trade_post(); Type: FUNCTION; Schema: naruv_valuation; Owner: -
--

CREATE FUNCTION naruv_valuation.trade_post() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE d naruv_trade.documents; m naruv_inventory.movements;
BEGIN
 IF NEW.action<>'fulfill' THEN RETURN NEW; END IF;
 SELECT * INTO STRICT d FROM naruv_trade.documents z WHERE z.org_id=NEW.org_id AND z.doc_id=NEW.doc_id;
 SELECT * INTO STRICT m FROM naruv_inventory.movements z WHERE z.org_id=NEW.org_id AND z.request_id=NEW.movement_id;
 IF (m.source_id,m.normalized_id,m.actor_id,m.quantity) IS DISTINCT FROM (d.source_id,d.item_id,NEW.actor_id,(NEW.payload->>'quantity')::bigint)
 OR m.from_warehouse IS DISTINCT FROM (CASE WHEN d.kind='sale' THEN d.warehouse_id ELSE NULL END)
 OR m.to_warehouse IS DISTINCT FROM (CASE WHEN d.kind='purchase' THEN d.warehouse_id ELSE NULL END)
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 PERFORM naruv_valuation.apply(NEW.org_id,m.request_id,d.kind,NEW.request_id,
  CASE WHEN d.kind='purchase' THEN m.quantity::numeric*d.unit_price ELSE NULL END);
 RETURN NEW;
END $$;


--
-- Name: validate_cost_journal(); Type: FUNCTION; Schema: naruv_valuation; Owner: -
--

CREATE FUNCTION naruv_valuation.validate_cost_journal() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE e naruv_valuation.entries; j naruv_valuation.cost_journals; m naruv_inventory.movements; expected record;
BEGIN
 SELECT * INTO STRICT e FROM naruv_valuation.entries z WHERE z.org_id=NEW.org_id AND z.movement_id=NEW.movement_id;
 SELECT * INTO j FROM naruv_valuation.cost_journals z WHERE z.org_id=NEW.org_id AND z.movement_id=NEW.movement_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'COST_JOURNAL_MISSING'; END IF;
 SELECT * INTO STRICT m FROM naruv_inventory.movements z WHERE z.org_id=e.org_id AND z.request_id=e.movement_id;
 SELECT * INTO expected FROM naruv_valuation.expected_posting(e.kind,e.amount_krw);
 IF (j.debit_account,j.credit_account,j.amount_krw,j.period_start) IS DISTINCT FROM
 (expected.dr,expected.cr,expected.amount,date_trunc('month',m.created_at AT TIME ZONE 'Asia/Seoul')::date)
 THEN RAISE EXCEPTION 'COST_JOURNAL_MISMATCH'; END IF;
 RETURN NULL;
END $$;


--
-- Name: audit_logs; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.audit_logs (
    id text NOT NULL,
    org_id text NOT NULL,
    actor_id text NOT NULL,
    entity_type text NOT NULL,
    entity_id text NOT NULL,
    action text NOT NULL,
    detail text NOT NULL,
    created_at text NOT NULL
);

ALTER TABLE ONLY jw_dev.audit_logs FORCE ROW LEVEL SECURITY;


--
-- Name: customers; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.customers (
    id text NOT NULL,
    org_id text NOT NULL,
    name text NOT NULL,
    business_number text DEFAULT ''::text NOT NULL,
    contact_name text DEFAULT ''::text NOT NULL,
    email text DEFAULT ''::text NOT NULL,
    phone text DEFAULT ''::text NOT NULL,
    created_at text NOT NULL
);

ALTER TABLE ONLY jw_dev.customers FORCE ROW LEVEL SECURITY;


--
-- Name: login_failures; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.login_failures (
    email text NOT NULL,
    attempts bigint NOT NULL,
    first_failed_at text NOT NULL
);

ALTER TABLE ONLY jw_dev.login_failures FORCE ROW LEVEL SECURITY;


--
-- Name: messenger_attachments; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.messenger_attachments (
    message_id text NOT NULL,
    filename text NOT NULL,
    mime text NOT NULL,
    data bytea NOT NULL,
    size_bytes bigint NOT NULL,
    content_hash text NOT NULL
);

ALTER TABLE ONLY jw_dev.messenger_attachments FORCE ROW LEVEL SECURITY;


--
-- Name: messenger_companies; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.messenger_companies (
    org_id text NOT NULL,
    business_number text NOT NULL,
    verified_at text,
    verification_kind text
);

ALTER TABLE ONLY jw_dev.messenger_companies FORCE ROW LEVEL SECURITY;


--
-- Name: messenger_connections; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.messenger_connections (
    id text NOT NULL,
    org_a text NOT NULL,
    org_b text NOT NULL,
    requester_org text NOT NULL,
    status text NOT NULL,
    created_at text NOT NULL,
    accepted_at text
);

ALTER TABLE ONLY jw_dev.messenger_connections FORCE ROW LEVEL SECURITY;


--
-- Name: messenger_edits; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.messenger_edits (
    id text NOT NULL,
    message_id text NOT NULL,
    previous_body text,
    new_body text,
    actor_user text,
    edited_at text NOT NULL,
    version bigint NOT NULL
);

ALTER TABLE ONLY jw_dev.messenger_edits FORCE ROW LEVEL SECURITY;


--
-- Name: messenger_messages; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.messenger_messages (
    id text NOT NULL,
    connection_id text NOT NULL,
    sender_org text NOT NULL,
    sender_user text NOT NULL,
    kind text NOT NULL,
    body text NOT NULL,
    actor_name text NOT NULL,
    request_id text NOT NULL,
    version bigint NOT NULL,
    created_at text NOT NULL,
    edited_at text,
    message_seq bigint
);

ALTER TABLE ONLY jw_dev.messenger_messages FORCE ROW LEVEL SECURITY;


--
-- Name: messenger_read_positions; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.messenger_read_positions (
    connection_id text NOT NULL,
    org_id text NOT NULL,
    last_read_rowid bigint,
    updated_at text,
    last_read_seq bigint
);

ALTER TABLE ONLY jw_dev.messenger_read_positions FORCE ROW LEVEL SECURITY;


--
-- Name: messenger_seq_v90; Type: SEQUENCE; Schema: jw_dev; Owner: -
--

CREATE SEQUENCE jw_dev.messenger_seq_v90
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mfa_credentials; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.mfa_credentials (
    user_id text NOT NULL,
    secret_encrypted text NOT NULL,
    last_counter bigint NOT NULL
);

ALTER TABLE ONLY jw_dev.mfa_credentials FORCE ROW LEVEL SECURITY;


--
-- Name: mfa_recovery_codes; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.mfa_recovery_codes (
    user_id text NOT NULL,
    code_hash text NOT NULL,
    consumed_at text
);

ALTER TABLE ONLY jw_dev.mfa_recovery_codes FORCE ROW LEVEL SECURITY;


--
-- Name: naruv_review_sources; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.naruv_review_sources (
    org_id text NOT NULL,
    source_id text NOT NULL,
    entity text NOT NULL,
    revision text NOT NULL,
    existing_ids text[] NOT NULL,
    active boolean DEFAULT true NOT NULL,
    CONSTRAINT naruv_review_sources_entity_check CHECK ((entity = ANY (ARRAY['item'::text, 'customer'::text]))),
    CONSTRAINT naruv_review_sources_existing_ids_check CHECK (((cardinality(existing_ids) <= 10000) AND (array_position(existing_ids, NULL::text) IS NULL))),
    CONSTRAINT naruv_review_sources_revision_check CHECK ((revision ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'::text)),
    CONSTRAINT naruv_review_sources_source_id_check CHECK ((source_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'::text))
);

ALTER TABLE ONLY jw_dev.naruv_review_sources FORCE ROW LEVEL SECURITY;


--
-- Name: organizations; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.organizations (
    id text NOT NULL,
    name text NOT NULL,
    created_at text NOT NULL
);

ALTER TABLE ONLY jw_dev.organizations FORCE ROW LEVEL SECURITY;


--
-- Name: quote_items; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.quote_items (
    id text NOT NULL,
    quote_id text NOT NULL,
    name text NOT NULL,
    quantity bigint NOT NULL,
    unit_price bigint NOT NULL,
    "position" bigint NOT NULL
);

ALTER TABLE ONLY jw_dev.quote_items FORCE ROW LEVEL SECURITY;


--
-- Name: quotes; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.quotes (
    id text NOT NULL,
    org_id text NOT NULL,
    customer_id text NOT NULL,
    customer_name_snapshot text NOT NULL,
    doc_no text NOT NULL,
    title text NOT NULL,
    status text NOT NULL,
    vat_mode text NOT NULL,
    created_at text NOT NULL,
    updated_at text NOT NULL,
    source_import_id text,
    source_document_meta text DEFAULT '{}'::text NOT NULL
);

ALTER TABLE ONLY jw_dev.quotes FORCE ROW LEVEL SECURITY;


--
-- Name: security_events; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.security_events (
    id text NOT NULL,
    org_id text,
    actor_id text,
    event_type text,
    created_at text
);

ALTER TABLE ONLY jw_dev.security_events FORCE ROW LEVEL SECURITY;


--
-- Name: sessions; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.sessions (
    id text NOT NULL,
    token_hash text NOT NULL,
    user_id text NOT NULL,
    expires_at text NOT NULL,
    csrf_token text NOT NULL,
    created_at text NOT NULL
);

ALTER TABLE ONLY jw_dev.sessions FORCE ROW LEVEL SECURITY;


--
-- Name: staff_disabled; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.staff_disabled (
    user_id text NOT NULL
);

ALTER TABLE ONLY jw_dev.staff_disabled FORCE ROW LEVEL SECURITY;


--
-- Name: users; Type: TABLE; Schema: jw_dev; Owner: -
--

CREATE TABLE jw_dev.users (
    id text NOT NULL,
    org_id text NOT NULL,
    email text NOT NULL,
    password_hash text NOT NULL,
    name text NOT NULL,
    role text NOT NULL,
    created_at text NOT NULL
);

ALTER TABLE ONLY jw_dev.users FORCE ROW LEVEL SECURITY;


--
-- Name: journals; Type: TABLE; Schema: naruv_accounting; Owner: -
--

CREATE TABLE naruv_accounting.journals (
    org_id text NOT NULL,
    event_id text NOT NULL,
    bill_id text NOT NULL,
    period_start date NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    posted_at timestamp with time zone NOT NULL,
    reversal_of text,
    CONSTRAINT journals_action_check CHECK ((action = ANY (ARRAY['bill'::text, 'pay'::text, 'reverse'::text, 'credit'::text, 'refund'::text]))),
    CONSTRAINT journals_check CHECK (((action = 'reverse'::text) = (reversal_of IS NOT NULL)))
);

ALTER TABLE ONLY naruv_accounting.journals FORCE ROW LEVEL SECURITY;


--
-- Name: lines; Type: TABLE; Schema: naruv_accounting; Owner: -
--

CREATE TABLE naruv_accounting.lines (
    org_id text NOT NULL,
    event_id text NOT NULL,
    line_no smallint NOT NULL,
    account text NOT NULL,
    debit bigint NOT NULL,
    credit bigint NOT NULL,
    CONSTRAINT lines_account_check CHECK ((account = ANY (ARRAY['AR'::text, 'AP'::text, 'SALES'::text, 'PURCHASE_CLEARING'::text, 'VAT_OUTPUT'::text, 'VAT_INPUT'::text, 'CASH_CLEARING'::text, 'PURCHASE_COST_VARIANCE'::text]))),
    CONSTRAINT lines_check CHECK ((((debit > 0) AND (credit = 0)) OR ((credit > 0) AND (debit = 0)))),
    CONSTRAINT lines_credit_check CHECK (((credit >= 0) AND (credit <= '110000000000000'::bigint))),
    CONSTRAINT lines_debit_check CHECK (((debit >= 0) AND (debit <= '110000000000000'::bigint))),
    CONSTRAINT lines_line_no_check CHECK (((line_no >= 1) AND (line_no <= 5)))
);

ALTER TABLE ONLY naruv_accounting.lines FORCE ROW LEVEL SECURITY;


--
-- Name: periods; Type: TABLE; Schema: naruv_accounting; Owner: -
--

CREATE TABLE naruv_accounting.periods (
    org_id text NOT NULL,
    period_start date NOT NULL,
    closed_at timestamp with time zone,
    closed_by text,
    CONSTRAINT periods_check CHECK (((closed_at IS NULL) = (closed_by IS NULL))),
    CONSTRAINT periods_period_start_check CHECK ((EXTRACT(day FROM period_start) = (1)::numeric))
);

ALTER TABLE ONLY naruv_accounting.periods FORCE ROW LEVEL SECURITY;


--
-- Name: epochs; Type: TABLE; Schema: naruv_auth_fence; Owner: -
--

CREATE TABLE naruv_auth_fence.epochs (
    actor_id text NOT NULL,
    epoch bigint NOT NULL,
    CONSTRAINT epochs_epoch_check CHECK ((epoch >= 0))
);

ALTER TABLE ONLY naruv_auth_fence.epochs FORCE ROW LEVEL SECURITY;


--
-- Name: events; Type: TABLE; Schema: naruv_bundle; Owner: -
--

CREATE TABLE naruv_bundle.events (
    org_id text NOT NULL,
    request_id text NOT NULL,
    bundle_id text NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    payload jsonb NOT NULL,
    receipt jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT events_action_check CHECK ((action = ANY (ARRAY['open'::text, 'fulfill'::text, 'cancel'::text, 'bill'::text, 'pay'::text, 'reverse'::text])))
);

ALTER TABLE ONLY naruv_bundle.events FORCE ROW LEVEL SECURITY;


--
-- Name: headers; Type: TABLE; Schema: naruv_bundle; Owner: -
--

CREATE TABLE naruv_bundle.headers (
    org_id text NOT NULL,
    bundle_id text NOT NULL,
    actor_id text NOT NULL,
    kind text NOT NULL,
    counterparty_id text NOT NULL,
    vat_mode text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT headers_kind_check CHECK ((kind = ANY (ARRAY['sale'::text, 'purchase'::text]))),
    CONSTRAINT headers_vat_mode_check CHECK ((vat_mode = ANY (ARRAY['taxable'::text, 'exempt'::text])))
);

ALTER TABLE ONLY naruv_bundle.headers FORCE ROW LEVEL SECURITY;


--
-- Name: lines; Type: TABLE; Schema: naruv_bundle; Owner: -
--

CREATE TABLE naruv_bundle.lines (
    org_id text NOT NULL,
    bundle_id text NOT NULL,
    line_no integer NOT NULL,
    doc_id text NOT NULL,
    CONSTRAINT lines_line_no_check CHECK (((line_no >= 1) AND (line_no <= 20)))
);

ALTER TABLE ONLY naruv_bundle.lines FORCE ROW LEVEL SECURITY;


--
-- Name: crosswalk; Type: TABLE; Schema: naruv_customer_bridge; Owner: -
--

CREATE TABLE naruv_customer_bridge.crosswalk (
    org_id text NOT NULL,
    source_id text NOT NULL,
    entity text NOT NULL,
    normalized_id text NOT NULL,
    source_customer_id text NOT NULL,
    customer_id text NOT NULL,
    stage_id text NOT NULL,
    CONSTRAINT crosswalk_check CHECK ((normalized_id = lower((source_customer_id COLLATE "C")))),
    CONSTRAINT crosswalk_customer_id_check CHECK ((customer_id ~ '^[a-f0-9]{32}$'::text)),
    CONSTRAINT crosswalk_entity_check CHECK ((entity = 'customer'::text))
);

ALTER TABLE ONLY naruv_customer_bridge.crosswalk FORCE ROW LEVEL SECURITY;


--
-- Name: attendance; Type: TABLE; Schema: naruv_draft; Owner: -
--

CREATE TABLE naruv_draft.attendance (
    org_id text NOT NULL,
    worker_id text NOT NULL,
    period text NOT NULL,
    work_day date NOT NULL,
    regular integer NOT NULL,
    additional integer NOT NULL,
    CONSTRAINT attendance_additional_check CHECK (((additional >= 0) AND (additional <= 1440))),
    CONSTRAINT attendance_check CHECK (((regular + additional) <= 1440)),
    CONSTRAINT attendance_check1 CHECK ((to_char((work_day)::timestamp with time zone, 'YYYY-MM'::text) = period)),
    CONSTRAINT attendance_regular_check CHECK (((regular >= 0) AND (regular <= 1440)))
);

ALTER TABLE ONLY naruv_draft.attendance FORCE ROW LEVEL SECURITY;


--
-- Name: attendance_receipts; Type: TABLE; Schema: naruv_draft; Owner: -
--

CREATE TABLE naruv_draft.attendance_receipts (
    org_id text NOT NULL,
    request_id text NOT NULL,
    actor_id text NOT NULL,
    worker_id text NOT NULL,
    period text NOT NULL,
    work_day date NOT NULL,
    regular integer NOT NULL,
    additional integer NOT NULL,
    recorded_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT attendance_receipts_additional_check CHECK (((additional >= 0) AND (additional <= 1440))),
    CONSTRAINT attendance_receipts_check CHECK (((regular + additional) <= 1440)),
    CONSTRAINT attendance_receipts_regular_check CHECK (((regular >= 0) AND (regular <= 1440)))
);

ALTER TABLE ONLY naruv_draft.attendance_receipts FORCE ROW LEVEL SECURITY;


--
-- Name: document_admissions; Type: TABLE; Schema: naruv_draft; Owner: -
--

CREATE TABLE naruv_draft.document_admissions (
    org_id text NOT NULL,
    document_id text NOT NULL,
    request_id text NOT NULL,
    actor_id text NOT NULL,
    format text NOT NULL,
    source_sha256 text NOT NULL,
    observation_sha256 text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT document_admissions_format_check CHECK ((format = ANY (ARRAY['pdf'::text, 'xlsx'::text]))),
    CONSTRAINT document_admissions_observation_sha256_check CHECK ((observation_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT document_admissions_source_sha256_check CHECK ((source_sha256 ~ '^[0-9a-f]{64}$'::text))
);

ALTER TABLE ONLY naruv_draft.document_admissions FORCE ROW LEVEL SECURITY;


--
-- Name: document_revisions; Type: TABLE; Schema: naruv_draft; Owner: -
--

CREATE TABLE naruv_draft.document_revisions (
    org_id text NOT NULL,
    document_id text NOT NULL,
    version integer NOT NULL,
    request_id text NOT NULL,
    previous_revision text NOT NULL,
    actor_id text NOT NULL,
    source_sha256 text NOT NULL,
    previous_sha256 text NOT NULL,
    observation_sha256 text NOT NULL,
    observations jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT document_revisions_observation_sha256_check CHECK ((observation_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT document_revisions_observations_check CHECK (((jsonb_typeof(observations) = 'array'::text) AND (octet_length((observations)::text) <= 32768))),
    CONSTRAINT document_revisions_previous_sha256_check CHECK ((previous_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT document_revisions_source_sha256_check CHECK ((source_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT document_revisions_version_check CHECK (((version >= 1) AND (version <= 32)))
);

ALTER TABLE ONLY naruv_draft.document_revisions FORCE ROW LEVEL SECURITY;


--
-- Name: documents; Type: TABLE; Schema: naruv_draft; Owner: -
--

CREATE TABLE naruv_draft.documents (
    org_id text NOT NULL,
    document_id text NOT NULL,
    revision text NOT NULL,
    original_bytes bytea NOT NULL,
    original_sha256 text NOT NULL,
    observations jsonb NOT NULL,
    active boolean NOT NULL,
    CONSTRAINT documents_observations_check CHECK (((jsonb_typeof(observations) = 'array'::text) AND (octet_length((observations)::text) <= 32768))),
    CONSTRAINT documents_original_bytes_check CHECK (((octet_length(original_bytes) >= 1) AND (octet_length(original_bytes) <= 1048576))),
    CONSTRAINT documents_original_sha256_check CHECK ((original_sha256 ~ '^[0-9a-f]{64}$'::text))
);

ALTER TABLE ONLY naruv_draft.documents FORCE ROW LEVEL SECURITY;


--
-- Name: pay_periods; Type: TABLE; Schema: naruv_draft; Owner: -
--

CREATE TABLE naruv_draft.pay_periods (
    org_id text NOT NULL,
    worker_id text NOT NULL,
    period text NOT NULL,
    revision text NOT NULL,
    hourly_krw bigint NOT NULL,
    additional_bps integer NOT NULL,
    confirmed boolean NOT NULL,
    CONSTRAINT pay_periods_additional_bps_check CHECK (((additional_bps >= 1) AND (additional_bps <= 50000))),
    CONSTRAINT pay_periods_hourly_krw_check CHECK (((hourly_krw >= 1) AND (hourly_krw <= 100000000)))
);

ALTER TABLE ONLY naruv_draft.pay_periods FORCE ROW LEVEL SECURITY;


--
-- Name: period_amendments; Type: TABLE; Schema: naruv_draft; Owner: -
--

CREATE TABLE naruv_draft.period_amendments (
    org_id text NOT NULL,
    request_id text NOT NULL,
    actor_id text NOT NULL,
    worker_id text NOT NULL,
    period text NOT NULL,
    kind text NOT NULL,
    expected_sha256 text NOT NULL,
    input jsonb NOT NULL,
    before_values jsonb NOT NULL,
    after_values jsonb NOT NULL,
    receipt jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT period_amendments_expected_sha256_check CHECK ((expected_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT period_amendments_kind_check CHECK ((kind = ANY (ARRAY['attendance'::text, 'policy'::text])))
);

ALTER TABLE ONLY naruv_draft.period_amendments FORCE ROW LEVEL SECURITY;


--
-- Name: period_confirmations; Type: TABLE; Schema: naruv_draft; Owner: -
--

CREATE TABLE naruv_draft.period_confirmations (
    org_id text NOT NULL,
    worker_id text NOT NULL,
    period text NOT NULL,
    request_id text NOT NULL,
    actor_id text NOT NULL,
    review_sha256 text NOT NULL,
    confirmed_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT period_confirmations_review_sha256_check CHECK ((review_sha256 ~ '^[0-9a-f]{64}$'::text))
);

ALTER TABLE ONLY naruv_draft.period_confirmations FORCE ROW LEVEL SECURITY;


--
-- Name: profile_envelopes; Type: TABLE; Schema: naruv_draft; Owner: -
--

CREATE TABLE naruv_draft.profile_envelopes (
    org_id text NOT NULL,
    worker_id text NOT NULL,
    revision text NOT NULL,
    actor_id text NOT NULL,
    envelope jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT profile_envelopes_envelope_check CHECK (((jsonb_typeof(envelope) = 'object'::text) AND (octet_length((envelope)::text) <= 5000)))
);

ALTER TABLE ONLY naruv_draft.profile_envelopes FORCE ROW LEVEL SECURITY;


--
-- Name: profile_retention; Type: TABLE; Schema: naruv_draft; Owner: -
--

CREATE TABLE naruv_draft.profile_retention (
    org_id text NOT NULL,
    worker_id text NOT NULL,
    eligible_at timestamp with time zone NOT NULL,
    legal_hold boolean NOT NULL,
    approval_sha256 text NOT NULL,
    purged_at timestamp with time zone,
    CONSTRAINT profile_retention_approval_sha256_check CHECK ((approval_sha256 ~ '^[0-9a-f]{64}$'::text))
);

ALTER TABLE ONLY naruv_draft.profile_retention FORCE ROW LEVEL SECURITY;


--
-- Name: profile_revision_history; Type: TABLE; Schema: naruv_draft; Owner: -
--

CREATE TABLE naruv_draft.profile_revision_history (
    org_id text NOT NULL,
    worker_id text NOT NULL,
    revision text NOT NULL,
    previous_revision text,
    actor_id text NOT NULL,
    recorded_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL
);

ALTER TABLE ONLY naruv_draft.profile_revision_history FORCE ROW LEVEL SECURITY;


--
-- Name: setup_receipts; Type: TABLE; Schema: naruv_draft; Owner: -
--

CREATE TABLE naruv_draft.setup_receipts (
    org_id text NOT NULL,
    request_id text NOT NULL,
    actor_id text NOT NULL,
    worker_id text NOT NULL,
    kind text NOT NULL,
    period text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT setup_receipts_check CHECK ((((kind = 'staff'::text) AND (period = ''::text)) OR ((kind = 'period'::text) AND (period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'::text)))),
    CONSTRAINT setup_receipts_kind_check CHECK ((kind = ANY (ARRAY['staff'::text, 'period'::text]))),
    CONSTRAINT setup_receipts_payload_check CHECK ((jsonb_typeof(payload) = 'object'::text))
);

ALTER TABLE ONLY naruv_draft.setup_receipts FORCE ROW LEVEL SECURITY;


--
-- Name: staff; Type: TABLE; Schema: naruv_draft; Owner: -
--

CREATE TABLE naruv_draft.staff (
    org_id text NOT NULL,
    worker_id text NOT NULL,
    active boolean NOT NULL
);

ALTER TABLE ONLY naruv_draft.staff FORCE ROW LEVEL SECURITY;


--
-- Name: staff_archivals; Type: TABLE; Schema: naruv_draft; Owner: -
--

CREATE TABLE naruv_draft.staff_archivals (
    org_id text NOT NULL,
    worker_id text NOT NULL,
    request_id text NOT NULL,
    actor_id text NOT NULL,
    archived_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL
);

ALTER TABLE ONLY naruv_draft.staff_archivals FORCE ROW LEVEL SECURITY;


--
-- Name: statement_review_receipts; Type: TABLE; Schema: naruv_draft; Owner: -
--

CREATE TABLE naruv_draft.statement_review_receipts (
    org_id text NOT NULL,
    request_id text NOT NULL,
    actor_id text NOT NULL,
    worker_id text NOT NULL,
    period text NOT NULL,
    review_sha256 text NOT NULL,
    statement_sha256 text NOT NULL,
    render_sha256 text NOT NULL,
    recorded_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT statement_review_receipts_render_sha256_check CHECK ((render_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT statement_review_receipts_review_sha256_check CHECK ((review_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT statement_review_receipts_statement_sha256_check CHECK ((statement_sha256 ~ '^[0-9a-f]{64}$'::text))
);

ALTER TABLE ONLY naruv_draft.statement_review_receipts FORCE ROW LEVEL SECURITY;


--
-- Name: events; Type: TABLE; Schema: naruv_finance; Owner: -
--

CREATE TABLE naruv_finance.events (
    org_id text NOT NULL,
    request_id text NOT NULL,
    bill_id text NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    payload jsonb NOT NULL,
    amount bigint NOT NULL,
    payment_ref text,
    reversal_of text,
    receipt jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT events_action_check CHECK ((action = ANY (ARRAY['bill'::text, 'pay'::text, 'reverse'::text, 'credit'::text, 'refund'::text]))),
    CONSTRAINT events_amount_check CHECK (((amount >= 0) AND (amount <= '110000000000000'::bigint))),
    CONSTRAINT events_check CHECK (((action = ANY (ARRAY['pay'::text, 'refund'::text])) = (payment_ref IS NOT NULL))),
    CONSTRAINT events_check1 CHECK (((action = 'reverse'::text) = (reversal_of IS NOT NULL))),
    CONSTRAINT events_check2 CHECK ((((action = 'bill'::text) AND (amount = 0)) OR ((action = ANY (ARRAY['pay'::text, 'reverse'::text, 'refund'::text])) AND (amount > 0)) OR (action = 'credit'::text)))
);

ALTER TABLE ONLY naruv_finance.events FORCE ROW LEVEL SECURITY;


--
-- Name: organizations; Type: TABLE; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE TABLE naruv_hosted_identity_review.organizations (
    id text NOT NULL,
    name text NOT NULL
);

ALTER TABLE ONLY naruv_hosted_identity_review.organizations FORCE ROW LEVEL SECURITY;


--
-- Name: sessions; Type: TABLE; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE TABLE naruv_hosted_identity_review.sessions (
    token_hash text NOT NULL,
    actor_id text NOT NULL,
    epoch bigint NOT NULL,
    csrf_token text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked boolean DEFAULT false NOT NULL,
    CONSTRAINT sessions_csrf_token_check CHECK (((length(csrf_token) >= 32) AND (length(csrf_token) <= 256))),
    CONSTRAINT sessions_token_hash_check CHECK ((token_hash ~ '^[0-9a-f]{64}$'::text))
);

ALTER TABLE ONLY naruv_hosted_identity_review.sessions FORCE ROW LEVEL SECURITY;


--
-- Name: users; Type: TABLE; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE TABLE naruv_hosted_identity_review.users (
    id text NOT NULL,
    org_id text NOT NULL,
    actor_role text NOT NULL,
    active boolean NOT NULL,
    epoch bigint DEFAULT 0 NOT NULL,
    CONSTRAINT users_actor_role_check CHECK ((actor_role = ANY (ARRAY['admin'::text, 'member'::text]))),
    CONSTRAINT users_epoch_check CHECK ((epoch >= 0))
);

ALTER TABLE ONLY naruv_hosted_identity_review.users FORCE ROW LEVEL SECURITY;


--
-- Name: balances; Type: TABLE; Schema: naruv_inventory; Owner: -
--

CREATE TABLE naruv_inventory.balances (
    org_id text NOT NULL,
    source_id text NOT NULL,
    normalized_id text NOT NULL,
    warehouse_id text NOT NULL,
    quantity bigint NOT NULL,
    CONSTRAINT balances_quantity_check CHECK (((quantity >= 0) AND (quantity <= '1000000000000'::bigint)))
);

ALTER TABLE ONLY naruv_inventory.balances FORCE ROW LEVEL SECURITY;


--
-- Name: items; Type: TABLE; Schema: naruv_inventory; Owner: -
--

CREATE TABLE naruv_inventory.items (
    org_id text NOT NULL,
    source_id text NOT NULL,
    normalized_id text NOT NULL,
    entity text DEFAULT 'item'::text NOT NULL,
    source_item_id text NOT NULL,
    name text NOT NULL,
    unit text NOT NULL,
    CONSTRAINT items_check CHECK ((normalized_id = lower((source_item_id COLLATE "C")))),
    CONSTRAINT items_entity_check CHECK ((entity = 'item'::text))
);

ALTER TABLE ONLY naruv_inventory.items FORCE ROW LEVEL SECURITY;


--
-- Name: warehouses; Type: TABLE; Schema: naruv_inventory; Owner: -
--

CREATE TABLE naruv_inventory.warehouses (
    org_id text NOT NULL,
    warehouse_id text NOT NULL,
    name text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    CONSTRAINT warehouses_warehouse_id_check CHECK ((warehouse_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'::text))
);

ALTER TABLE ONLY naruv_inventory.warehouses FORCE ROW LEVEL SECURITY;


--
-- Name: approvals; Type: TABLE; Schema: naruv_native_review; Owner: -
--

CREATE TABLE naruv_native_review.approvals (
    org_id text NOT NULL,
    stage_id text NOT NULL,
    actor_id text NOT NULL,
    stage_sha256 text NOT NULL,
    canonical_sha256 text NOT NULL,
    snapshot_sha256 text NOT NULL,
    status text NOT NULL,
    approved_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT approvals_canonical_sha256_check CHECK ((canonical_sha256 ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT approvals_check CHECK ((expires_at > approved_at)),
    CONSTRAINT approvals_snapshot_sha256_check CHECK ((snapshot_sha256 ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT approvals_stage_sha256_check CHECK ((stage_sha256 ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT approvals_status_check CHECK ((status = ANY (ARRAY['APPROVED'::text, 'REVOKED'::text, 'COMMITTED'::text])))
);

ALTER TABLE ONLY naruv_native_review.approvals FORCE ROW LEVEL SECURITY;


--
-- Name: records; Type: TABLE; Schema: naruv_native_review; Owner: -
--

CREATE TABLE naruv_native_review.records (
    org_id text NOT NULL,
    source_id text NOT NULL,
    entity text NOT NULL,
    source_record_id text NOT NULL,
    normalized_id text GENERATED ALWAYS AS (lower((source_record_id COLLATE "C"))) STORED NOT NULL,
    stage_id text NOT NULL,
    data jsonb NOT NULL,
    CONSTRAINT records_data_check CHECK ((jsonb_typeof(data) = 'object'::text)),
    CONSTRAINT records_entity_check CHECK ((entity = ANY (ARRAY['item'::text, 'customer'::text]))),
    CONSTRAINT records_source_record_id_check CHECK ((source_record_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'::text))
);

ALTER TABLE ONLY naruv_native_review.records FORCE ROW LEVEL SECURITY;


--
-- Name: stages; Type: TABLE; Schema: naruv_native_review; Owner: -
--

CREATE TABLE naruv_native_review.stages (
    org_id text NOT NULL,
    stage_id text NOT NULL,
    actor_id text NOT NULL,
    session_binding_sha256 text NOT NULL,
    auth_epoch bigint NOT NULL,
    source_id text NOT NULL,
    entity text NOT NULL,
    file_format text NOT NULL,
    raw_sha256 text NOT NULL,
    byte_count integer NOT NULL,
    stage_sha256 text NOT NULL,
    canonical_sha256 text NOT NULL,
    rows_sha256 text NOT NULL,
    snapshot_sha256 text NOT NULL,
    expected_revision text NOT NULL,
    expected_ids text[] NOT NULL,
    rows_canonical text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT stages_auth_epoch_check CHECK ((auth_epoch >= 0)),
    CONSTRAINT stages_byte_count_check CHECK (((byte_count >= 1) AND (byte_count <= 1048576))),
    CONSTRAINT stages_canonical_sha256_check CHECK ((canonical_sha256 ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT stages_check CHECK (((octet_length(rows_canonical) <= 2097152) AND (canonical_sha256 = encode(sha256(convert_to(rows_canonical, 'UTF8'::name)), 'hex'::text)) AND (jsonb_typeof((rows_canonical)::jsonb) = 'array'::text) AND ((jsonb_array_length((rows_canonical)::jsonb) >= 1) AND (jsonb_array_length((rows_canonical)::jsonb) <= 1000)))),
    CONSTRAINT stages_check1 CHECK ((expires_at > created_at)),
    CONSTRAINT stages_entity_check CHECK ((entity = ANY (ARRAY['item'::text, 'customer'::text]))),
    CONSTRAINT stages_expected_ids_check CHECK ((cardinality(expected_ids) <= 10000)),
    CONSTRAINT stages_file_format_check CHECK ((file_format = ANY (ARRAY['csv'::text, 'xlsx'::text]))),
    CONSTRAINT stages_raw_sha256_check CHECK ((raw_sha256 ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT stages_rows_sha256_check CHECK ((rows_sha256 ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT stages_session_binding_sha256_check CHECK ((session_binding_sha256 ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT stages_snapshot_sha256_check CHECK ((snapshot_sha256 ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT stages_stage_id_check CHECK ((stage_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'::text)),
    CONSTRAINT stages_stage_sha256_check CHECK ((stage_sha256 ~ '^[a-f0-9]{64}$'::text))
);

ALTER TABLE ONLY naruv_native_review.stages FORCE ROW LEVEL SECURITY;


--
-- Name: boms; Type: TABLE; Schema: naruv_production; Owner: -
--

CREATE TABLE naruv_production.boms (
    org_id text NOT NULL,
    bom_id text NOT NULL,
    source_id text NOT NULL,
    product_id text NOT NULL,
    actor_id text NOT NULL,
    created_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY naruv_production.boms FORCE ROW LEVEL SECURITY;


--
-- Name: components; Type: TABLE; Schema: naruv_production; Owner: -
--

CREATE TABLE naruv_production.components (
    org_id text NOT NULL,
    bom_id text NOT NULL,
    source_id text NOT NULL,
    material_id text NOT NULL,
    per_unit bigint NOT NULL,
    CONSTRAINT components_per_unit_check CHECK (((per_unit >= 1) AND (per_unit <= 10000)))
);

ALTER TABLE ONLY naruv_production.components FORCE ROW LEVEL SECURITY;


--
-- Name: events; Type: TABLE; Schema: naruv_production; Owner: -
--

CREATE TABLE naruv_production.events (
    org_id text NOT NULL,
    request_id text NOT NULL,
    bom_id text NOT NULL,
    order_id text,
    actor_id text NOT NULL,
    action text NOT NULL,
    payload jsonb NOT NULL,
    receipt jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT events_action_check CHECK ((action = ANY (ARRAY['define'::text, 'open'::text, 'complete'::text, 'cancel'::text]))),
    CONSTRAINT events_check CHECK (((action = 'define'::text) = (order_id IS NULL)))
);

ALTER TABLE ONLY naruv_production.events FORCE ROW LEVEL SECURITY;


--
-- Name: conversions; Type: TABLE; Schema: naruv_quote_bundle; Owner: -
--

CREATE TABLE naruv_quote_bundle.conversions (
    org_id text NOT NULL,
    quote_id text NOT NULL,
    bundle_id text NOT NULL,
    actor_id text NOT NULL,
    snapshot_sha256 text NOT NULL,
    snapshot jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT conversions_snapshot_sha256_check CHECK ((snapshot_sha256 ~ '^[a-f0-9]{64}$'::text))
);

ALTER TABLE ONLY naruv_quote_bundle.conversions FORCE ROW LEVEL SECURITY;


--
-- Name: events; Type: TABLE; Schema: naruv_trade; Owner: -
--

CREATE TABLE naruv_trade.events (
    org_id text NOT NULL,
    request_id text NOT NULL,
    doc_id text NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    payload jsonb NOT NULL,
    movement_id text,
    receipt jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT events_action_check CHECK ((action = ANY (ARRAY['open'::text, 'fulfill'::text, 'cancel'::text]))),
    CONSTRAINT events_check CHECK (((action = 'fulfill'::text) = (movement_id IS NOT NULL)))
);

ALTER TABLE ONLY naruv_trade.events FORCE ROW LEVEL SECURITY;


--
-- Name: balances; Type: TABLE; Schema: naruv_valuation; Owner: -
--

CREATE TABLE naruv_valuation.balances (
    org_id text NOT NULL,
    source_id text NOT NULL,
    item_id text NOT NULL,
    warehouse_id text NOT NULL,
    quantity bigint NOT NULL,
    value_krw numeric(24,0) NOT NULL,
    CONSTRAINT balances_check CHECK (((quantity <> 0) OR (value_krw = (0)::numeric))),
    CONSTRAINT balances_quantity_check CHECK (((quantity >= 0) AND (quantity <= '1000000000000'::bigint))),
    CONSTRAINT balances_value_krw_check CHECK (((value_krw >= (0)::numeric) AND (value_krw <= '1000000000000000000000'::numeric)))
);

ALTER TABLE ONLY naruv_valuation.balances FORCE ROW LEVEL SECURITY;


--
-- Name: cost_journals; Type: TABLE; Schema: naruv_valuation; Owner: -
--

CREATE TABLE naruv_valuation.cost_journals (
    org_id text NOT NULL,
    movement_id text NOT NULL,
    period_start date NOT NULL,
    debit_account text,
    credit_account text,
    amount_krw numeric(24,0) NOT NULL,
    CONSTRAINT cost_journals_amount_krw_check CHECK (((amount_krw >= (0)::numeric) AND (amount_krw <= '1000000000000000000000'::numeric))),
    CONSTRAINT cost_journals_check CHECK ((((amount_krw = (0)::numeric) AND (debit_account IS NULL) AND (credit_account IS NULL)) OR ((amount_krw > (0)::numeric) AND (debit_account IS NOT NULL) AND (credit_account IS NOT NULL) AND (debit_account <> credit_account)))),
    CONSTRAINT cost_journals_credit_account_check CHECK ((credit_account = ANY (ARRAY['INVENTORY'::text, 'PURCHASE_CLEARING'::text, 'WIP'::text, 'OPENING_EQUITY'::text, 'COGS'::text]))),
    CONSTRAINT cost_journals_debit_account_check CHECK ((debit_account = ANY (ARRAY['INVENTORY'::text, 'COGS'::text, 'WIP'::text, 'ADJUSTMENT_EXPENSE'::text, 'PURCHASE_CLEARING'::text])))
);

ALTER TABLE ONLY naruv_valuation.cost_journals FORCE ROW LEVEL SECURITY;


--
-- Name: entries; Type: TABLE; Schema: naruv_valuation; Owner: -
--

CREATE TABLE naruv_valuation.entries (
    org_id text NOT NULL,
    movement_id text NOT NULL,
    kind text NOT NULL,
    source_event_id text,
    amount_krw numeric(24,0) NOT NULL,
    from_value numeric(24,0),
    to_value numeric(24,0),
    CONSTRAINT entries_amount_krw_check CHECK (((amount_krw >= (0)::numeric) AND (amount_krw <= '1000000000000000000000'::numeric))),
    CONSTRAINT entries_check CHECK (((kind = ANY (ARRAY['purchase'::text, 'sale'::text, 'material'::text, 'output'::text, 'sale_return'::text, 'purchase_return'::text])) = (source_event_id IS NOT NULL))),
    CONSTRAINT entries_from_value_check CHECK (((from_value >= (0)::numeric) AND (from_value <= '1000000000000000000000'::numeric))),
    CONSTRAINT entries_kind_check CHECK ((kind = ANY (ARRAY['opening'::text, 'purchase'::text, 'sale'::text, 'transfer'::text, 'adjustment_issue'::text, 'material'::text, 'output'::text, 'sale_return'::text, 'purchase_return'::text]))),
    CONSTRAINT entries_to_value_check CHECK (((to_value >= (0)::numeric) AND (to_value <= '1000000000000000000000'::numeric)))
);

ALTER TABLE ONLY naruv_valuation.entries FORCE ROW LEVEL SECURITY;


--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);


--
-- Name: customers customers_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.customers
    ADD CONSTRAINT customers_pkey PRIMARY KEY (id);


--
-- Name: login_failures login_failures_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.login_failures
    ADD CONSTRAINT login_failures_pkey PRIMARY KEY (email);


--
-- Name: messenger_attachments messenger_attachments_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.messenger_attachments
    ADD CONSTRAINT messenger_attachments_pkey PRIMARY KEY (message_id);


--
-- Name: messenger_companies messenger_companies_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.messenger_companies
    ADD CONSTRAINT messenger_companies_pkey PRIMARY KEY (org_id);


--
-- Name: messenger_connections messenger_connections_org_a_org_b_key; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.messenger_connections
    ADD CONSTRAINT messenger_connections_org_a_org_b_key UNIQUE (org_a, org_b);


--
-- Name: messenger_connections messenger_connections_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.messenger_connections
    ADD CONSTRAINT messenger_connections_pkey PRIMARY KEY (id);


--
-- Name: messenger_edits messenger_edits_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.messenger_edits
    ADD CONSTRAINT messenger_edits_pkey PRIMARY KEY (id);


--
-- Name: messenger_messages messenger_messages_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.messenger_messages
    ADD CONSTRAINT messenger_messages_pkey PRIMARY KEY (id);


--
-- Name: messenger_messages messenger_messages_sender_org_request_id_key; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.messenger_messages
    ADD CONSTRAINT messenger_messages_sender_org_request_id_key UNIQUE (sender_org, request_id);


--
-- Name: messenger_read_positions messenger_read_positions_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.messenger_read_positions
    ADD CONSTRAINT messenger_read_positions_pkey PRIMARY KEY (connection_id, org_id);


--
-- Name: mfa_credentials mfa_credentials_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.mfa_credentials
    ADD CONSTRAINT mfa_credentials_pkey PRIMARY KEY (user_id);


--
-- Name: mfa_recovery_codes mfa_recovery_codes_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.mfa_recovery_codes
    ADD CONSTRAINT mfa_recovery_codes_pkey PRIMARY KEY (user_id, code_hash);


--
-- Name: naruv_review_sources naruv_review_sources_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.naruv_review_sources
    ADD CONSTRAINT naruv_review_sources_pkey PRIMARY KEY (org_id, source_id, entity);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: quote_items quote_items_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.quote_items
    ADD CONSTRAINT quote_items_pkey PRIMARY KEY (id);


--
-- Name: quotes quotes_org_id_doc_no_key; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.quotes
    ADD CONSTRAINT quotes_org_id_doc_no_key UNIQUE (org_id, doc_no);


--
-- Name: quotes quotes_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.quotes
    ADD CONSTRAINT quotes_pkey PRIMARY KEY (id);


--
-- Name: quotes quotes_source_import_id_key; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.quotes
    ADD CONSTRAINT quotes_source_import_id_key UNIQUE (source_import_id);


--
-- Name: security_events security_events_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.security_events
    ADD CONSTRAINT security_events_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_token_hash_key; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.sessions
    ADD CONSTRAINT sessions_token_hash_key UNIQUE (token_hash);


--
-- Name: staff_disabled staff_disabled_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.staff_disabled
    ADD CONSTRAINT staff_disabled_pkey PRIMARY KEY (user_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: journals journals_org_id_reversal_of_key; Type: CONSTRAINT; Schema: naruv_accounting; Owner: -
--

ALTER TABLE ONLY naruv_accounting.journals
    ADD CONSTRAINT journals_org_id_reversal_of_key UNIQUE (org_id, reversal_of);


--
-- Name: journals journals_pkey; Type: CONSTRAINT; Schema: naruv_accounting; Owner: -
--

ALTER TABLE ONLY naruv_accounting.journals
    ADD CONSTRAINT journals_pkey PRIMARY KEY (org_id, event_id);


--
-- Name: lines lines_pkey; Type: CONSTRAINT; Schema: naruv_accounting; Owner: -
--

ALTER TABLE ONLY naruv_accounting.lines
    ADD CONSTRAINT lines_pkey PRIMARY KEY (org_id, event_id, line_no);


--
-- Name: periods periods_pkey; Type: CONSTRAINT; Schema: naruv_accounting; Owner: -
--

ALTER TABLE ONLY naruv_accounting.periods
    ADD CONSTRAINT periods_pkey PRIMARY KEY (org_id, period_start);


--
-- Name: epochs epochs_pkey; Type: CONSTRAINT; Schema: naruv_auth_fence; Owner: -
--

ALTER TABLE ONLY naruv_auth_fence.epochs
    ADD CONSTRAINT epochs_pkey PRIMARY KEY (actor_id);


--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: naruv_bundle; Owner: -
--

ALTER TABLE ONLY naruv_bundle.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (org_id, request_id);


--
-- Name: headers headers_pkey; Type: CONSTRAINT; Schema: naruv_bundle; Owner: -
--

ALTER TABLE ONLY naruv_bundle.headers
    ADD CONSTRAINT headers_pkey PRIMARY KEY (org_id, bundle_id);


--
-- Name: lines lines_org_id_doc_id_key; Type: CONSTRAINT; Schema: naruv_bundle; Owner: -
--

ALTER TABLE ONLY naruv_bundle.lines
    ADD CONSTRAINT lines_org_id_doc_id_key UNIQUE (org_id, doc_id);


--
-- Name: lines lines_pkey; Type: CONSTRAINT; Schema: naruv_bundle; Owner: -
--

ALTER TABLE ONLY naruv_bundle.lines
    ADD CONSTRAINT lines_pkey PRIMARY KEY (org_id, bundle_id, line_no);


--
-- Name: crosswalk crosswalk_org_id_customer_id_key; Type: CONSTRAINT; Schema: naruv_customer_bridge; Owner: -
--

ALTER TABLE ONLY naruv_customer_bridge.crosswalk
    ADD CONSTRAINT crosswalk_org_id_customer_id_key UNIQUE (org_id, customer_id);


--
-- Name: crosswalk crosswalk_pkey; Type: CONSTRAINT; Schema: naruv_customer_bridge; Owner: -
--

ALTER TABLE ONLY naruv_customer_bridge.crosswalk
    ADD CONSTRAINT crosswalk_pkey PRIMARY KEY (org_id, source_id, normalized_id);


--
-- Name: attendance attendance_pkey; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.attendance
    ADD CONSTRAINT attendance_pkey PRIMARY KEY (org_id, worker_id, period, work_day);


--
-- Name: attendance_receipts attendance_receipts_org_id_worker_id_period_work_day_key; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.attendance_receipts
    ADD CONSTRAINT attendance_receipts_org_id_worker_id_period_work_day_key UNIQUE (org_id, worker_id, period, work_day);


--
-- Name: attendance_receipts attendance_receipts_pkey; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.attendance_receipts
    ADD CONSTRAINT attendance_receipts_pkey PRIMARY KEY (org_id, request_id);


--
-- Name: document_admissions document_admissions_org_id_request_id_key; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.document_admissions
    ADD CONSTRAINT document_admissions_org_id_request_id_key UNIQUE (org_id, request_id);


--
-- Name: document_admissions document_admissions_pkey; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.document_admissions
    ADD CONSTRAINT document_admissions_pkey PRIMARY KEY (org_id, document_id);


--
-- Name: document_revisions document_revisions_org_id_request_id_key; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.document_revisions
    ADD CONSTRAINT document_revisions_org_id_request_id_key UNIQUE (org_id, request_id);


--
-- Name: document_revisions document_revisions_pkey; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.document_revisions
    ADD CONSTRAINT document_revisions_pkey PRIMARY KEY (org_id, document_id, version);


--
-- Name: documents documents_pkey; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.documents
    ADD CONSTRAINT documents_pkey PRIMARY KEY (org_id, document_id);


--
-- Name: pay_periods pay_periods_pkey; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.pay_periods
    ADD CONSTRAINT pay_periods_pkey PRIMARY KEY (org_id, worker_id, period);


--
-- Name: period_amendments period_amendments_pkey; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.period_amendments
    ADD CONSTRAINT period_amendments_pkey PRIMARY KEY (org_id, request_id);


--
-- Name: period_confirmations period_confirmations_org_id_request_id_key; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.period_confirmations
    ADD CONSTRAINT period_confirmations_org_id_request_id_key UNIQUE (org_id, request_id);


--
-- Name: period_confirmations period_confirmations_pkey; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.period_confirmations
    ADD CONSTRAINT period_confirmations_pkey PRIMARY KEY (org_id, worker_id, period);


--
-- Name: profile_envelopes profile_envelopes_pkey; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.profile_envelopes
    ADD CONSTRAINT profile_envelopes_pkey PRIMARY KEY (org_id, worker_id);


--
-- Name: profile_retention profile_retention_pkey; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.profile_retention
    ADD CONSTRAINT profile_retention_pkey PRIMARY KEY (org_id, worker_id);


--
-- Name: profile_revision_history profile_revision_history_pkey; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.profile_revision_history
    ADD CONSTRAINT profile_revision_history_pkey PRIMARY KEY (org_id, worker_id, revision);


--
-- Name: setup_receipts setup_receipts_org_id_worker_id_kind_period_key; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.setup_receipts
    ADD CONSTRAINT setup_receipts_org_id_worker_id_kind_period_key UNIQUE (org_id, worker_id, kind, period);


--
-- Name: setup_receipts setup_receipts_pkey; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.setup_receipts
    ADD CONSTRAINT setup_receipts_pkey PRIMARY KEY (org_id, request_id);


--
-- Name: staff_archivals staff_archivals_org_id_request_id_key; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.staff_archivals
    ADD CONSTRAINT staff_archivals_org_id_request_id_key UNIQUE (org_id, request_id);


--
-- Name: staff_archivals staff_archivals_pkey; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.staff_archivals
    ADD CONSTRAINT staff_archivals_pkey PRIMARY KEY (org_id, worker_id);


--
-- Name: staff staff_pkey; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.staff
    ADD CONSTRAINT staff_pkey PRIMARY KEY (org_id, worker_id);


--
-- Name: statement_review_receipts statement_review_receipts_org_id_worker_id_period_review_sh_key; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.statement_review_receipts
    ADD CONSTRAINT statement_review_receipts_org_id_worker_id_period_review_sh_key UNIQUE (org_id, worker_id, period, review_sha256);


--
-- Name: statement_review_receipts statement_review_receipts_pkey; Type: CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.statement_review_receipts
    ADD CONSTRAINT statement_review_receipts_pkey PRIMARY KEY (org_id, request_id);


--
-- Name: bills bills_org_id_fulfillment_id_key; Type: CONSTRAINT; Schema: naruv_finance; Owner: -
--

ALTER TABLE ONLY naruv_finance.bills
    ADD CONSTRAINT bills_org_id_fulfillment_id_key UNIQUE (org_id, fulfillment_id);


--
-- Name: bills bills_pkey; Type: CONSTRAINT; Schema: naruv_finance; Owner: -
--

ALTER TABLE ONLY naruv_finance.bills
    ADD CONSTRAINT bills_pkey PRIMARY KEY (org_id, bill_id);


--
-- Name: events events_org_id_payment_ref_key; Type: CONSTRAINT; Schema: naruv_finance; Owner: -
--

ALTER TABLE ONLY naruv_finance.events
    ADD CONSTRAINT events_org_id_payment_ref_key UNIQUE (org_id, payment_ref);


--
-- Name: events events_org_id_reversal_of_key; Type: CONSTRAINT; Schema: naruv_finance; Owner: -
--

ALTER TABLE ONLY naruv_finance.events
    ADD CONSTRAINT events_org_id_reversal_of_key UNIQUE (org_id, reversal_of);


--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: naruv_finance; Owner: -
--

ALTER TABLE ONLY naruv_finance.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (org_id, request_id);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: naruv_hosted_identity_review; Owner: -
--

ALTER TABLE ONLY naruv_hosted_identity_review.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: naruv_hosted_identity_review; Owner: -
--

ALTER TABLE ONLY naruv_hosted_identity_review.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (token_hash);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: naruv_hosted_identity_review; Owner: -
--

ALTER TABLE ONLY naruv_hosted_identity_review.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: balances balances_pkey; Type: CONSTRAINT; Schema: naruv_inventory; Owner: -
--

ALTER TABLE ONLY naruv_inventory.balances
    ADD CONSTRAINT balances_pkey PRIMARY KEY (org_id, source_id, normalized_id, warehouse_id);


--
-- Name: items items_pkey; Type: CONSTRAINT; Schema: naruv_inventory; Owner: -
--

ALTER TABLE ONLY naruv_inventory.items
    ADD CONSTRAINT items_pkey PRIMARY KEY (org_id, source_id, normalized_id);


--
-- Name: movements movements_pkey; Type: CONSTRAINT; Schema: naruv_inventory; Owner: -
--

ALTER TABLE ONLY naruv_inventory.movements
    ADD CONSTRAINT movements_pkey PRIMARY KEY (org_id, request_id);


--
-- Name: warehouses warehouses_pkey; Type: CONSTRAINT; Schema: naruv_inventory; Owner: -
--

ALTER TABLE ONLY naruv_inventory.warehouses
    ADD CONSTRAINT warehouses_pkey PRIMARY KEY (org_id, warehouse_id);


--
-- Name: approvals approvals_pkey; Type: CONSTRAINT; Schema: naruv_native_review; Owner: -
--

ALTER TABLE ONLY naruv_native_review.approvals
    ADD CONSTRAINT approvals_pkey PRIMARY KEY (org_id, stage_id);


--
-- Name: receipts receipts_org_id_reservation_id_key; Type: CONSTRAINT; Schema: naruv_native_review; Owner: -
--

ALTER TABLE ONLY naruv_native_review.receipts
    ADD CONSTRAINT receipts_org_id_reservation_id_key UNIQUE (org_id, reservation_id);


--
-- Name: receipts receipts_pkey; Type: CONSTRAINT; Schema: naruv_native_review; Owner: -
--

ALTER TABLE ONLY naruv_native_review.receipts
    ADD CONSTRAINT receipts_pkey PRIMARY KEY (org_id, stage_id);


--
-- Name: records records_pkey; Type: CONSTRAINT; Schema: naruv_native_review; Owner: -
--

ALTER TABLE ONLY naruv_native_review.records
    ADD CONSTRAINT records_pkey PRIMARY KEY (org_id, source_id, entity, normalized_id);


--
-- Name: stages stages_pkey; Type: CONSTRAINT; Schema: naruv_native_review; Owner: -
--

ALTER TABLE ONLY naruv_native_review.stages
    ADD CONSTRAINT stages_pkey PRIMARY KEY (org_id, stage_id);


--
-- Name: boms boms_org_id_bom_id_source_id_key; Type: CONSTRAINT; Schema: naruv_production; Owner: -
--

ALTER TABLE ONLY naruv_production.boms
    ADD CONSTRAINT boms_org_id_bom_id_source_id_key UNIQUE (org_id, bom_id, source_id);


--
-- Name: boms boms_pkey; Type: CONSTRAINT; Schema: naruv_production; Owner: -
--

ALTER TABLE ONLY naruv_production.boms
    ADD CONSTRAINT boms_pkey PRIMARY KEY (org_id, bom_id);


--
-- Name: components components_pkey; Type: CONSTRAINT; Schema: naruv_production; Owner: -
--

ALTER TABLE ONLY naruv_production.components
    ADD CONSTRAINT components_pkey PRIMARY KEY (org_id, bom_id, material_id);


--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: naruv_production; Owner: -
--

ALTER TABLE ONLY naruv_production.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (org_id, request_id);


--
-- Name: orders orders_pkey; Type: CONSTRAINT; Schema: naruv_production; Owner: -
--

ALTER TABLE ONLY naruv_production.orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (org_id, order_id);


--
-- Name: conversions conversions_org_id_bundle_id_key; Type: CONSTRAINT; Schema: naruv_quote_bundle; Owner: -
--

ALTER TABLE ONLY naruv_quote_bundle.conversions
    ADD CONSTRAINT conversions_org_id_bundle_id_key UNIQUE (org_id, bundle_id);


--
-- Name: conversions conversions_pkey; Type: CONSTRAINT; Schema: naruv_quote_bundle; Owner: -
--

ALTER TABLE ONLY naruv_quote_bundle.conversions
    ADD CONSTRAINT conversions_pkey PRIMARY KEY (org_id, quote_id);


--
-- Name: conversions conversions_quote_id_key; Type: CONSTRAINT; Schema: naruv_quote_bundle; Owner: -
--

ALTER TABLE ONLY naruv_quote_bundle.conversions
    ADD CONSTRAINT conversions_quote_id_key UNIQUE (quote_id);


--
-- Name: documents documents_pkey; Type: CONSTRAINT; Schema: naruv_trade; Owner: -
--

ALTER TABLE ONLY naruv_trade.documents
    ADD CONSTRAINT documents_pkey PRIMARY KEY (org_id, doc_id);


--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: naruv_trade; Owner: -
--

ALTER TABLE ONLY naruv_trade.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (org_id, request_id);


--
-- Name: balances balances_pkey; Type: CONSTRAINT; Schema: naruv_valuation; Owner: -
--

ALTER TABLE ONLY naruv_valuation.balances
    ADD CONSTRAINT balances_pkey PRIMARY KEY (org_id, source_id, item_id, warehouse_id);


--
-- Name: cost_journals cost_journals_pkey; Type: CONSTRAINT; Schema: naruv_valuation; Owner: -
--

ALTER TABLE ONLY naruv_valuation.cost_journals
    ADD CONSTRAINT cost_journals_pkey PRIMARY KEY (org_id, movement_id);


--
-- Name: entries entries_pkey; Type: CONSTRAINT; Schema: naruv_valuation; Owner: -
--

ALTER TABLE ONLY naruv_valuation.entries
    ADD CONSTRAINT entries_pkey PRIMARY KEY (org_id, movement_id);


--
-- Name: naruv_ci_customer_business_key; Type: INDEX; Schema: jw_dev; Owner: -
--

CREATE UNIQUE INDEX naruv_ci_customer_business_key ON jw_dev.customers USING btree (org_id, replace(btrim(business_number), '-'::text, ''::text)) WHERE (btrim(business_number) <> ''::text);


--
-- Name: naruv_ci_customer_name_key; Type: INDEX; Schema: jw_dev; Owner: -
--

CREATE UNIQUE INDEX naruv_ci_customer_name_key ON jw_dev.customers USING btree (org_id, lower((btrim(name) COLLATE "C")));


--
-- Name: naruv_ci_customer_tenant_id; Type: INDEX; Schema: jw_dev; Owner: -
--

CREATE UNIQUE INDEX naruv_ci_customer_tenant_id ON jw_dev.customers USING btree (org_id, id);


--
-- Name: journal_bill; Type: INDEX; Schema: naruv_accounting; Owner: -
--

CREATE INDEX journal_bill ON naruv_accounting.journals USING btree (org_id, bill_id);


--
-- Name: finance_bill_doc; Type: INDEX; Schema: naruv_finance; Owner: -
--

CREATE INDEX finance_bill_doc ON naruv_finance.bills USING btree (org_id, doc_id);


--
-- Name: finance_credit_bill; Type: INDEX; Schema: naruv_finance; Owner: -
--

CREATE INDEX finance_credit_bill ON naruv_finance.events USING btree (org_id, bill_id) WHERE (action = 'credit'::text);


--
-- Name: finance_event_bill; Type: INDEX; Schema: naruv_finance; Owner: -
--

CREATE INDEX finance_event_bill ON naruv_finance.events USING btree (org_id, bill_id);


--
-- Name: production_open; Type: INDEX; Schema: naruv_production; Owner: -
--

CREATE INDEX production_open ON naruv_production.orders USING btree (org_id, bom_id, warehouse_id) WHERE (state = ANY (ARRAY['OPEN'::text, 'PARTIAL'::text]));


--
-- Name: documents_quote_line; Type: INDEX; Schema: naruv_trade; Owner: -
--

CREATE UNIQUE INDEX documents_quote_line ON naruv_trade.documents USING btree (org_id, quote_line_id) WHERE (quote_line_id IS NOT NULL);


--
-- Name: documents_single_quote; Type: INDEX; Schema: naruv_trade; Owner: -
--

CREATE UNIQUE INDEX documents_single_quote ON naruv_trade.documents USING btree (org_id, quote_id) WHERE (quote_line_id IS NULL);


--
-- Name: naruv_trade_reservation_lookup; Type: INDEX; Schema: naruv_trade; Owner: -
--

CREATE INDEX naruv_trade_reservation_lookup ON naruv_trade.documents USING btree (org_id, source_id, item_id, warehouse_id) WHERE ((kind = 'sale'::text) AND (state = ANY (ARRAY['OPEN'::text, 'PARTIAL'::text])));


--
-- Name: staff_disabled naruv_fence_disabled; Type: TRIGGER; Schema: jw_dev; Owner: -
--

CREATE TRIGGER naruv_fence_disabled BEFORE INSERT OR DELETE OR UPDATE ON jw_dev.staff_disabled FOR EACH ROW EXECUTE FUNCTION naruv_auth_fence.auth_change();


--
-- Name: staff_disabled naruv_fence_disabled_truncate; Type: TRIGGER; Schema: jw_dev; Owner: -
--

CREATE TRIGGER naruv_fence_disabled_truncate BEFORE TRUNCATE ON jw_dev.staff_disabled FOR EACH STATEMENT EXECUTE FUNCTION naruv_auth_fence.auth_change();


--
-- Name: sessions naruv_fence_sessions; Type: TRIGGER; Schema: jw_dev; Owner: -
--

CREATE TRIGGER naruv_fence_sessions BEFORE INSERT OR DELETE OR UPDATE ON jw_dev.sessions FOR EACH ROW EXECUTE FUNCTION naruv_auth_fence.auth_change();


--
-- Name: sessions naruv_fence_sessions_truncate; Type: TRIGGER; Schema: jw_dev; Owner: -
--

CREATE TRIGGER naruv_fence_sessions_truncate BEFORE TRUNCATE ON jw_dev.sessions FOR EACH STATEMENT EXECUTE FUNCTION naruv_auth_fence.auth_change();


--
-- Name: users naruv_fence_users; Type: TRIGGER; Schema: jw_dev; Owner: -
--

CREATE TRIGGER naruv_fence_users BEFORE INSERT OR DELETE OR UPDATE ON jw_dev.users FOR EACH ROW EXECUTE FUNCTION naruv_auth_fence.auth_change();


--
-- Name: users naruv_fence_users_truncate; Type: TRIGGER; Schema: jw_dev; Owner: -
--

CREATE TRIGGER naruv_fence_users_truncate BEFORE TRUNCATE ON jw_dev.users FOR EACH STATEMENT EXECUTE FUNCTION naruv_auth_fence.auth_change();


--
-- Name: quotes quote_freeze; Type: TRIGGER; Schema: jw_dev; Owner: -
--

CREATE TRIGGER quote_freeze BEFORE INSERT OR DELETE OR UPDATE ON jw_dev.quotes FOR EACH ROW EXECUTE FUNCTION naruv_quote_fence."freeze"();


--
-- Name: quote_items quote_line_freeze; Type: TRIGGER; Schema: jw_dev; Owner: -
--

CREATE TRIGGER quote_line_freeze BEFORE INSERT OR DELETE OR UPDATE ON jw_dev.quote_items FOR EACH ROW EXECUTE FUNCTION naruv_quote_fence."freeze"();


--
-- Name: quote_items quote_line_truncate_freeze; Type: TRIGGER; Schema: jw_dev; Owner: -
--

CREATE TRIGGER quote_line_truncate_freeze BEFORE TRUNCATE ON jw_dev.quote_items FOR EACH STATEMENT EXECUTE FUNCTION naruv_quote_fence."freeze"();


--
-- Name: quotes quote_truncate_freeze; Type: TRIGGER; Schema: jw_dev; Owner: -
--

CREATE TRIGGER quote_truncate_freeze BEFORE TRUNCATE ON jw_dev.quotes FOR EACH STATEMENT EXECUTE FUNCTION naruv_quote_fence."freeze"();


--
-- Name: journals journal_balance; Type: TRIGGER; Schema: naruv_accounting; Owner: -
--

CREATE CONSTRAINT TRIGGER journal_balance AFTER INSERT ON naruv_accounting.journals DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION naruv_accounting.validate_journal();


--
-- Name: journals journals_immutable; Type: TRIGGER; Schema: naruv_accounting; Owner: -
--

CREATE TRIGGER journals_immutable BEFORE DELETE OR UPDATE ON naruv_accounting.journals FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: lines line_balance; Type: TRIGGER; Schema: naruv_accounting; Owner: -
--

CREATE CONSTRAINT TRIGGER line_balance AFTER INSERT ON naruv_accounting.lines DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION naruv_accounting.validate_journal();


--
-- Name: lines lines_immutable; Type: TRIGGER; Schema: naruv_accounting; Owner: -
--

CREATE TRIGGER lines_immutable BEFORE DELETE OR UPDATE ON naruv_accounting.lines FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: periods period_guard; Type: TRIGGER; Schema: naruv_accounting; Owner: -
--

CREATE TRIGGER period_guard BEFORE DELETE OR UPDATE ON naruv_accounting.periods FOR EACH ROW EXECUTE FUNCTION naruv_accounting.period_guard();


--
-- Name: events immutable_bundle; Type: TRIGGER; Schema: naruv_bundle; Owner: -
--

CREATE TRIGGER immutable_bundle BEFORE DELETE OR UPDATE ON naruv_bundle.events FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: headers immutable_bundle; Type: TRIGGER; Schema: naruv_bundle; Owner: -
--

CREATE TRIGGER immutable_bundle BEFORE DELETE OR UPDATE ON naruv_bundle.headers FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: lines immutable_bundle; Type: TRIGGER; Schema: naruv_bundle; Owner: -
--

CREATE TRIGGER immutable_bundle BEFORE DELETE OR UPDATE ON naruv_bundle.lines FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: crosswalk crosswalk_immutable; Type: TRIGGER; Schema: naruv_customer_bridge; Owner: -
--

CREATE TRIGGER crosswalk_immutable BEFORE DELETE OR UPDATE ON naruv_customer_bridge.crosswalk FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: attendance_receipts attendance_receipt_immutable; Type: TRIGGER; Schema: naruv_draft; Owner: -
--

CREATE TRIGGER attendance_receipt_immutable BEFORE DELETE OR UPDATE ON naruv_draft.attendance_receipts FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: document_admissions document_admission_immutable; Type: TRIGGER; Schema: naruv_draft; Owner: -
--

CREATE TRIGGER document_admission_immutable BEFORE DELETE OR UPDATE ON naruv_draft.document_admissions FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: document_revisions document_revision_immutable; Type: TRIGGER; Schema: naruv_draft; Owner: -
--

CREATE TRIGGER document_revision_immutable BEFORE DELETE OR UPDATE ON naruv_draft.document_revisions FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: period_amendments period_amendment_immutable; Type: TRIGGER; Schema: naruv_draft; Owner: -
--

CREATE TRIGGER period_amendment_immutable BEFORE DELETE OR UPDATE ON naruv_draft.period_amendments FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: period_confirmations period_confirmation_immutable; Type: TRIGGER; Schema: naruv_draft; Owner: -
--

CREATE TRIGGER period_confirmation_immutable BEFORE DELETE OR UPDATE ON naruv_draft.period_confirmations FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: profile_revision_history profile_history_immutable; Type: TRIGGER; Schema: naruv_draft; Owner: -
--

CREATE TRIGGER profile_history_immutable BEFORE DELETE OR UPDATE ON naruv_draft.profile_revision_history FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: setup_receipts setup_receipt_immutable; Type: TRIGGER; Schema: naruv_draft; Owner: -
--

CREATE TRIGGER setup_receipt_immutable BEFORE DELETE OR UPDATE ON naruv_draft.setup_receipts FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: staff_archivals staff_archival_immutable; Type: TRIGGER; Schema: naruv_draft; Owner: -
--

CREATE TRIGGER staff_archival_immutable BEFORE DELETE OR UPDATE ON naruv_draft.staff_archivals FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: statement_review_receipts statement_receipt_immutable; Type: TRIGGER; Schema: naruv_draft; Owner: -
--

CREATE TRIGGER statement_receipt_immutable BEFORE DELETE OR UPDATE ON naruv_draft.statement_review_receipts FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: events accounting_post; Type: TRIGGER; Schema: naruv_finance; Owner: -
--

CREATE TRIGGER accounting_post AFTER INSERT ON naruv_finance.events FOR EACH ROW EXECUTE FUNCTION naruv_accounting.post_finance();


--
-- Name: bills bills_immutable; Type: TRIGGER; Schema: naruv_finance; Owner: -
--

CREATE TRIGGER bills_immutable BEFORE DELETE OR UPDATE ON naruv_finance.bills FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: events events_immutable; Type: TRIGGER; Schema: naruv_finance; Owner: -
--

CREATE TRIGGER events_immutable BEFORE DELETE OR UPDATE ON naruv_finance.events FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: bills quote_bundle_vat; Type: TRIGGER; Schema: naruv_finance; Owner: -
--

CREATE TRIGGER quote_bundle_vat BEFORE INSERT ON naruv_finance.bills FOR EACH ROW EXECUTE FUNCTION naruv_quote_bundle.allocate_vat();


--
-- Name: items immutable_items; Type: TRIGGER; Schema: naruv_inventory; Owner: -
--

CREATE TRIGGER immutable_items BEFORE DELETE OR UPDATE ON naruv_inventory.items FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: movements immutable_movements; Type: TRIGGER; Schema: naruv_inventory; Owner: -
--

CREATE TRIGGER immutable_movements BEFORE DELETE OR UPDATE ON naruv_inventory.movements FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: balances trade_balance_guard; Type: TRIGGER; Schema: naruv_inventory; Owner: -
--

CREATE TRIGGER trade_balance_guard BEFORE UPDATE OF quantity ON naruv_inventory.balances FOR EACH ROW EXECUTE FUNCTION naruv_trade.balance_guard();


--
-- Name: movements valuation_required; Type: TRIGGER; Schema: naruv_inventory; Owner: -
--

CREATE CONSTRAINT TRIGGER valuation_required AFTER INSERT ON naruv_inventory.movements DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION naruv_valuation.check_movement();


--
-- Name: records bridge_customer_after_insert; Type: TRIGGER; Schema: naruv_native_review; Owner: -
--

CREATE TRIGGER bridge_customer_after_insert AFTER INSERT ON naruv_native_review.records FOR EACH ROW WHEN ((new.entity = 'customer'::text)) EXECUTE FUNCTION naruv_customer_bridge.apply_customer();


--
-- Name: records inventory_item_after_insert; Type: TRIGGER; Schema: naruv_native_review; Owner: -
--

CREATE TRIGGER inventory_item_after_insert AFTER INSERT ON naruv_native_review.records FOR EACH ROW WHEN ((new.entity = 'item'::text)) EXECUTE FUNCTION naruv_inventory.import_item();


--
-- Name: receipts receipt_immutable; Type: TRIGGER; Schema: naruv_native_review; Owner: -
--

CREATE TRIGGER receipt_immutable BEFORE DELETE OR UPDATE ON naruv_native_review.receipts FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: stages stage_immutable; Type: TRIGGER; Schema: naruv_native_review; Owner: -
--

CREATE TRIGGER stage_immutable BEFORE DELETE OR UPDATE ON naruv_native_review.stages FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: boms production_immutable; Type: TRIGGER; Schema: naruv_production; Owner: -
--

CREATE TRIGGER production_immutable BEFORE DELETE OR UPDATE ON naruv_production.boms FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: components production_immutable; Type: TRIGGER; Schema: naruv_production; Owner: -
--

CREATE TRIGGER production_immutable BEFORE DELETE OR UPDATE ON naruv_production.components FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: events production_immutable; Type: TRIGGER; Schema: naruv_production; Owner: -
--

CREATE TRIGGER production_immutable BEFORE DELETE OR UPDATE ON naruv_production.events FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: events valuation_production; Type: TRIGGER; Schema: naruv_production; Owner: -
--

CREATE TRIGGER valuation_production AFTER INSERT ON naruv_production.events FOR EACH ROW EXECUTE FUNCTION naruv_valuation.production_post();


--
-- Name: conversions conversion_immutable; Type: TRIGGER; Schema: naruv_quote_bundle; Owner: -
--

CREATE TRIGGER conversion_immutable BEFORE DELETE OR UPDATE ON naruv_quote_bundle.conversions FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: events trade_events_immutable; Type: TRIGGER; Schema: naruv_trade; Owner: -
--

CREATE TRIGGER trade_events_immutable BEFORE DELETE OR UPDATE ON naruv_trade.events FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: events valuation_trade; Type: TRIGGER; Schema: naruv_trade; Owner: -
--

CREATE TRIGGER valuation_trade AFTER INSERT ON naruv_trade.events FOR EACH ROW EXECUTE FUNCTION naruv_valuation.trade_post();


--
-- Name: entries cost_entries_immutable; Type: TRIGGER; Schema: naruv_valuation; Owner: -
--

CREATE TRIGGER cost_entries_immutable BEFORE DELETE OR UPDATE ON naruv_valuation.entries FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: entries cost_entry_journal_required; Type: TRIGGER; Schema: naruv_valuation; Owner: -
--

CREATE CONSTRAINT TRIGGER cost_entry_journal_required AFTER INSERT ON naruv_valuation.entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION naruv_valuation.validate_cost_journal();


--
-- Name: cost_journals cost_journal_check; Type: TRIGGER; Schema: naruv_valuation; Owner: -
--

CREATE CONSTRAINT TRIGGER cost_journal_check AFTER INSERT ON naruv_valuation.cost_journals DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION naruv_valuation.validate_cost_journal();


--
-- Name: entries cost_journal_post; Type: TRIGGER; Schema: naruv_valuation; Owner: -
--

CREATE TRIGGER cost_journal_post AFTER INSERT ON naruv_valuation.entries FOR EACH ROW EXECUTE FUNCTION naruv_valuation.post_cost_journal();


--
-- Name: cost_journals cost_journals_immutable; Type: TRIGGER; Schema: naruv_valuation; Owner: -
--

CREATE TRIGGER cost_journals_immutable BEFORE DELETE OR UPDATE ON naruv_valuation.cost_journals FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();


--
-- Name: customers customers_org_id_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.customers
    ADD CONSTRAINT customers_org_id_fkey FOREIGN KEY (org_id) REFERENCES jw_dev.organizations(id);


--
-- Name: messenger_attachments messenger_attachments_message_id_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.messenger_attachments
    ADD CONSTRAINT messenger_attachments_message_id_fkey FOREIGN KEY (message_id) REFERENCES jw_dev.messenger_messages(id);


--
-- Name: messenger_companies messenger_companies_org_id_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.messenger_companies
    ADD CONSTRAINT messenger_companies_org_id_fkey FOREIGN KEY (org_id) REFERENCES jw_dev.organizations(id);


--
-- Name: messenger_connections messenger_connections_org_a_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.messenger_connections
    ADD CONSTRAINT messenger_connections_org_a_fkey FOREIGN KEY (org_a) REFERENCES jw_dev.organizations(id);


--
-- Name: messenger_connections messenger_connections_org_b_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.messenger_connections
    ADD CONSTRAINT messenger_connections_org_b_fkey FOREIGN KEY (org_b) REFERENCES jw_dev.organizations(id);


--
-- Name: messenger_edits messenger_edits_message_id_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.messenger_edits
    ADD CONSTRAINT messenger_edits_message_id_fkey FOREIGN KEY (message_id) REFERENCES jw_dev.messenger_messages(id);


--
-- Name: messenger_messages messenger_messages_connection_id_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.messenger_messages
    ADD CONSTRAINT messenger_messages_connection_id_fkey FOREIGN KEY (connection_id) REFERENCES jw_dev.messenger_connections(id);


--
-- Name: messenger_read_positions messenger_read_positions_connection_id_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.messenger_read_positions
    ADD CONSTRAINT messenger_read_positions_connection_id_fkey FOREIGN KEY (connection_id) REFERENCES jw_dev.messenger_connections(id);


--
-- Name: mfa_credentials mfa_credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.mfa_credentials
    ADD CONSTRAINT mfa_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES jw_dev.users(id);


--
-- Name: mfa_recovery_codes mfa_recovery_codes_user_id_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.mfa_recovery_codes
    ADD CONSTRAINT mfa_recovery_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES jw_dev.users(id);


--
-- Name: naruv_review_sources naruv_review_sources_org_id_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.naruv_review_sources
    ADD CONSTRAINT naruv_review_sources_org_id_fkey FOREIGN KEY (org_id) REFERENCES jw_dev.organizations(id);


--
-- Name: quote_items quote_items_quote_id_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.quote_items
    ADD CONSTRAINT quote_items_quote_id_fkey FOREIGN KEY (quote_id) REFERENCES jw_dev.quotes(id);


--
-- Name: quotes quotes_customer_id_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.quotes
    ADD CONSTRAINT quotes_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES jw_dev.customers(id);


--
-- Name: quotes quotes_org_id_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.quotes
    ADD CONSTRAINT quotes_org_id_fkey FOREIGN KEY (org_id) REFERENCES jw_dev.organizations(id);


--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES jw_dev.users(id);


--
-- Name: staff_disabled staff_disabled_user_id_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.staff_disabled
    ADD CONSTRAINT staff_disabled_user_id_fkey FOREIGN KEY (user_id) REFERENCES jw_dev.users(id);


--
-- Name: users users_org_id_fkey; Type: FK CONSTRAINT; Schema: jw_dev; Owner: -
--

ALTER TABLE ONLY jw_dev.users
    ADD CONSTRAINT users_org_id_fkey FOREIGN KEY (org_id) REFERENCES jw_dev.organizations(id);


--
-- Name: journals journals_org_id_bill_id_fkey; Type: FK CONSTRAINT; Schema: naruv_accounting; Owner: -
--

ALTER TABLE ONLY naruv_accounting.journals
    ADD CONSTRAINT journals_org_id_bill_id_fkey FOREIGN KEY (org_id, bill_id) REFERENCES naruv_finance.bills(org_id, bill_id);


--
-- Name: journals journals_org_id_event_id_fkey; Type: FK CONSTRAINT; Schema: naruv_accounting; Owner: -
--

ALTER TABLE ONLY naruv_accounting.journals
    ADD CONSTRAINT journals_org_id_event_id_fkey FOREIGN KEY (org_id, event_id) REFERENCES naruv_finance.events(org_id, request_id);


--
-- Name: journals journals_org_id_period_start_fkey; Type: FK CONSTRAINT; Schema: naruv_accounting; Owner: -
--

ALTER TABLE ONLY naruv_accounting.journals
    ADD CONSTRAINT journals_org_id_period_start_fkey FOREIGN KEY (org_id, period_start) REFERENCES naruv_accounting.periods(org_id, period_start);


--
-- Name: journals journals_org_id_reversal_of_fkey; Type: FK CONSTRAINT; Schema: naruv_accounting; Owner: -
--

ALTER TABLE ONLY naruv_accounting.journals
    ADD CONSTRAINT journals_org_id_reversal_of_fkey FOREIGN KEY (org_id, reversal_of) REFERENCES naruv_accounting.journals(org_id, event_id);


--
-- Name: lines lines_org_id_event_id_fkey; Type: FK CONSTRAINT; Schema: naruv_accounting; Owner: -
--

ALTER TABLE ONLY naruv_accounting.lines
    ADD CONSTRAINT lines_org_id_event_id_fkey FOREIGN KEY (org_id, event_id) REFERENCES naruv_accounting.journals(org_id, event_id);


--
-- Name: events events_org_id_bundle_id_fkey; Type: FK CONSTRAINT; Schema: naruv_bundle; Owner: -
--

ALTER TABLE ONLY naruv_bundle.events
    ADD CONSTRAINT events_org_id_bundle_id_fkey FOREIGN KEY (org_id, bundle_id) REFERENCES naruv_bundle.headers(org_id, bundle_id);


--
-- Name: lines lines_org_id_bundle_id_fkey; Type: FK CONSTRAINT; Schema: naruv_bundle; Owner: -
--

ALTER TABLE ONLY naruv_bundle.lines
    ADD CONSTRAINT lines_org_id_bundle_id_fkey FOREIGN KEY (org_id, bundle_id) REFERENCES naruv_bundle.headers(org_id, bundle_id);


--
-- Name: lines lines_org_id_doc_id_fkey; Type: FK CONSTRAINT; Schema: naruv_bundle; Owner: -
--

ALTER TABLE ONLY naruv_bundle.lines
    ADD CONSTRAINT lines_org_id_doc_id_fkey FOREIGN KEY (org_id, doc_id) REFERENCES naruv_trade.documents(org_id, doc_id);


--
-- Name: crosswalk crosswalk_org_id_customer_id_fkey; Type: FK CONSTRAINT; Schema: naruv_customer_bridge; Owner: -
--

ALTER TABLE ONLY naruv_customer_bridge.crosswalk
    ADD CONSTRAINT crosswalk_org_id_customer_id_fkey FOREIGN KEY (org_id, customer_id) REFERENCES jw_dev.customers(org_id, id);


--
-- Name: crosswalk crosswalk_org_id_source_id_entity_normalized_id_fkey; Type: FK CONSTRAINT; Schema: naruv_customer_bridge; Owner: -
--

ALTER TABLE ONLY naruv_customer_bridge.crosswalk
    ADD CONSTRAINT crosswalk_org_id_source_id_entity_normalized_id_fkey FOREIGN KEY (org_id, source_id, entity, normalized_id) REFERENCES naruv_native_review.records(org_id, source_id, entity, normalized_id);


--
-- Name: crosswalk crosswalk_org_id_stage_id_fkey; Type: FK CONSTRAINT; Schema: naruv_customer_bridge; Owner: -
--

ALTER TABLE ONLY naruv_customer_bridge.crosswalk
    ADD CONSTRAINT crosswalk_org_id_stage_id_fkey FOREIGN KEY (org_id, stage_id) REFERENCES naruv_native_review.stages(org_id, stage_id);


--
-- Name: attendance attendance_org_id_worker_id_period_fkey; Type: FK CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.attendance
    ADD CONSTRAINT attendance_org_id_worker_id_period_fkey FOREIGN KEY (org_id, worker_id, period) REFERENCES naruv_draft.pay_periods(org_id, worker_id, period);


--
-- Name: attendance_receipts attendance_receipts_org_id_worker_id_period_work_day_fkey; Type: FK CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.attendance_receipts
    ADD CONSTRAINT attendance_receipts_org_id_worker_id_period_work_day_fkey FOREIGN KEY (org_id, worker_id, period, work_day) REFERENCES naruv_draft.attendance(org_id, worker_id, period, work_day);


--
-- Name: document_admissions document_admissions_org_id_document_id_fkey; Type: FK CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.document_admissions
    ADD CONSTRAINT document_admissions_org_id_document_id_fkey FOREIGN KEY (org_id, document_id) REFERENCES naruv_draft.documents(org_id, document_id);


--
-- Name: document_revisions document_revisions_org_id_document_id_fkey; Type: FK CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.document_revisions
    ADD CONSTRAINT document_revisions_org_id_document_id_fkey FOREIGN KEY (org_id, document_id) REFERENCES naruv_draft.documents(org_id, document_id);


--
-- Name: pay_periods pay_periods_org_id_worker_id_fkey; Type: FK CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.pay_periods
    ADD CONSTRAINT pay_periods_org_id_worker_id_fkey FOREIGN KEY (org_id, worker_id) REFERENCES naruv_draft.staff(org_id, worker_id);


--
-- Name: period_amendments period_amendments_org_id_worker_id_period_fkey; Type: FK CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.period_amendments
    ADD CONSTRAINT period_amendments_org_id_worker_id_period_fkey FOREIGN KEY (org_id, worker_id, period) REFERENCES naruv_draft.pay_periods(org_id, worker_id, period);


--
-- Name: period_confirmations period_confirmations_org_id_worker_id_period_fkey; Type: FK CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.period_confirmations
    ADD CONSTRAINT period_confirmations_org_id_worker_id_period_fkey FOREIGN KEY (org_id, worker_id, period) REFERENCES naruv_draft.pay_periods(org_id, worker_id, period);


--
-- Name: profile_envelopes profile_envelopes_org_id_worker_id_fkey; Type: FK CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.profile_envelopes
    ADD CONSTRAINT profile_envelopes_org_id_worker_id_fkey FOREIGN KEY (org_id, worker_id) REFERENCES naruv_draft.staff(org_id, worker_id);


--
-- Name: profile_retention profile_retention_org_id_worker_id_fkey; Type: FK CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.profile_retention
    ADD CONSTRAINT profile_retention_org_id_worker_id_fkey FOREIGN KEY (org_id, worker_id) REFERENCES naruv_draft.staff(org_id, worker_id);


--
-- Name: profile_revision_history profile_revision_history_org_id_worker_id_fkey; Type: FK CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.profile_revision_history
    ADD CONSTRAINT profile_revision_history_org_id_worker_id_fkey FOREIGN KEY (org_id, worker_id) REFERENCES naruv_draft.staff(org_id, worker_id);


--
-- Name: setup_receipts setup_receipts_org_id_worker_id_fkey; Type: FK CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.setup_receipts
    ADD CONSTRAINT setup_receipts_org_id_worker_id_fkey FOREIGN KEY (org_id, worker_id) REFERENCES naruv_draft.staff(org_id, worker_id);


--
-- Name: staff_archivals staff_archivals_org_id_worker_id_fkey; Type: FK CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.staff_archivals
    ADD CONSTRAINT staff_archivals_org_id_worker_id_fkey FOREIGN KEY (org_id, worker_id) REFERENCES naruv_draft.staff(org_id, worker_id);


--
-- Name: statement_review_receipts statement_review_receipts_org_id_worker_id_period_fkey; Type: FK CONSTRAINT; Schema: naruv_draft; Owner: -
--

ALTER TABLE ONLY naruv_draft.statement_review_receipts
    ADD CONSTRAINT statement_review_receipts_org_id_worker_id_period_fkey FOREIGN KEY (org_id, worker_id, period) REFERENCES naruv_draft.pay_periods(org_id, worker_id, period);


--
-- Name: bills bills_org_id_doc_id_fkey; Type: FK CONSTRAINT; Schema: naruv_finance; Owner: -
--

ALTER TABLE ONLY naruv_finance.bills
    ADD CONSTRAINT bills_org_id_doc_id_fkey FOREIGN KEY (org_id, doc_id) REFERENCES naruv_trade.documents(org_id, doc_id);


--
-- Name: bills bills_org_id_fulfillment_id_fkey; Type: FK CONSTRAINT; Schema: naruv_finance; Owner: -
--

ALTER TABLE ONLY naruv_finance.bills
    ADD CONSTRAINT bills_org_id_fulfillment_id_fkey FOREIGN KEY (org_id, fulfillment_id) REFERENCES naruv_trade.events(org_id, request_id);


--
-- Name: events events_org_id_bill_id_fkey; Type: FK CONSTRAINT; Schema: naruv_finance; Owner: -
--

ALTER TABLE ONLY naruv_finance.events
    ADD CONSTRAINT events_org_id_bill_id_fkey FOREIGN KEY (org_id, bill_id) REFERENCES naruv_finance.bills(org_id, bill_id);


--
-- Name: events events_org_id_reversal_of_fkey; Type: FK CONSTRAINT; Schema: naruv_finance; Owner: -
--

ALTER TABLE ONLY naruv_finance.events
    ADD CONSTRAINT events_org_id_reversal_of_fkey FOREIGN KEY (org_id, reversal_of) REFERENCES naruv_finance.events(org_id, request_id);


--
-- Name: sessions sessions_actor_id_fkey; Type: FK CONSTRAINT; Schema: naruv_hosted_identity_review; Owner: -
--

ALTER TABLE ONLY naruv_hosted_identity_review.sessions
    ADD CONSTRAINT sessions_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES naruv_hosted_identity_review.users(id);


--
-- Name: users users_org_id_fkey; Type: FK CONSTRAINT; Schema: naruv_hosted_identity_review; Owner: -
--

ALTER TABLE ONLY naruv_hosted_identity_review.users
    ADD CONSTRAINT users_org_id_fkey FOREIGN KEY (org_id) REFERENCES naruv_hosted_identity_review.organizations(id);


--
-- Name: balances balances_org_id_source_id_normalized_id_fkey; Type: FK CONSTRAINT; Schema: naruv_inventory; Owner: -
--

ALTER TABLE ONLY naruv_inventory.balances
    ADD CONSTRAINT balances_org_id_source_id_normalized_id_fkey FOREIGN KEY (org_id, source_id, normalized_id) REFERENCES naruv_inventory.items(org_id, source_id, normalized_id);


--
-- Name: balances balances_org_id_warehouse_id_fkey; Type: FK CONSTRAINT; Schema: naruv_inventory; Owner: -
--

ALTER TABLE ONLY naruv_inventory.balances
    ADD CONSTRAINT balances_org_id_warehouse_id_fkey FOREIGN KEY (org_id, warehouse_id) REFERENCES naruv_inventory.warehouses(org_id, warehouse_id);


--
-- Name: items items_org_id_source_id_entity_normalized_id_fkey; Type: FK CONSTRAINT; Schema: naruv_inventory; Owner: -
--

ALTER TABLE ONLY naruv_inventory.items
    ADD CONSTRAINT items_org_id_source_id_entity_normalized_id_fkey FOREIGN KEY (org_id, source_id, entity, normalized_id) REFERENCES naruv_native_review.records(org_id, source_id, entity, normalized_id);


--
-- Name: movements movements_org_id_from_warehouse_fkey; Type: FK CONSTRAINT; Schema: naruv_inventory; Owner: -
--

ALTER TABLE ONLY naruv_inventory.movements
    ADD CONSTRAINT movements_org_id_from_warehouse_fkey FOREIGN KEY (org_id, from_warehouse) REFERENCES naruv_inventory.warehouses(org_id, warehouse_id);


--
-- Name: movements movements_org_id_source_id_normalized_id_fkey; Type: FK CONSTRAINT; Schema: naruv_inventory; Owner: -
--

ALTER TABLE ONLY naruv_inventory.movements
    ADD CONSTRAINT movements_org_id_source_id_normalized_id_fkey FOREIGN KEY (org_id, source_id, normalized_id) REFERENCES naruv_inventory.items(org_id, source_id, normalized_id);


--
-- Name: movements movements_org_id_to_warehouse_fkey; Type: FK CONSTRAINT; Schema: naruv_inventory; Owner: -
--

ALTER TABLE ONLY naruv_inventory.movements
    ADD CONSTRAINT movements_org_id_to_warehouse_fkey FOREIGN KEY (org_id, to_warehouse) REFERENCES naruv_inventory.warehouses(org_id, warehouse_id);


--
-- Name: approvals approvals_org_id_stage_id_fkey; Type: FK CONSTRAINT; Schema: naruv_native_review; Owner: -
--

ALTER TABLE ONLY naruv_native_review.approvals
    ADD CONSTRAINT approvals_org_id_stage_id_fkey FOREIGN KEY (org_id, stage_id) REFERENCES naruv_native_review.stages(org_id, stage_id);


--
-- Name: receipts receipts_org_id_stage_id_fkey; Type: FK CONSTRAINT; Schema: naruv_native_review; Owner: -
--

ALTER TABLE ONLY naruv_native_review.receipts
    ADD CONSTRAINT receipts_org_id_stage_id_fkey FOREIGN KEY (org_id, stage_id) REFERENCES naruv_native_review.approvals(org_id, stage_id);


--
-- Name: records records_org_id_stage_id_fkey; Type: FK CONSTRAINT; Schema: naruv_native_review; Owner: -
--

ALTER TABLE ONLY naruv_native_review.records
    ADD CONSTRAINT records_org_id_stage_id_fkey FOREIGN KEY (org_id, stage_id) REFERENCES naruv_native_review.stages(org_id, stage_id);


--
-- Name: boms boms_org_id_source_id_product_id_fkey; Type: FK CONSTRAINT; Schema: naruv_production; Owner: -
--

ALTER TABLE ONLY naruv_production.boms
    ADD CONSTRAINT boms_org_id_source_id_product_id_fkey FOREIGN KEY (org_id, source_id, product_id) REFERENCES naruv_inventory.items(org_id, source_id, normalized_id);


--
-- Name: components components_org_id_bom_id_source_id_fkey; Type: FK CONSTRAINT; Schema: naruv_production; Owner: -
--

ALTER TABLE ONLY naruv_production.components
    ADD CONSTRAINT components_org_id_bom_id_source_id_fkey FOREIGN KEY (org_id, bom_id, source_id) REFERENCES naruv_production.boms(org_id, bom_id, source_id);


--
-- Name: components components_org_id_source_id_material_id_fkey; Type: FK CONSTRAINT; Schema: naruv_production; Owner: -
--

ALTER TABLE ONLY naruv_production.components
    ADD CONSTRAINT components_org_id_source_id_material_id_fkey FOREIGN KEY (org_id, source_id, material_id) REFERENCES naruv_inventory.items(org_id, source_id, normalized_id);


--
-- Name: events events_org_id_bom_id_fkey; Type: FK CONSTRAINT; Schema: naruv_production; Owner: -
--

ALTER TABLE ONLY naruv_production.events
    ADD CONSTRAINT events_org_id_bom_id_fkey FOREIGN KEY (org_id, bom_id) REFERENCES naruv_production.boms(org_id, bom_id);


--
-- Name: events events_org_id_order_id_fkey; Type: FK CONSTRAINT; Schema: naruv_production; Owner: -
--

ALTER TABLE ONLY naruv_production.events
    ADD CONSTRAINT events_org_id_order_id_fkey FOREIGN KEY (org_id, order_id) REFERENCES naruv_production.orders(org_id, order_id);


--
-- Name: orders orders_org_id_bom_id_fkey; Type: FK CONSTRAINT; Schema: naruv_production; Owner: -
--

ALTER TABLE ONLY naruv_production.orders
    ADD CONSTRAINT orders_org_id_bom_id_fkey FOREIGN KEY (org_id, bom_id) REFERENCES naruv_production.boms(org_id, bom_id);


--
-- Name: orders orders_org_id_warehouse_id_fkey; Type: FK CONSTRAINT; Schema: naruv_production; Owner: -
--

ALTER TABLE ONLY naruv_production.orders
    ADD CONSTRAINT orders_org_id_warehouse_id_fkey FOREIGN KEY (org_id, warehouse_id) REFERENCES naruv_inventory.warehouses(org_id, warehouse_id);


--
-- Name: conversions conversions_org_id_bundle_id_fkey; Type: FK CONSTRAINT; Schema: naruv_quote_bundle; Owner: -
--

ALTER TABLE ONLY naruv_quote_bundle.conversions
    ADD CONSTRAINT conversions_org_id_bundle_id_fkey FOREIGN KEY (org_id, bundle_id) REFERENCES naruv_bundle.headers(org_id, bundle_id);


--
-- Name: conversions conversions_quote_id_fkey; Type: FK CONSTRAINT; Schema: naruv_quote_bundle; Owner: -
--

ALTER TABLE ONLY naruv_quote_bundle.conversions
    ADD CONSTRAINT conversions_quote_id_fkey FOREIGN KEY (quote_id) REFERENCES jw_dev.quotes(id);


--
-- Name: documents documents_org_id_counterparty_id_fkey; Type: FK CONSTRAINT; Schema: naruv_trade; Owner: -
--

ALTER TABLE ONLY naruv_trade.documents
    ADD CONSTRAINT documents_org_id_counterparty_id_fkey FOREIGN KEY (org_id, counterparty_id) REFERENCES jw_dev.customers(org_id, id);


--
-- Name: documents documents_org_id_source_id_item_id_fkey; Type: FK CONSTRAINT; Schema: naruv_trade; Owner: -
--

ALTER TABLE ONLY naruv_trade.documents
    ADD CONSTRAINT documents_org_id_source_id_item_id_fkey FOREIGN KEY (org_id, source_id, item_id) REFERENCES naruv_inventory.items(org_id, source_id, normalized_id);


--
-- Name: documents documents_org_id_warehouse_id_fkey; Type: FK CONSTRAINT; Schema: naruv_trade; Owner: -
--

ALTER TABLE ONLY naruv_trade.documents
    ADD CONSTRAINT documents_org_id_warehouse_id_fkey FOREIGN KEY (org_id, warehouse_id) REFERENCES naruv_inventory.warehouses(org_id, warehouse_id);


--
-- Name: documents documents_quote_id_fkey; Type: FK CONSTRAINT; Schema: naruv_trade; Owner: -
--

ALTER TABLE ONLY naruv_trade.documents
    ADD CONSTRAINT documents_quote_id_fkey FOREIGN KEY (quote_id) REFERENCES jw_dev.quotes(id);


--
-- Name: documents documents_quote_line_id_fkey; Type: FK CONSTRAINT; Schema: naruv_trade; Owner: -
--

ALTER TABLE ONLY naruv_trade.documents
    ADD CONSTRAINT documents_quote_line_id_fkey FOREIGN KEY (quote_line_id) REFERENCES jw_dev.quote_items(id);


--
-- Name: events events_org_id_doc_id_fkey; Type: FK CONSTRAINT; Schema: naruv_trade; Owner: -
--

ALTER TABLE ONLY naruv_trade.events
    ADD CONSTRAINT events_org_id_doc_id_fkey FOREIGN KEY (org_id, doc_id) REFERENCES naruv_trade.documents(org_id, doc_id);


--
-- Name: events events_org_id_movement_id_fkey; Type: FK CONSTRAINT; Schema: naruv_trade; Owner: -
--

ALTER TABLE ONLY naruv_trade.events
    ADD CONSTRAINT events_org_id_movement_id_fkey FOREIGN KEY (org_id, movement_id) REFERENCES naruv_inventory.movements(org_id, request_id);


--
-- Name: balances balances_org_id_source_id_item_id_warehouse_id_fkey; Type: FK CONSTRAINT; Schema: naruv_valuation; Owner: -
--

ALTER TABLE ONLY naruv_valuation.balances
    ADD CONSTRAINT balances_org_id_source_id_item_id_warehouse_id_fkey FOREIGN KEY (org_id, source_id, item_id, warehouse_id) REFERENCES naruv_inventory.balances(org_id, source_id, normalized_id, warehouse_id);


--
-- Name: cost_journals cost_journals_org_id_movement_id_fkey; Type: FK CONSTRAINT; Schema: naruv_valuation; Owner: -
--

ALTER TABLE ONLY naruv_valuation.cost_journals
    ADD CONSTRAINT cost_journals_org_id_movement_id_fkey FOREIGN KEY (org_id, movement_id) REFERENCES naruv_valuation.entries(org_id, movement_id);


--
-- Name: cost_journals cost_journals_org_id_period_start_fkey; Type: FK CONSTRAINT; Schema: naruv_valuation; Owner: -
--

ALTER TABLE ONLY naruv_valuation.cost_journals
    ADD CONSTRAINT cost_journals_org_id_period_start_fkey FOREIGN KEY (org_id, period_start) REFERENCES naruv_accounting.periods(org_id, period_start);


--
-- Name: entries entries_org_id_movement_id_fkey; Type: FK CONSTRAINT; Schema: naruv_valuation; Owner: -
--

ALTER TABLE ONLY naruv_valuation.entries
    ADD CONSTRAINT entries_org_id_movement_id_fkey FOREIGN KEY (org_id, movement_id) REFERENCES naruv_inventory.movements(org_id, request_id);


--
-- Name: audit_logs; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.audit_logs ENABLE ROW LEVEL SECURITY;

--
-- Name: audit_logs ci_audit_insert; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY ci_audit_insert ON jw_dev.audit_logs FOR INSERT TO jw_app_dev WITH CHECK (((org_id = jw_dev.current_org_from_session()) AND (actor_id = jw_dev.current_actor_from_session_v82())));


--
-- Name: customers ci_customers_tenant; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY ci_customers_tenant ON jw_dev.customers FOR SELECT TO jw_app_dev USING ((org_id = jw_dev.current_org_from_session()));


--
-- Name: quotes ci_quote_insert; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY ci_quote_insert ON jw_dev.quotes FOR INSERT TO jw_app_dev WITH CHECK ((org_id = jw_dev.current_org_from_session()));


--
-- Name: quote_items ci_quote_item_insert; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY ci_quote_item_insert ON jw_dev.quote_items FOR INSERT TO jw_app_dev WITH CHECK ((EXISTS ( SELECT 1
   FROM jw_dev.quotes q
  WHERE ((q.id = quote_items.quote_id) AND (q.org_id = jw_dev.current_org_from_session())))));


--
-- Name: quote_items ci_quote_item_select; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY ci_quote_item_select ON jw_dev.quote_items FOR SELECT TO jw_app_dev USING ((EXISTS ( SELECT 1
   FROM jw_dev.quotes q
  WHERE ((q.id = quote_items.quote_id) AND (q.org_id = jw_dev.current_org_from_session())))));


--
-- Name: quotes ci_quote_select; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY ci_quote_select ON jw_dev.quotes FOR SELECT TO jw_app_dev USING ((org_id = jw_dev.current_org_from_session()));


--
-- Name: customers; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.customers ENABLE ROW LEVEL SECURITY;

--
-- Name: organizations cutover_reader; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_reader ON jw_dev.organizations FOR SELECT TO naruv_identity_reader_ci USING (true);


--
-- Name: sessions cutover_reader; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_reader ON jw_dev.sessions FOR SELECT TO naruv_identity_reader_ci USING (true);


--
-- Name: staff_disabled cutover_reader; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_reader ON jw_dev.staff_disabled FOR SELECT TO naruv_identity_reader_ci USING (true);


--
-- Name: users cutover_reader; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_reader ON jw_dev.users FOR SELECT TO naruv_identity_reader_ci USING (true);


--
-- Name: login_failures cutover_writer_delete; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_delete ON jw_dev.login_failures FOR DELETE TO naruv_v85_writer_ci USING (true);


--
-- Name: sessions cutover_writer_delete; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_delete ON jw_dev.sessions FOR DELETE TO naruv_v85_writer_ci USING (true);


--
-- Name: login_failures cutover_writer_insert; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_insert ON jw_dev.login_failures FOR INSERT TO naruv_v85_writer_ci WITH CHECK (true);


--
-- Name: security_events cutover_writer_insert; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_insert ON jw_dev.security_events FOR INSERT TO naruv_v85_writer_ci WITH CHECK (true);


--
-- Name: sessions cutover_writer_insert; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_insert ON jw_dev.sessions FOR INSERT TO naruv_v85_writer_ci WITH CHECK (true);


--
-- Name: login_failures cutover_writer_select; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_select ON jw_dev.login_failures FOR SELECT TO naruv_v85_writer_ci USING (true);


--
-- Name: mfa_credentials cutover_writer_select; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_select ON jw_dev.mfa_credentials FOR SELECT TO naruv_v85_writer_ci USING (true);


--
-- Name: mfa_recovery_codes cutover_writer_select; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_select ON jw_dev.mfa_recovery_codes FOR SELECT TO naruv_v85_writer_ci USING (true);


--
-- Name: sessions cutover_writer_select; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_select ON jw_dev.sessions FOR SELECT TO naruv_v85_writer_ci USING (true);


--
-- Name: staff_disabled cutover_writer_select; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_select ON jw_dev.staff_disabled FOR SELECT TO naruv_v85_writer_ci USING (true);


--
-- Name: users cutover_writer_select; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_select ON jw_dev.users FOR SELECT TO naruv_v85_writer_ci USING (true);


--
-- Name: login_failures cutover_writer_update; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_update ON jw_dev.login_failures FOR UPDATE TO naruv_v85_writer_ci USING (true) WITH CHECK (true);


--
-- Name: mfa_credentials cutover_writer_update; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_update ON jw_dev.mfa_credentials FOR UPDATE TO naruv_v85_writer_ci USING (true) WITH CHECK (true);


--
-- Name: mfa_recovery_codes cutover_writer_update; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_update ON jw_dev.mfa_recovery_codes FOR UPDATE TO naruv_v85_writer_ci USING (true) WITH CHECK (true);


--
-- Name: sessions cutover_writer_update; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_update ON jw_dev.sessions FOR UPDATE TO naruv_v85_writer_ci USING (true) WITH CHECK (false);


--
-- Name: users cutover_writer_update; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY cutover_writer_update ON jw_dev.users FOR UPDATE TO naruv_v85_writer_ci USING (true) WITH CHECK (false);


--
-- Name: login_failures; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.login_failures ENABLE ROW LEVEL SECURITY;

--
-- Name: messenger_attachments; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.messenger_attachments ENABLE ROW LEVEL SECURITY;

--
-- Name: messenger_companies; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.messenger_companies ENABLE ROW LEVEL SECURITY;

--
-- Name: messenger_connections; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.messenger_connections ENABLE ROW LEVEL SECURITY;

--
-- Name: messenger_edits; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.messenger_edits ENABLE ROW LEVEL SECURITY;

--
-- Name: messenger_attachments messenger_exec_insert; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY messenger_exec_insert ON jw_dev.messenger_attachments FOR INSERT TO naruv_messenger_executor_ci WITH CHECK (true);


--
-- Name: messenger_connections messenger_exec_insert; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY messenger_exec_insert ON jw_dev.messenger_connections FOR INSERT TO naruv_messenger_executor_ci WITH CHECK (true);


--
-- Name: messenger_edits messenger_exec_insert; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY messenger_exec_insert ON jw_dev.messenger_edits FOR INSERT TO naruv_messenger_executor_ci WITH CHECK (true);


--
-- Name: messenger_messages messenger_exec_insert; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY messenger_exec_insert ON jw_dev.messenger_messages FOR INSERT TO naruv_messenger_executor_ci WITH CHECK (true);


--
-- Name: messenger_read_positions messenger_exec_insert; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY messenger_exec_insert ON jw_dev.messenger_read_positions FOR INSERT TO naruv_messenger_executor_ci WITH CHECK (true);


--
-- Name: messenger_attachments messenger_exec_select; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY messenger_exec_select ON jw_dev.messenger_attachments FOR SELECT TO naruv_messenger_executor_ci USING (true);


--
-- Name: messenger_companies messenger_exec_select; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY messenger_exec_select ON jw_dev.messenger_companies FOR SELECT TO naruv_messenger_executor_ci USING (true);


--
-- Name: messenger_connections messenger_exec_select; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY messenger_exec_select ON jw_dev.messenger_connections FOR SELECT TO naruv_messenger_executor_ci USING (true);


--
-- Name: messenger_edits messenger_exec_select; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY messenger_exec_select ON jw_dev.messenger_edits FOR SELECT TO naruv_messenger_executor_ci USING (true);


--
-- Name: messenger_messages messenger_exec_select; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY messenger_exec_select ON jw_dev.messenger_messages FOR SELECT TO naruv_messenger_executor_ci USING (true);


--
-- Name: messenger_read_positions messenger_exec_select; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY messenger_exec_select ON jw_dev.messenger_read_positions FOR SELECT TO naruv_messenger_executor_ci USING (true);


--
-- Name: organizations messenger_exec_select; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY messenger_exec_select ON jw_dev.organizations FOR SELECT TO naruv_messenger_executor_ci USING (true);


--
-- Name: messenger_connections messenger_exec_update; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY messenger_exec_update ON jw_dev.messenger_connections FOR UPDATE TO naruv_messenger_executor_ci USING (true) WITH CHECK (true);


--
-- Name: messenger_messages messenger_exec_update; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY messenger_exec_update ON jw_dev.messenger_messages FOR UPDATE TO naruv_messenger_executor_ci USING (true) WITH CHECK (true);


--
-- Name: messenger_read_positions messenger_exec_update; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY messenger_exec_update ON jw_dev.messenger_read_positions FOR UPDATE TO naruv_messenger_executor_ci USING (true) WITH CHECK (true);


--
-- Name: messenger_messages; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.messenger_messages ENABLE ROW LEVEL SECURITY;

--
-- Name: messenger_read_positions; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.messenger_read_positions ENABLE ROW LEVEL SECURITY;

--
-- Name: mfa_credentials; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.mfa_credentials ENABLE ROW LEVEL SECURITY;

--
-- Name: mfa_recovery_codes; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.mfa_recovery_codes ENABLE ROW LEVEL SECURITY;

--
-- Name: audit_logs naruv_ci_customer_audit; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY naruv_ci_customer_audit ON jw_dev.audit_logs FOR INSERT TO naruv_native_owner WITH CHECK (((org_id = jw_dev.current_org_from_session()) AND (EXISTS ( SELECT 1
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE ((i.org_id = audit_logs.org_id) AND (i.actor_id = audit_logs.actor_id) AND (i.actor_role = 'admin'::text))))));


--
-- Name: customers naruv_ci_customer_insert; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY naruv_ci_customer_insert ON jw_dev.customers FOR INSERT TO naruv_native_owner WITH CHECK (((org_id = jw_dev.current_org_from_session()) AND (EXISTS ( SELECT 1
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE ((i.org_id = customers.org_id) AND (i.actor_role = 'admin'::text))))));


--
-- Name: naruv_review_sources naruv_native_owner_source; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY naruv_native_owner_source ON jw_dev.naruv_review_sources TO naruv_native_owner USING (((org_id = jw_dev.current_org_from_session()) AND (EXISTS ( SELECT 1
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE ((i.org_id = naruv_review_sources.org_id) AND (i.actor_role = 'admin'::text)))))) WITH CHECK (((org_id = jw_dev.current_org_from_session()) AND (EXISTS ( SELECT 1
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE ((i.org_id = naruv_review_sources.org_id) AND (i.actor_role = 'admin'::text))))));


--
-- Name: naruv_review_sources naruv_review_source_tenant; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY naruv_review_source_tenant ON jw_dev.naruv_review_sources FOR SELECT TO jw_app_dev USING (((org_id = jw_dev.current_org_from_session()) AND (EXISTS ( SELECT 1
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE ((i.org_id = naruv_review_sources.org_id) AND (i.actor_role = 'admin'::text))))));


--
-- Name: naruv_review_sources; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.naruv_review_sources ENABLE ROW LEVEL SECURITY;

--
-- Name: customers naruv_trade_customer_read; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY naruv_trade_customer_read ON jw_dev.customers FOR SELECT TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: quote_items naruv_trade_quote_item_read; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY naruv_trade_quote_item_read ON jw_dev.quote_items FOR SELECT TO naruv_native_owner USING ((EXISTS ( SELECT 1
   FROM jw_dev.quotes q
  WHERE ((q.id = quote_items.quote_id) AND (q.org_id = ( SELECT i.org_id
           FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
          WHERE (i.actor_role = 'admin'::text)))))));


--
-- Name: quotes naruv_trade_quote_read; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY naruv_trade_quote_read ON jw_dev.quotes FOR SELECT TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: organizations; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.organizations ENABLE ROW LEVEL SECURITY;

--
-- Name: quote_items; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.quote_items ENABLE ROW LEVEL SECURITY;

--
-- Name: quotes; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.quotes ENABLE ROW LEVEL SECURITY;

--
-- Name: security_events; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.security_events ENABLE ROW LEVEL SECURITY;

--
-- Name: sessions; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.sessions ENABLE ROW LEVEL SECURITY;

--
-- Name: staff_disabled; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.staff_disabled ENABLE ROW LEVEL SECURITY;

--
-- Name: staff_disabled sync_disabled; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY sync_disabled ON jw_dev.staff_disabled TO naruv_sync_owner_ci USING (true) WITH CHECK (true);


--
-- Name: sessions sync_sessions; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY sync_sessions ON jw_dev.sessions TO naruv_sync_owner_ci USING (true) WITH CHECK (true);


--
-- Name: users sync_users; Type: POLICY; Schema: jw_dev; Owner: -
--

CREATE POLICY sync_users ON jw_dev.users TO naruv_sync_owner_ci USING (true) WITH CHECK (true);


--
-- Name: users; Type: ROW SECURITY; Schema: jw_dev; Owner: -
--

ALTER TABLE jw_dev.users ENABLE ROW LEVEL SECURITY;

--
-- Name: journals accounting_scope; Type: POLICY; Schema: naruv_accounting; Owner: -
--

CREATE POLICY accounting_scope ON naruv_accounting.journals TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: lines accounting_scope; Type: POLICY; Schema: naruv_accounting; Owner: -
--

CREATE POLICY accounting_scope ON naruv_accounting.lines TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: periods accounting_scope; Type: POLICY; Schema: naruv_accounting; Owner: -
--

CREATE POLICY accounting_scope ON naruv_accounting.periods TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: journals; Type: ROW SECURITY; Schema: naruv_accounting; Owner: -
--

ALTER TABLE naruv_accounting.journals ENABLE ROW LEVEL SECURITY;

--
-- Name: lines; Type: ROW SECURITY; Schema: naruv_accounting; Owner: -
--

ALTER TABLE naruv_accounting.lines ENABLE ROW LEVEL SECURITY;

--
-- Name: periods; Type: ROW SECURITY; Schema: naruv_accounting; Owner: -
--

ALTER TABLE naruv_accounting.periods ENABLE ROW LEVEL SECURITY;

--
-- Name: epochs; Type: ROW SECURITY; Schema: naruv_auth_fence; Owner: -
--

ALTER TABLE naruv_auth_fence.epochs ENABLE ROW LEVEL SECURITY;

--
-- Name: epochs fence_internal; Type: POLICY; Schema: naruv_auth_fence; Owner: -
--

CREATE POLICY fence_internal ON naruv_auth_fence.epochs TO naruv_auth_fence_owner USING (true) WITH CHECK (true);


--
-- Name: events bundle_scope; Type: POLICY; Schema: naruv_bundle; Owner: -
--

CREATE POLICY bundle_scope ON naruv_bundle.events TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: headers bundle_scope; Type: POLICY; Schema: naruv_bundle; Owner: -
--

CREATE POLICY bundle_scope ON naruv_bundle.headers TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: lines bundle_scope; Type: POLICY; Schema: naruv_bundle; Owner: -
--

CREATE POLICY bundle_scope ON naruv_bundle.lines TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: events; Type: ROW SECURITY; Schema: naruv_bundle; Owner: -
--

ALTER TABLE naruv_bundle.events ENABLE ROW LEVEL SECURITY;

--
-- Name: headers; Type: ROW SECURITY; Schema: naruv_bundle; Owner: -
--

ALTER TABLE naruv_bundle.headers ENABLE ROW LEVEL SECURITY;

--
-- Name: lines; Type: ROW SECURITY; Schema: naruv_bundle; Owner: -
--

ALTER TABLE naruv_bundle.lines ENABLE ROW LEVEL SECURITY;

--
-- Name: crosswalk; Type: ROW SECURITY; Schema: naruv_customer_bridge; Owner: -
--

ALTER TABLE naruv_customer_bridge.crosswalk ENABLE ROW LEVEL SECURITY;

--
-- Name: crosswalk crosswalk_owner_scope; Type: POLICY; Schema: naruv_customer_bridge; Owner: -
--

CREATE POLICY crosswalk_owner_scope ON naruv_customer_bridge.crosswalk TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: period_amendments amendment_scope; Type: POLICY; Schema: naruv_draft; Owner: -
--

CREATE POLICY amendment_scope ON naruv_draft.period_amendments TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: staff_archivals archival_scope; Type: POLICY; Schema: naruv_draft; Owner: -
--

CREATE POLICY archival_scope ON naruv_draft.staff_archivals TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: attendance; Type: ROW SECURITY; Schema: naruv_draft; Owner: -
--

ALTER TABLE naruv_draft.attendance ENABLE ROW LEVEL SECURITY;

--
-- Name: attendance_receipts attendance_receipt_scope; Type: POLICY; Schema: naruv_draft; Owner: -
--

CREATE POLICY attendance_receipt_scope ON naruv_draft.attendance_receipts TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: attendance_receipts; Type: ROW SECURITY; Schema: naruv_draft; Owner: -
--

ALTER TABLE naruv_draft.attendance_receipts ENABLE ROW LEVEL SECURITY;

--
-- Name: period_confirmations confirmation_scope; Type: POLICY; Schema: naruv_draft; Owner: -
--

CREATE POLICY confirmation_scope ON naruv_draft.period_confirmations TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: document_admissions document_admission_scope; Type: POLICY; Schema: naruv_draft; Owner: -
--

CREATE POLICY document_admission_scope ON naruv_draft.document_admissions TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: document_admissions; Type: ROW SECURITY; Schema: naruv_draft; Owner: -
--

ALTER TABLE naruv_draft.document_admissions ENABLE ROW LEVEL SECURITY;

--
-- Name: document_revisions; Type: ROW SECURITY; Schema: naruv_draft; Owner: -
--

ALTER TABLE naruv_draft.document_revisions ENABLE ROW LEVEL SECURITY;

--
-- Name: documents; Type: ROW SECURITY; Schema: naruv_draft; Owner: -
--

ALTER TABLE naruv_draft.documents ENABLE ROW LEVEL SECURITY;

--
-- Name: attendance draft_scope; Type: POLICY; Schema: naruv_draft; Owner: -
--

CREATE POLICY draft_scope ON naruv_draft.attendance TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: documents draft_scope; Type: POLICY; Schema: naruv_draft; Owner: -
--

CREATE POLICY draft_scope ON naruv_draft.documents TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: pay_periods draft_scope; Type: POLICY; Schema: naruv_draft; Owner: -
--

CREATE POLICY draft_scope ON naruv_draft.pay_periods TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: staff draft_scope; Type: POLICY; Schema: naruv_draft; Owner: -
--

CREATE POLICY draft_scope ON naruv_draft.staff TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: pay_periods; Type: ROW SECURITY; Schema: naruv_draft; Owner: -
--

ALTER TABLE naruv_draft.pay_periods ENABLE ROW LEVEL SECURITY;

--
-- Name: period_amendments; Type: ROW SECURITY; Schema: naruv_draft; Owner: -
--

ALTER TABLE naruv_draft.period_amendments ENABLE ROW LEVEL SECURITY;

--
-- Name: period_confirmations; Type: ROW SECURITY; Schema: naruv_draft; Owner: -
--

ALTER TABLE naruv_draft.period_confirmations ENABLE ROW LEVEL SECURITY;

--
-- Name: profile_envelopes; Type: ROW SECURITY; Schema: naruv_draft; Owner: -
--

ALTER TABLE naruv_draft.profile_envelopes ENABLE ROW LEVEL SECURITY;

--
-- Name: profile_revision_history profile_history_scope; Type: POLICY; Schema: naruv_draft; Owner: -
--

CREATE POLICY profile_history_scope ON naruv_draft.profile_revision_history TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: profile_retention; Type: ROW SECURITY; Schema: naruv_draft; Owner: -
--

ALTER TABLE naruv_draft.profile_retention ENABLE ROW LEVEL SECURITY;

--
-- Name: profile_retention profile_retention_scope; Type: POLICY; Schema: naruv_draft; Owner: -
--

CREATE POLICY profile_retention_scope ON naruv_draft.profile_retention TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: profile_revision_history; Type: ROW SECURITY; Schema: naruv_draft; Owner: -
--

ALTER TABLE naruv_draft.profile_revision_history ENABLE ROW LEVEL SECURITY;

--
-- Name: profile_envelopes profile_scope; Type: POLICY; Schema: naruv_draft; Owner: -
--

CREATE POLICY profile_scope ON naruv_draft.profile_envelopes TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: document_revisions revision_scope; Type: POLICY; Schema: naruv_draft; Owner: -
--

CREATE POLICY revision_scope ON naruv_draft.document_revisions TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: setup_receipts; Type: ROW SECURITY; Schema: naruv_draft; Owner: -
--

ALTER TABLE naruv_draft.setup_receipts ENABLE ROW LEVEL SECURITY;

--
-- Name: setup_receipts setup_scope; Type: POLICY; Schema: naruv_draft; Owner: -
--

CREATE POLICY setup_scope ON naruv_draft.setup_receipts TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: staff; Type: ROW SECURITY; Schema: naruv_draft; Owner: -
--

ALTER TABLE naruv_draft.staff ENABLE ROW LEVEL SECURITY;

--
-- Name: staff_archivals; Type: ROW SECURITY; Schema: naruv_draft; Owner: -
--

ALTER TABLE naruv_draft.staff_archivals ENABLE ROW LEVEL SECURITY;

--
-- Name: statement_review_receipts statement_receipt_scope; Type: POLICY; Schema: naruv_draft; Owner: -
--

CREATE POLICY statement_receipt_scope ON naruv_draft.statement_review_receipts TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: statement_review_receipts; Type: ROW SECURITY; Schema: naruv_draft; Owner: -
--

ALTER TABLE naruv_draft.statement_review_receipts ENABLE ROW LEVEL SECURITY;

--
-- Name: bills; Type: ROW SECURITY; Schema: naruv_finance; Owner: -
--

ALTER TABLE naruv_finance.bills ENABLE ROW LEVEL SECURITY;

--
-- Name: events; Type: ROW SECURITY; Schema: naruv_finance; Owner: -
--

ALTER TABLE naruv_finance.events ENABLE ROW LEVEL SECURITY;

--
-- Name: bills finance_scope; Type: POLICY; Schema: naruv_finance; Owner: -
--

CREATE POLICY finance_scope ON naruv_finance.bills TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: events finance_scope; Type: POLICY; Schema: naruv_finance; Owner: -
--

CREATE POLICY finance_scope ON naruv_finance.events TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: sessions cutover_reader; Type: POLICY; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE POLICY cutover_reader ON naruv_hosted_identity_review.sessions FOR SELECT TO naruv_identity_reader_ci USING (true);


--
-- Name: users cutover_reader; Type: POLICY; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE POLICY cutover_reader ON naruv_hosted_identity_review.users FOR SELECT TO naruv_identity_reader_ci USING (true);


--
-- Name: sessions cutover_writer_insert; Type: POLICY; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE POLICY cutover_writer_insert ON naruv_hosted_identity_review.sessions FOR INSERT TO naruv_v85_writer_ci WITH CHECK (true);


--
-- Name: sessions cutover_writer_select; Type: POLICY; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE POLICY cutover_writer_select ON naruv_hosted_identity_review.sessions FOR SELECT TO naruv_v85_writer_ci USING (true);


--
-- Name: users cutover_writer_select; Type: POLICY; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE POLICY cutover_writer_select ON naruv_hosted_identity_review.users FOR SELECT TO naruv_v85_writer_ci USING (true);


--
-- Name: sessions cutover_writer_update; Type: POLICY; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE POLICY cutover_writer_update ON naruv_hosted_identity_review.sessions FOR UPDATE TO naruv_v85_writer_ci USING (true) WITH CHECK (true);


--
-- Name: users cutover_writer_update; Type: POLICY; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE POLICY cutover_writer_update ON naruv_hosted_identity_review.users FOR UPDATE TO naruv_v85_writer_ci USING (true) WITH CHECK (false);


--
-- Name: sessions insert_session; Type: POLICY; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE POLICY insert_session ON naruv_hosted_identity_review.sessions FOR INSERT TO naruv_hid_writer WITH CHECK (true);


--
-- Name: organizations; Type: ROW SECURITY; Schema: naruv_hosted_identity_review; Owner: -
--

ALTER TABLE naruv_hosted_identity_review.organizations ENABLE ROW LEVEL SECURITY;

--
-- Name: organizations read_internal; Type: POLICY; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE POLICY read_internal ON naruv_hosted_identity_review.organizations FOR SELECT TO naruv_hid_reader, naruv_hid_writer USING (true);


--
-- Name: sessions read_internal; Type: POLICY; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE POLICY read_internal ON naruv_hosted_identity_review.sessions FOR SELECT TO naruv_hid_reader, naruv_hid_writer USING (true);


--
-- Name: users read_internal; Type: POLICY; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE POLICY read_internal ON naruv_hosted_identity_review.users FOR SELECT TO naruv_hid_reader, naruv_hid_writer USING (true);


--
-- Name: sessions; Type: ROW SECURITY; Schema: naruv_hosted_identity_review; Owner: -
--

ALTER TABLE naruv_hosted_identity_review.sessions ENABLE ROW LEVEL SECURITY;

--
-- Name: sessions sync_sessions_read; Type: POLICY; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE POLICY sync_sessions_read ON naruv_hosted_identity_review.sessions FOR SELECT TO naruv_sync_owner_ci USING (true);


--
-- Name: users sync_users_read; Type: POLICY; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE POLICY sync_users_read ON naruv_hosted_identity_review.users FOR SELECT TO naruv_sync_owner_ci USING (true);


--
-- Name: sessions update_session; Type: POLICY; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE POLICY update_session ON naruv_hosted_identity_review.sessions FOR UPDATE TO naruv_hid_writer USING (true) WITH CHECK (true);


--
-- Name: users update_user; Type: POLICY; Schema: naruv_hosted_identity_review; Owner: -
--

CREATE POLICY update_user ON naruv_hosted_identity_review.users FOR UPDATE TO naruv_hid_writer USING (true) WITH CHECK (true);


--
-- Name: users; Type: ROW SECURITY; Schema: naruv_hosted_identity_review; Owner: -
--

ALTER TABLE naruv_hosted_identity_review.users ENABLE ROW LEVEL SECURITY;

--
-- Name: balances; Type: ROW SECURITY; Schema: naruv_inventory; Owner: -
--

ALTER TABLE naruv_inventory.balances ENABLE ROW LEVEL SECURITY;

--
-- Name: balances inventory_scope; Type: POLICY; Schema: naruv_inventory; Owner: -
--

CREATE POLICY inventory_scope ON naruv_inventory.balances TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: items inventory_scope; Type: POLICY; Schema: naruv_inventory; Owner: -
--

CREATE POLICY inventory_scope ON naruv_inventory.items TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: movements inventory_scope; Type: POLICY; Schema: naruv_inventory; Owner: -
--

CREATE POLICY inventory_scope ON naruv_inventory.movements TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: warehouses inventory_scope; Type: POLICY; Schema: naruv_inventory; Owner: -
--

CREATE POLICY inventory_scope ON naruv_inventory.warehouses TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: items; Type: ROW SECURITY; Schema: naruv_inventory; Owner: -
--

ALTER TABLE naruv_inventory.items ENABLE ROW LEVEL SECURITY;

--
-- Name: movements; Type: ROW SECURITY; Schema: naruv_inventory; Owner: -
--

ALTER TABLE naruv_inventory.movements ENABLE ROW LEVEL SECURITY;

--
-- Name: warehouses; Type: ROW SECURITY; Schema: naruv_inventory; Owner: -
--

ALTER TABLE naruv_inventory.warehouses ENABLE ROW LEVEL SECURITY;

--
-- Name: approvals; Type: ROW SECURITY; Schema: naruv_native_review; Owner: -
--

ALTER TABLE naruv_native_review.approvals ENABLE ROW LEVEL SECURITY;

--
-- Name: approvals native_owner_scope; Type: POLICY; Schema: naruv_native_review; Owner: -
--

CREATE POLICY native_owner_scope ON naruv_native_review.approvals TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: receipts native_owner_scope; Type: POLICY; Schema: naruv_native_review; Owner: -
--

CREATE POLICY native_owner_scope ON naruv_native_review.receipts TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: records native_owner_scope; Type: POLICY; Schema: naruv_native_review; Owner: -
--

CREATE POLICY native_owner_scope ON naruv_native_review.records TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: stages native_owner_scope; Type: POLICY; Schema: naruv_native_review; Owner: -
--

CREATE POLICY native_owner_scope ON naruv_native_review.stages TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: receipts; Type: ROW SECURITY; Schema: naruv_native_review; Owner: -
--

ALTER TABLE naruv_native_review.receipts ENABLE ROW LEVEL SECURITY;

--
-- Name: records; Type: ROW SECURITY; Schema: naruv_native_review; Owner: -
--

ALTER TABLE naruv_native_review.records ENABLE ROW LEVEL SECURITY;

--
-- Name: stages; Type: ROW SECURITY; Schema: naruv_native_review; Owner: -
--

ALTER TABLE naruv_native_review.stages ENABLE ROW LEVEL SECURITY;

--
-- Name: boms; Type: ROW SECURITY; Schema: naruv_production; Owner: -
--

ALTER TABLE naruv_production.boms ENABLE ROW LEVEL SECURITY;

--
-- Name: components; Type: ROW SECURITY; Schema: naruv_production; Owner: -
--

ALTER TABLE naruv_production.components ENABLE ROW LEVEL SECURITY;

--
-- Name: events; Type: ROW SECURITY; Schema: naruv_production; Owner: -
--

ALTER TABLE naruv_production.events ENABLE ROW LEVEL SECURITY;

--
-- Name: orders; Type: ROW SECURITY; Schema: naruv_production; Owner: -
--

ALTER TABLE naruv_production.orders ENABLE ROW LEVEL SECURITY;

--
-- Name: boms production_scope; Type: POLICY; Schema: naruv_production; Owner: -
--

CREATE POLICY production_scope ON naruv_production.boms TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: components production_scope; Type: POLICY; Schema: naruv_production; Owner: -
--

CREATE POLICY production_scope ON naruv_production.components TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: events production_scope; Type: POLICY; Schema: naruv_production; Owner: -
--

CREATE POLICY production_scope ON naruv_production.events TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: orders production_scope; Type: POLICY; Schema: naruv_production; Owner: -
--

CREATE POLICY production_scope ON naruv_production.orders TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: conversions conversion_fence_read; Type: POLICY; Schema: naruv_quote_bundle; Owner: -
--

CREATE POLICY conversion_fence_read ON naruv_quote_bundle.conversions FOR SELECT TO naruv_quote_fence USING (true);


--
-- Name: conversions conversion_scope; Type: POLICY; Schema: naruv_quote_bundle; Owner: -
--

CREATE POLICY conversion_scope ON naruv_quote_bundle.conversions TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: conversions; Type: ROW SECURITY; Schema: naruv_quote_bundle; Owner: -
--

ALTER TABLE naruv_quote_bundle.conversions ENABLE ROW LEVEL SECURITY;

--
-- Name: documents; Type: ROW SECURITY; Schema: naruv_trade; Owner: -
--

ALTER TABLE naruv_trade.documents ENABLE ROW LEVEL SECURITY;

--
-- Name: events; Type: ROW SECURITY; Schema: naruv_trade; Owner: -
--

ALTER TABLE naruv_trade.events ENABLE ROW LEVEL SECURITY;

--
-- Name: documents trade_scope; Type: POLICY; Schema: naruv_trade; Owner: -
--

CREATE POLICY trade_scope ON naruv_trade.documents TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: events trade_scope; Type: POLICY; Schema: naruv_trade; Owner: -
--

CREATE POLICY trade_scope ON naruv_trade.events TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: balances; Type: ROW SECURITY; Schema: naruv_valuation; Owner: -
--

ALTER TABLE naruv_valuation.balances ENABLE ROW LEVEL SECURITY;

--
-- Name: cost_journals; Type: ROW SECURITY; Schema: naruv_valuation; Owner: -
--

ALTER TABLE naruv_valuation.cost_journals ENABLE ROW LEVEL SECURITY;

--
-- Name: entries; Type: ROW SECURITY; Schema: naruv_valuation; Owner: -
--

ALTER TABLE naruv_valuation.entries ENABLE ROW LEVEL SECURITY;

--
-- Name: balances valuation_scope; Type: POLICY; Schema: naruv_valuation; Owner: -
--

CREATE POLICY valuation_scope ON naruv_valuation.balances TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: cost_journals valuation_scope; Type: POLICY; Schema: naruv_valuation; Owner: -
--

CREATE POLICY valuation_scope ON naruv_valuation.cost_journals TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- Name: entries valuation_scope; Type: POLICY; Schema: naruv_valuation; Owner: -
--

CREATE POLICY valuation_scope ON naruv_valuation.entries TO naruv_native_owner USING ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text)))) WITH CHECK ((org_id = ( SELECT i.org_id
   FROM jw_dev.stage_identity_v84() i(actor_id, org_id, actor_role, csrf_token, org_name)
  WHERE (i.actor_role = 'admin'::text))));


--
-- PostgreSQL database dump complete
--



RESET ROLE;
GRANT CREATE ON DATABASE postgres TO "naruv_sync_owner_ci";
GRANT CREATE ON DATABASE postgres TO "naruv_hid_owner";
GRANT CREATE ON DATABASE postgres TO "naruv_quote_fence";
GRANT CREATE ON DATABASE postgres TO "naruv_auth_fence_owner";
GRANT CREATE ON DATABASE postgres TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "jw_dev" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "jw_dev" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "jw_dev" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "jw_dev" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "jw_dev" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "jw_dev" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "jw_dev" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "jw_dev" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "jw_dev" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "jw_dev" TO "naruv_v85_writer_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_accounting" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_accounting" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_accounting" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "naruv_accounting" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "naruv_accounting" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_accounting" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_accounting" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_accounting" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "naruv_accounting" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_accounting" TO "naruv_v85_writer_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_auth_fence" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_auth_fence" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_auth_fence" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "naruv_auth_fence" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "naruv_auth_fence" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_auth_fence" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_auth_fence" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_auth_fence" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "naruv_auth_fence" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_auth_fence" TO "naruv_v85_writer_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_bundle" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_bundle" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_bundle" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "naruv_bundle" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "naruv_bundle" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_bundle" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_bundle" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_bundle" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "naruv_bundle" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_bundle" TO "naruv_v85_writer_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_customer_bridge" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_customer_bridge" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_customer_bridge" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "naruv_customer_bridge" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "naruv_customer_bridge" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_customer_bridge" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_customer_bridge" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_customer_bridge" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "naruv_customer_bridge" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_customer_bridge" TO "naruv_v85_writer_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_draft" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_draft" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_draft" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "naruv_draft" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "naruv_draft" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_draft" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_draft" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_draft" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "naruv_draft" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_draft" TO "naruv_v85_writer_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_finance" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_finance" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_finance" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "naruv_finance" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "naruv_finance" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_finance" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_finance" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_finance" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "naruv_finance" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_finance" TO "naruv_v85_writer_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_v85_writer_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_inventory" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_inventory" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_inventory" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "naruv_inventory" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "naruv_inventory" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_inventory" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_inventory" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_inventory" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "naruv_inventory" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_inventory" TO "naruv_v85_writer_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_native_review" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_native_review" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_native_review" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "naruv_native_review" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "naruv_native_review" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_native_review" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_native_review" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_native_review" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "naruv_native_review" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_native_review" TO "naruv_v85_writer_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_production" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_production" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_production" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "naruv_production" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "naruv_production" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_production" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_production" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_production" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "naruv_production" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_production" TO "naruv_v85_writer_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_bundle" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_bundle" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_bundle" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_bundle" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_bundle" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_bundle" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_bundle" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_bundle" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_bundle" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_bundle" TO "naruv_v85_writer_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_fence" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_fence" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_fence" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_fence" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_fence" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_fence" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_fence" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_fence" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_fence" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_quote_fence" TO "naruv_v85_writer_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_sync_ci" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_sync_ci" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_sync_ci" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "naruv_sync_ci" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "naruv_sync_ci" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_sync_ci" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_sync_ci" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_sync_ci" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "naruv_sync_ci" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_sync_ci" TO "naruv_v85_writer_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_trade" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_trade" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_trade" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "naruv_trade" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "naruv_trade" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_trade" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_trade" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_trade" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "naruv_trade" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_trade" TO "naruv_v85_writer_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_valuation" TO "naruv_auth_fence_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_valuation" TO "naruv_hid_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_valuation" TO "naruv_hid_reader";
GRANT USAGE,CREATE ON SCHEMA "naruv_valuation" TO "naruv_hid_writer";
GRANT USAGE,CREATE ON SCHEMA "naruv_valuation" TO "naruv_identity_reader_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_valuation" TO "naruv_messenger_executor_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_valuation" TO "naruv_native_owner";
GRANT USAGE,CREATE ON SCHEMA "naruv_valuation" TO "naruv_quote_fence";
GRANT USAGE,CREATE ON SCHEMA "naruv_valuation" TO "naruv_sync_owner_ci";
GRANT USAGE,CREATE ON SCHEMA "naruv_valuation" TO "naruv_v85_writer_ci";
REVOKE ALL ON TABLE "jw_dev"."audit_logs" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."customers" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."login_failures" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."messenger_attachments" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."messenger_companies" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."messenger_connections" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."messenger_edits" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."messenger_messages" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."messenger_read_positions" FROM PUBLIC;
REVOKE ALL ON SEQUENCE "jw_dev"."messenger_seq_v90" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."mfa_credentials" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."mfa_recovery_codes" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."naruv_review_sources" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."organizations" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."quote_items" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."quotes" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."security_events" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."sessions" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."staff_disabled" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."users" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_accounting"."journals" FROM PUBLIC;
ALTER TABLE "naruv_accounting"."journals" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_accounting"."lines" FROM PUBLIC;
ALTER TABLE "naruv_accounting"."lines" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_accounting"."periods" FROM PUBLIC;
ALTER TABLE "naruv_accounting"."periods" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_auth_fence"."epochs" FROM PUBLIC;
ALTER TABLE "naruv_auth_fence"."epochs" OWNER TO "naruv_auth_fence_owner";
REVOKE ALL ON TABLE "naruv_bundle"."events" FROM PUBLIC;
ALTER TABLE "naruv_bundle"."events" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_bundle"."headers" FROM PUBLIC;
ALTER TABLE "naruv_bundle"."headers" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_bundle"."lines" FROM PUBLIC;
ALTER TABLE "naruv_bundle"."lines" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_customer_bridge"."crosswalk" FROM PUBLIC;
ALTER TABLE "naruv_customer_bridge"."crosswalk" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."attendance" FROM PUBLIC;
ALTER TABLE "naruv_draft"."attendance" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."attendance_receipts" FROM PUBLIC;
ALTER TABLE "naruv_draft"."attendance_receipts" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."document_admissions" FROM PUBLIC;
ALTER TABLE "naruv_draft"."document_admissions" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."document_revisions" FROM PUBLIC;
ALTER TABLE "naruv_draft"."document_revisions" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."documents" FROM PUBLIC;
ALTER TABLE "naruv_draft"."documents" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."pay_periods" FROM PUBLIC;
ALTER TABLE "naruv_draft"."pay_periods" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."period_amendments" FROM PUBLIC;
ALTER TABLE "naruv_draft"."period_amendments" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."period_confirmations" FROM PUBLIC;
ALTER TABLE "naruv_draft"."period_confirmations" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."profile_envelopes" FROM PUBLIC;
ALTER TABLE "naruv_draft"."profile_envelopes" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."profile_retention" FROM PUBLIC;
ALTER TABLE "naruv_draft"."profile_retention" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."profile_revision_history" FROM PUBLIC;
ALTER TABLE "naruv_draft"."profile_revision_history" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."setup_receipts" FROM PUBLIC;
ALTER TABLE "naruv_draft"."setup_receipts" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."staff" FROM PUBLIC;
ALTER TABLE "naruv_draft"."staff" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."staff_archivals" FROM PUBLIC;
ALTER TABLE "naruv_draft"."staff_archivals" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."statement_review_receipts" FROM PUBLIC;
ALTER TABLE "naruv_draft"."statement_review_receipts" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_finance"."bills" FROM PUBLIC;
ALTER TABLE "naruv_finance"."bills" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_finance"."events" FROM PUBLIC;
ALTER TABLE "naruv_finance"."events" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_hosted_identity_review"."organizations" FROM PUBLIC;
ALTER TABLE "naruv_hosted_identity_review"."organizations" OWNER TO "naruv_hid_owner";
REVOKE ALL ON TABLE "naruv_hosted_identity_review"."sessions" FROM PUBLIC;
ALTER TABLE "naruv_hosted_identity_review"."sessions" OWNER TO "naruv_hid_owner";
REVOKE ALL ON TABLE "naruv_hosted_identity_review"."users" FROM PUBLIC;
ALTER TABLE "naruv_hosted_identity_review"."users" OWNER TO "naruv_hid_owner";
REVOKE ALL ON TABLE "naruv_inventory"."balances" FROM PUBLIC;
ALTER TABLE "naruv_inventory"."balances" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_inventory"."items" FROM PUBLIC;
ALTER TABLE "naruv_inventory"."items" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_inventory"."movements" FROM PUBLIC;
ALTER TABLE "naruv_inventory"."movements" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_inventory"."warehouses" FROM PUBLIC;
ALTER TABLE "naruv_inventory"."warehouses" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_native_review"."approvals" FROM PUBLIC;
ALTER TABLE "naruv_native_review"."approvals" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_native_review"."receipts" FROM PUBLIC;
ALTER TABLE "naruv_native_review"."receipts" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_native_review"."records" FROM PUBLIC;
ALTER TABLE "naruv_native_review"."records" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_native_review"."stages" FROM PUBLIC;
ALTER TABLE "naruv_native_review"."stages" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_production"."boms" FROM PUBLIC;
ALTER TABLE "naruv_production"."boms" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_production"."components" FROM PUBLIC;
ALTER TABLE "naruv_production"."components" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_production"."events" FROM PUBLIC;
ALTER TABLE "naruv_production"."events" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_production"."orders" FROM PUBLIC;
ALTER TABLE "naruv_production"."orders" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_quote_bundle"."conversions" FROM PUBLIC;
ALTER TABLE "naruv_quote_bundle"."conversions" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_trade"."documents" FROM PUBLIC;
ALTER TABLE "naruv_trade"."documents" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_trade"."events" FROM PUBLIC;
ALTER TABLE "naruv_trade"."events" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_valuation"."balances" FROM PUBLIC;
ALTER TABLE "naruv_valuation"."balances" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_valuation"."cost_journals" FROM PUBLIC;
ALTER TABLE "naruv_valuation"."cost_journals" OWNER TO "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_valuation"."entries" FROM PUBLIC;
ALTER TABLE "naruv_valuation"."entries" OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "jw_dev"."current_actor_from_session_v82"() FROM PUBLIC;
ALTER FUNCTION "jw_dev"."current_actor_from_session_v82"() OWNER TO "naruv_identity_reader_ci";
REVOKE ALL ON FUNCTION "jw_dev"."current_org_from_session"() FROM PUBLIC;
ALTER FUNCTION "jw_dev"."current_org_from_session"() OWNER TO "naruv_identity_reader_ci";
REVOKE ALL ON FUNCTION "jw_dev"."search_messenger_companies_v90"(p_query text, p_limit integer, p_offset integer) FROM PUBLIC;
ALTER FUNCTION "jw_dev"."search_messenger_companies_v90"(p_query text, p_limit integer, p_offset integer) OWNER TO "naruv_messenger_executor_ci";
REVOKE ALL ON FUNCTION "jw_dev"."stage_identity_v84"() FROM PUBLIC;
ALTER FUNCTION "jw_dev"."stage_identity_v84"() OWNER TO "naruv_identity_reader_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_auth_candidate"(p_email text) FROM PUBLIC;
ALTER FUNCTION "jw_dev"."v85_auth_candidate"(p_email text) OWNER TO "naruv_v85_writer_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_auth_check_csrf"(p_token_hash text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "jw_dev"."v85_auth_check_csrf"(p_token_hash text, p_csrf text) OWNER TO "naruv_identity_reader_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_auth_failed"(p_email text) FROM PUBLIC;
ALTER FUNCTION "jw_dev"."v85_auth_failed"(p_email text) OWNER TO "naruv_v85_writer_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_auth_issue_session"(p_user_id text, p_token_hash text, p_csrf text, p_mfa_counter bigint, p_recovery_hash text) FROM PUBLIC;
ALTER FUNCTION "jw_dev"."v85_auth_issue_session"(p_user_id text, p_token_hash text, p_csrf text, p_mfa_counter bigint, p_recovery_hash text) OWNER TO "naruv_v85_writer_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_auth_revoke_session"(p_token_hash text) FROM PUBLIC;
ALTER FUNCTION "jw_dev"."v85_auth_revoke_session"(p_token_hash text) OWNER TO "naruv_v85_writer_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_candidate_native_ci"(p_email text) FROM PUBLIC;
ALTER FUNCTION "jw_dev"."v85_candidate_native_ci"(p_email text) OWNER TO "naruv_v85_writer_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_issue_native_ci"(p_user_id text, p_token_hash text, p_csrf text, p_mfa_counter bigint, p_recovery_hash text) FROM PUBLIC;
ALTER FUNCTION "jw_dev"."v85_issue_native_ci"(p_user_id text, p_token_hash text, p_csrf text, p_mfa_counter bigint, p_recovery_hash text) OWNER TO "naruv_v85_writer_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_revoke_native_ci"(p_token_hash text) FROM PUBLIC;
ALTER FUNCTION "jw_dev"."v85_revoke_native_ci"(p_token_hash text) OWNER TO "naruv_v85_writer_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v90_edit_text"(p_message_id text, p_new_body text, p_expected_version bigint) FROM PUBLIC;
ALTER FUNCTION "jw_dev"."v90_edit_text"(p_message_id text, p_new_body text, p_expected_version bigint) OWNER TO "naruv_messenger_executor_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v90_mark_read"(p_connection_id text, p_cursor bigint) FROM PUBLIC;
ALTER FUNCTION "jw_dev"."v90_mark_read"(p_connection_id text, p_cursor bigint) OWNER TO "naruv_messenger_executor_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v90_send_text"(p_connection_id text, p_request_id text, p_body text, p_filename text, p_mime text, p_data bytea) FROM PUBLIC;
ALTER FUNCTION "jw_dev"."v90_send_text"(p_connection_id text, p_request_id text, p_body text, p_filename text, p_mime text, p_data bytea) OWNER TO "naruv_messenger_executor_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v90_start_chat"(p_other_org text) FROM PUBLIC;
ALTER FUNCTION "jw_dev"."v90_start_chat"(p_other_org text) OWNER TO "naruv_messenger_executor_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v90_sync_edits"(p_connection_id text, p_after_at timestamp with time zone, p_after_edit_id text, p_limit integer) FROM PUBLIC;
ALTER FUNCTION "jw_dev"."v90_sync_edits"(p_connection_id text, p_after_at timestamp with time zone, p_after_edit_id text, p_limit integer) OWNER TO "naruv_messenger_executor_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v90_sync_messages"(p_connection_id text, p_after_cursor bigint, p_limit integer) FROM PUBLIC;
ALTER FUNCTION "jw_dev"."v90_sync_messages"(p_connection_id text, p_after_cursor bigint, p_limit integer) OWNER TO "naruv_messenger_executor_ci";
REVOKE ALL ON FUNCTION "naruv_accounting"."close_period"(p_month text, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_accounting"."close_period"(p_month text, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_accounting"."inspect_bill"(p_bill text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_accounting"."inspect_bill"(p_bill text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_accounting"."period_guard"() FROM PUBLIC;
ALTER FUNCTION "naruv_accounting"."period_guard"() OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_accounting"."post_finance"() FROM PUBLIC;
ALTER FUNCTION "naruv_accounting"."post_finance"() OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_accounting"."validate_journal"() FROM PUBLIC;
ALTER FUNCTION "naruv_accounting"."validate_journal"() OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_auth_fence"."auth_change"() FROM PUBLIC;
ALTER FUNCTION "naruv_auth_fence"."auth_change"() OWNER TO "naruv_auth_fence_owner";
REVOKE ALL ON FUNCTION "naruv_auth_fence"."lock_actor"(p_actor text) FROM PUBLIC;
ALTER FUNCTION "naruv_auth_fence"."lock_actor"(p_actor text) OWNER TO "naruv_auth_fence_owner";
REVOKE ALL ON FUNCTION "naruv_bundle"."child_id"(p_type text, p_key text, p_line integer) FROM PUBLIC;
ALTER FUNCTION "naruv_bundle"."child_id"(p_type text, p_key text, p_line integer) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_bundle"."command"(p_bundle text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_bundle"."command"(p_bundle text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_bundle"."inspect"(p_bundle text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_bundle"."inspect"(p_bundle text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_customer_bridge"."apply_customer"() FROM PUBLIC;
ALTER FUNCTION "naruv_customer_bridge"."apply_customer"() OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."admit_attendance"(p_worker text, p_period text, p_request text, p_day text, p_regular integer, p_additional integer, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."admit_attendance"(p_worker text, p_period text, p_request text, p_day text, p_regular integer, p_additional integer, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."admit_document"(p_doc text, p_request text, p_format text, p_raw bytea, p_observations jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."admit_document"(p_doc text, p_request text, p_format text, p_raw bytea, p_observations jsonb, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."amend_period"(p_worker text, p_period text, p_request text, p_expected text, p_kind text, p_data jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."amend_period"(p_worker text, p_period text, p_request text, p_expected text, p_kind text, p_data jsonb, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."archive_worker"(p_worker text, p_request text, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."archive_worker"(p_worker text, p_request text, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."document_source"(p_id text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."document_source"(p_id text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."inspect_worker"(p_worker text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."inspect_worker"(p_worker text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."list_workers"(p_after text, p_limit integer, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."list_workers"(p_after text, p_limit integer, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."pay_source"(p_worker text, p_period text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."pay_source"(p_worker text, p_period text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."period_digest"(p_org text, p_worker text, p_period text, p_revision text, p_rate bigint, p_bps integer, p_rows jsonb) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."period_digest"(p_org text, p_worker text, p_period text, p_revision text, p_rate bigint, p_bps integer, p_rows jsonb) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."profile_envelope"(p_worker text, p_revision text, p_envelope jsonb, p_expected text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."profile_envelope"(p_worker text, p_revision text, p_envelope jsonb, p_expected text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."purge_profile"(p_worker text, p_expected text, p_approval text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."purge_profile"(p_worker text, p_expected text, p_approval text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."record_statement_review"(p_worker text, p_period text, p_request text, p_review text, p_statement text, p_render text, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."record_statement_review"(p_worker text, p_period text, p_request text, p_review text, p_statement text, p_render text, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."review_period"(p_worker text, p_period text, p_request text, p_expected text, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."review_period"(p_worker text, p_period text, p_request text, p_expected text, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."revise_document"(p_doc text, p_request text, p_previous text, p_source_sha text, p_observations jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."revise_document"(p_doc text, p_request text, p_previous text, p_source_sha text, p_observations jsonb, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."setup_worker"(p_worker text, p_period text, p_request text, p_revision text, p_rate bigint, p_bps integer, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."setup_worker"(p_worker text, p_period text, p_request text, p_revision text, p_rate bigint, p_bps integer, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."validate_observations"(p_observations jsonb) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."validate_observations"(p_observations jsonb) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."verify_statement_review"(p_worker text, p_period text, p_request text, p_review text, p_statement text, p_render text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_draft"."verify_statement_review"(p_worker text, p_period text, p_request text, p_review text, p_statement text, p_render text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."adjusted_snapshot"(b naruv_finance.bills, p_paid bigint) FROM PUBLIC;
ALTER FUNCTION "naruv_finance"."adjusted_snapshot"(b naruv_finance.bills, p_paid bigint) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."allocation"(p_amount numeric, p_total bigint, p_previous bigint, p_qty bigint) FROM PUBLIC;
ALTER FUNCTION "naruv_finance"."allocation"(p_amount numeric, p_total bigint, p_previous bigint, p_qty bigint) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."command"(p_bill text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_finance"."command"(p_bill text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."command_bundle_internal"(p_bill text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_finance"."command_bundle_internal"(p_bill text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."credit_sum"(p_org text, p_bill text) FROM PUBLIC;
ALTER FUNCTION "naruv_finance"."credit_sum"(p_org text, p_bill text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."credited"(p_org text, p_bill text) FROM PUBLIC;
ALTER FUNCTION "naruv_finance"."credited"(p_org text, p_bill text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."inspect"(p_bill text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_finance"."inspect"(p_bill text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."paid"(p_org text, p_bill text) FROM PUBLIC;
ALTER FUNCTION "naruv_finance"."paid"(p_org text, p_bill text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."returned_qty"(p_org text, p_bill text) FROM PUBLIC;
ALTER FUNCTION "naruv_finance"."returned_qty"(p_org text, p_bill text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."snapshot"(b naruv_finance.bills, p_paid bigint) FROM PUBLIC;
ALTER FUNCTION "naruv_finance"."snapshot"(b naruv_finance.bills, p_paid bigint) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_hosted_identity_review"."change_actor"(p_actor text, p_active boolean, p_role text) FROM PUBLIC;
ALTER FUNCTION "naruv_hosted_identity_review"."change_actor"(p_actor text, p_active boolean, p_role text) OWNER TO "naruv_hid_writer";
REVOKE ALL ON FUNCTION "naruv_hosted_identity_review"."issue"(p_actor text, p_hash text, p_csrf text, p_ttl integer) FROM PUBLIC;
ALTER FUNCTION "naruv_hosted_identity_review"."issue"(p_actor text, p_hash text, p_csrf text, p_ttl integer) OWNER TO "naruv_hid_writer";
REVOKE ALL ON FUNCTION "naruv_hosted_identity_review"."lock_admin"(p_tenant text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_hosted_identity_review"."lock_admin"(p_tenant text, p_csrf text) OWNER TO "naruv_hid_writer";
REVOKE ALL ON FUNCTION "naruv_hosted_identity_review"."revoke"(p_hash text) FROM PUBLIC;
ALTER FUNCTION "naruv_hosted_identity_review"."revoke"(p_hash text) OWNER TO "naruv_hid_writer";
REVOKE ALL ON FUNCTION "naruv_hosted_identity_review"."stage_identity_v84"() FROM PUBLIC;
ALTER FUNCTION "naruv_hosted_identity_review"."stage_identity_v84"() OWNER TO "naruv_hid_reader";
REVOKE ALL ON FUNCTION "naruv_inventory"."import_item"() FROM PUBLIC;
ALTER FUNCTION "naruv_inventory"."import_item"() OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_inventory"."post_movement"(p_source text, p_item text, p_request text, p_from text, p_to text, p_qty bigint, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_inventory"."post_movement"(p_source text, p_item text, p_request text, p_from text, p_to text, p_qty bigint, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_inventory"."post_movement_internal"(p_source text, p_item text, p_request text, p_from text, p_to text, p_qty bigint, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_inventory"."post_movement_internal"(p_source text, p_item text, p_request text, p_from text, p_to text, p_qty bigint, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_inventory"."read_stock"(p_source text, p_item text, p_warehouse text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_inventory"."read_stock"(p_source text, p_item text, p_warehouse text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_inventory"."receipt"(r naruv_inventory.movements) FROM PUBLIC;
ALTER FUNCTION "naruv_inventory"."receipt"(r naruv_inventory.movements) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."approve"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_confirmed boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_native_review"."approve"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_confirmed boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."commit_stage"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_reservation text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_native_review"."commit_stage"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_reservation text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."guard"(p_csrf text, p_kind text) FROM PUBLIC;
ALTER FUNCTION "naruv_native_review"."guard"(p_csrf text, p_kind text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."immutable"() FROM PUBLIC;
ALTER FUNCTION "naruv_native_review"."immutable"() OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."inspect"(p_id text, p_reservation text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_native_review"."inspect"(p_id text, p_reservation text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."read_source"(p_source text, p_entity text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_native_review"."read_source"(p_source text, p_entity text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."receipt_json"(r naruv_native_review.receipts) FROM PUBLIC;
ALTER FUNCTION "naruv_native_review"."receipt_json"(r naruv_native_review.receipts) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."revoke"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_native_review"."revoke"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."store_stage"(p_id text, p_source text, p_entity text, p_format text, p_raw text, p_bytes integer, p_digest text, p_canonical text, p_rows_sha text, p_snapshot text, p_revision text, p_expected text[], p_rows_text text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_native_review"."store_stage"(p_id text, p_source text, p_entity text, p_format text, p_raw text, p_bytes integer, p_digest text, p_canonical text, p_rows_sha text, p_snapshot text, p_revision text, p_expected text[], p_rows_text text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."target_digest"(p_org text, p_source text, p_entity text, p_rev text, p_ids text[]) FROM PUBLIC;
ALTER FUNCTION "naruv_native_review"."target_digest"(p_org text, p_source text, p_entity text, p_rev text, p_ids text[]) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."validated_ids"(p_entity text, p_rows jsonb, p_existing text[]) FROM PUBLIC;
ALTER FUNCTION "naruv_native_review"."validated_ids"(p_entity text, p_rows jsonb, p_existing text[]) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_production"."command"(p_key text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_production"."command"(p_key text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_production"."ident"(v text) FROM PUBLIC;
ALTER FUNCTION "naruv_production"."ident"(v text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_production"."inspect"(p_order text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_production"."inspect"(p_order text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_production"."plan"(p_org text, p_bom text, p_wh text, p_qty bigint) FROM PUBLIC;
ALTER FUNCTION "naruv_production"."plan"(p_org text, p_bom text, p_wh text, p_qty bigint) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_production"."qty"(v jsonb, p_max bigint) FROM PUBLIC;
ALTER FUNCTION "naruv_production"."qty"(v jsonb, p_max bigint) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_production"."requirements"(p_bom text, p_payload jsonb, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_production"."requirements"(p_bom text, p_payload jsonb, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_production"."snapshot"(o naruv_production.orders) FROM PUBLIC;
ALTER FUNCTION "naruv_production"."snapshot"(o naruv_production.orders) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_quote_bundle"."allocate_vat"() FROM PUBLIC;
ALTER FUNCTION "naruv_quote_bundle"."allocate_vat"() OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_quote_bundle"."convert"(p_bundle text, p_request text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_quote_bundle"."convert"(p_bundle text, p_request text, p_payload jsonb, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_quote_bundle"."preview"(p_quote text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_quote_bundle"."preview"(p_quote text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_quote_bundle"."snapshot"(p_org text, p_quote text) FROM PUBLIC;
ALTER FUNCTION "naruv_quote_bundle"."snapshot"(p_org text, p_quote text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_quote_fence"."freeze"() FROM PUBLIC;
ALTER FUNCTION "naruv_quote_fence"."freeze"() OWNER TO "naruv_quote_fence";
REVOKE ALL ON FUNCTION "naruv_sync_ci"."change_actor"(p_actor text, p_active boolean, p_role text) FROM PUBLIC;
ALTER FUNCTION "naruv_sync_ci"."change_actor"(p_actor text, p_active boolean, p_role text) OWNER TO "naruv_sync_owner_ci";
REVOKE ALL ON FUNCTION "naruv_sync_ci"."issue"(p_id text, p_actor text, p_hash text, p_csrf text, p_ttl integer) FROM PUBLIC;
ALTER FUNCTION "naruv_sync_ci"."issue"(p_id text, p_actor text, p_hash text, p_csrf text, p_ttl integer) OWNER TO "naruv_sync_owner_ci";
REVOKE ALL ON FUNCTION "naruv_sync_ci"."revoke"(p_hash text) FROM PUBLIC;
ALTER FUNCTION "naruv_sync_ci"."revoke"(p_hash text) OWNER TO "naruv_sync_owner_ci";
REVOKE ALL ON FUNCTION "naruv_trade"."balance_guard"() FROM PUBLIC;
ALTER FUNCTION "naruv_trade"."balance_guard"() OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_trade"."command"(p_doc text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_trade"."command"(p_doc text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_trade"."command_bundle_internal"(p_doc text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_trade"."command_bundle_internal"(p_doc text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_trade"."inspect"(p_doc text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_trade"."inspect"(p_doc text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_trade"."reserved"(p_org text, p_source text, p_item text, p_wh text) FROM PUBLIC;
ALTER FUNCTION "naruv_trade"."reserved"(p_org text, p_source text, p_item text, p_wh text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_trade"."snapshot"(d naruv_trade.documents) FROM PUBLIC;
ALTER FUNCTION "naruv_trade"."snapshot"(d naruv_trade.documents) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."apply"(p_org text, p_mid text, p_kind text, p_event text, p_incoming numeric) FROM PUBLIC;
ALTER FUNCTION "naruv_valuation"."apply"(p_org text, p_mid text, p_kind text, p_event text, p_incoming numeric) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."audit_ledger"(p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_valuation"."audit_ledger"(p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."check_movement"() FROM PUBLIC;
ALTER FUNCTION "naruv_valuation"."check_movement"() OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."expected_posting"(p_kind text, p_amount numeric, OUT dr text, OUT cr text, OUT amount numeric) FROM PUBLIC;
ALTER FUNCTION "naruv_valuation"."expected_posting"(p_kind text, p_amount numeric, OUT dr text, OUT cr text, OUT amount numeric) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."inspect"(p_src text, p_item text, p_wh text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_valuation"."inspect"(p_src text, p_item text, p_wh text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."overview"(p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_valuation"."overview"(p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."post_cost_journal"() FROM PUBLIC;
ALTER FUNCTION "naruv_valuation"."post_cost_journal"() OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."production_post"() FROM PUBLIC;
ALTER FUNCTION "naruv_valuation"."production_post"() OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."receive"(p_item text, p_request text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_valuation"."receive"(p_item text, p_request text, p_payload jsonb, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."reconcile_bill"(p_bill text, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_valuation"."reconcile_bill"(p_bill text, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."return_adjusted"(p_bill text, p_request text, p_qty bigint, p_advanced boolean, p_ref text, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_valuation"."return_adjusted"(p_bill text, p_request text, p_qty bigint, p_advanced boolean, p_ref text, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."return_bill"(p_bill text, p_request text, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_valuation"."return_bill"(p_bill text, p_request text, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."return_quantity"(p_bill text, p_request text, p_qty bigint, p_confirm boolean, p_csrf text) FROM PUBLIC;
ALTER FUNCTION "naruv_valuation"."return_quantity"(p_bill text, p_request text, p_qty bigint, p_confirm boolean, p_csrf text) OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."trade_post"() FROM PUBLIC;
ALTER FUNCTION "naruv_valuation"."trade_post"() OWNER TO "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."validate_cost_journal"() FROM PUBLIC;
ALTER FUNCTION "naruv_valuation"."validate_cost_journal"() OWNER TO "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "jw_dev" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "jw_dev" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "jw_dev" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "jw_dev" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "jw_dev" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "jw_dev" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "jw_dev" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "jw_dev" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "jw_dev" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "jw_dev" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "jw_dev" FROM PUBLIC;
REVOKE USAGE,CREATE ON SCHEMA "naruv_accounting" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_accounting" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_accounting" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "naruv_accounting" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "naruv_accounting" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_accounting" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_accounting" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_accounting" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_accounting" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_accounting" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "naruv_accounting" FROM PUBLIC;
ALTER SCHEMA "naruv_accounting" OWNER TO "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_auth_fence" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_auth_fence" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_auth_fence" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "naruv_auth_fence" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "naruv_auth_fence" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_auth_fence" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_auth_fence" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_auth_fence" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_auth_fence" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_auth_fence" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "naruv_auth_fence" FROM PUBLIC;
ALTER SCHEMA "naruv_auth_fence" OWNER TO "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_bundle" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_bundle" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_bundle" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "naruv_bundle" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "naruv_bundle" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_bundle" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_bundle" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_bundle" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_bundle" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_bundle" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "naruv_bundle" FROM PUBLIC;
ALTER SCHEMA "naruv_bundle" OWNER TO "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_customer_bridge" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_customer_bridge" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_customer_bridge" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "naruv_customer_bridge" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "naruv_customer_bridge" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_customer_bridge" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_customer_bridge" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_customer_bridge" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_customer_bridge" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_customer_bridge" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "naruv_customer_bridge" FROM PUBLIC;
ALTER SCHEMA "naruv_customer_bridge" OWNER TO "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_draft" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_draft" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_draft" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "naruv_draft" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "naruv_draft" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_draft" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_draft" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_draft" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_draft" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_draft" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "naruv_draft" FROM PUBLIC;
ALTER SCHEMA "naruv_draft" OWNER TO "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_finance" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_finance" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_finance" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "naruv_finance" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "naruv_finance" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_finance" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_finance" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_finance" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_finance" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_finance" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "naruv_finance" FROM PUBLIC;
ALTER SCHEMA "naruv_finance" OWNER TO "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_hosted_identity_review" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "naruv_hosted_identity_review" FROM PUBLIC;
ALTER SCHEMA "naruv_hosted_identity_review" OWNER TO "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_inventory" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_inventory" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_inventory" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "naruv_inventory" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "naruv_inventory" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_inventory" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_inventory" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_inventory" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_inventory" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_inventory" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "naruv_inventory" FROM PUBLIC;
ALTER SCHEMA "naruv_inventory" OWNER TO "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_native_review" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_native_review" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_native_review" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "naruv_native_review" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "naruv_native_review" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_native_review" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_native_review" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_native_review" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_native_review" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_native_review" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "naruv_native_review" FROM PUBLIC;
ALTER SCHEMA "naruv_native_review" OWNER TO "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_production" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_production" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_production" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "naruv_production" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "naruv_production" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_production" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_production" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_production" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_production" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_production" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "naruv_production" FROM PUBLIC;
ALTER SCHEMA "naruv_production" OWNER TO "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_bundle" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_bundle" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_bundle" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_bundle" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_bundle" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_bundle" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_bundle" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_bundle" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_bundle" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_bundle" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "naruv_quote_bundle" FROM PUBLIC;
ALTER SCHEMA "naruv_quote_bundle" OWNER TO "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_fence" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_fence" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_fence" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_fence" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_fence" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_fence" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_fence" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_fence" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_fence" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_quote_fence" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "naruv_quote_fence" FROM PUBLIC;
ALTER SCHEMA "naruv_quote_fence" OWNER TO "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_sync_ci" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_sync_ci" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_sync_ci" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "naruv_sync_ci" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "naruv_sync_ci" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_sync_ci" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_sync_ci" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_sync_ci" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_sync_ci" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_sync_ci" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "naruv_sync_ci" FROM PUBLIC;
ALTER SCHEMA "naruv_sync_ci" OWNER TO "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_trade" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_trade" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_trade" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "naruv_trade" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "naruv_trade" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_trade" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_trade" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_trade" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_trade" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_trade" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "naruv_trade" FROM PUBLIC;
ALTER SCHEMA "naruv_trade" OWNER TO "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_valuation" FROM "naruv_auth_fence_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_valuation" FROM "naruv_hid_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_valuation" FROM "naruv_hid_reader";
REVOKE USAGE,CREATE ON SCHEMA "naruv_valuation" FROM "naruv_hid_writer";
REVOKE USAGE,CREATE ON SCHEMA "naruv_valuation" FROM "naruv_identity_reader_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_valuation" FROM "naruv_messenger_executor_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_valuation" FROM "naruv_native_owner";
REVOKE USAGE,CREATE ON SCHEMA "naruv_valuation" FROM "naruv_quote_fence";
REVOKE USAGE,CREATE ON SCHEMA "naruv_valuation" FROM "naruv_sync_owner_ci";
REVOKE USAGE,CREATE ON SCHEMA "naruv_valuation" FROM "naruv_v85_writer_ci";
REVOKE ALL ON SCHEMA "naruv_valuation" FROM PUBLIC;
ALTER SCHEMA "naruv_valuation" OWNER TO "naruv_native_owner";
REVOKE CREATE ON DATABASE postgres FROM "naruv_sync_owner_ci";
REVOKE CREATE ON DATABASE postgres FROM "naruv_hid_owner";
REVOKE CREATE ON DATABASE postgres FROM "naruv_quote_fence";
REVOKE CREATE ON DATABASE postgres FROM "naruv_auth_fence_owner";
REVOKE CREATE ON DATABASE postgres FROM "naruv_native_owner";
SET ROLE "naruv_auth_fence_owner";
REVOKE ALL ON SCHEMA "naruv_auth_fence" FROM PUBLIC;
REVOKE ALL ON SCHEMA "naruv_auth_fence" FROM "naruv_auth_fence_owner";
GRANT CREATE ON SCHEMA "naruv_auth_fence" TO "naruv_auth_fence_owner";
GRANT USAGE ON SCHEMA "naruv_auth_fence" TO "naruv_auth_fence_owner";
GRANT USAGE ON SCHEMA "naruv_auth_fence" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_hid_owner";
REVOKE ALL ON SCHEMA "naruv_hosted_identity_review" FROM PUBLIC;
REVOKE ALL ON SCHEMA "naruv_hosted_identity_review" FROM "naruv_hid_owner";
GRANT USAGE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_hid_auth";
GRANT USAGE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_hid_business";
GRANT USAGE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_hid_ingest";
GRANT CREATE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_hid_owner";
GRANT USAGE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_hid_owner";
GRANT USAGE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_hid_reader";
GRANT USAGE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_hid_writer";
GRANT USAGE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_identity_reader_ci";
GRANT USAGE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_sync_owner_ci";
GRANT USAGE ON SCHEMA "naruv_hosted_identity_review" TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON SCHEMA "naruv_accounting" FROM PUBLIC;
REVOKE ALL ON SCHEMA "naruv_accounting" FROM "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_accounting" TO "jw_app_dev";
GRANT CREATE ON SCHEMA "naruv_accounting" TO "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_accounting" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON SCHEMA "naruv_bundle" FROM PUBLIC;
REVOKE ALL ON SCHEMA "naruv_bundle" FROM "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_bundle" TO "jw_app_dev";
GRANT CREATE ON SCHEMA "naruv_bundle" TO "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_bundle" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON SCHEMA "naruv_customer_bridge" FROM PUBLIC;
REVOKE ALL ON SCHEMA "naruv_customer_bridge" FROM "naruv_native_owner";
GRANT CREATE ON SCHEMA "naruv_customer_bridge" TO "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_customer_bridge" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON SCHEMA "naruv_draft" FROM PUBLIC;
REVOKE ALL ON SCHEMA "naruv_draft" FROM "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_draft" TO "jw_app_dev";
GRANT CREATE ON SCHEMA "naruv_draft" TO "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_draft" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON SCHEMA "naruv_finance" FROM PUBLIC;
REVOKE ALL ON SCHEMA "naruv_finance" FROM "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_finance" TO "jw_app_dev";
GRANT CREATE ON SCHEMA "naruv_finance" TO "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_finance" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON SCHEMA "naruv_inventory" FROM PUBLIC;
REVOKE ALL ON SCHEMA "naruv_inventory" FROM "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_inventory" TO "jw_app_dev";
GRANT CREATE ON SCHEMA "naruv_inventory" TO "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_inventory" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON SCHEMA "naruv_native_review" FROM PUBLIC;
REVOKE ALL ON SCHEMA "naruv_native_review" FROM "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_native_review" TO "jw_app_dev";
GRANT CREATE ON SCHEMA "naruv_native_review" TO "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_native_review" TO "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_native_review" TO "naruv_native_stage";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON SCHEMA "naruv_production" FROM PUBLIC;
REVOKE ALL ON SCHEMA "naruv_production" FROM "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_production" TO "jw_app_dev";
GRANT CREATE ON SCHEMA "naruv_production" TO "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_production" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON SCHEMA "naruv_quote_bundle" FROM PUBLIC;
REVOKE ALL ON SCHEMA "naruv_quote_bundle" FROM "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_quote_bundle" TO "jw_app_dev";
GRANT CREATE ON SCHEMA "naruv_quote_bundle" TO "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_quote_bundle" TO "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_quote_bundle" TO "naruv_quote_fence";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON SCHEMA "naruv_trade" FROM PUBLIC;
REVOKE ALL ON SCHEMA "naruv_trade" FROM "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_trade" TO "jw_app_dev";
GRANT CREATE ON SCHEMA "naruv_trade" TO "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_trade" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON SCHEMA "naruv_valuation" FROM PUBLIC;
REVOKE ALL ON SCHEMA "naruv_valuation" FROM "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_valuation" TO "jw_app_dev";
GRANT CREATE ON SCHEMA "naruv_valuation" TO "naruv_native_owner";
GRANT USAGE ON SCHEMA "naruv_valuation" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_quote_fence";
REVOKE ALL ON SCHEMA "naruv_quote_fence" FROM PUBLIC;
REVOKE ALL ON SCHEMA "naruv_quote_fence" FROM "naruv_quote_fence";
GRANT CREATE ON SCHEMA "naruv_quote_fence" TO "naruv_quote_fence";
GRANT USAGE ON SCHEMA "naruv_quote_fence" TO "naruv_quote_fence";
RESET ROLE;
SET ROLE "naruv_sync_owner_ci";
REVOKE ALL ON SCHEMA "naruv_sync_ci" FROM PUBLIC;
REVOKE ALL ON SCHEMA "naruv_sync_ci" FROM "naruv_sync_owner_ci";
GRANT USAGE ON SCHEMA "naruv_sync_ci" TO "naruv_sync_broker_ci";
GRANT CREATE ON SCHEMA "naruv_sync_ci" TO "naruv_sync_owner_ci";
GRANT USAGE ON SCHEMA "naruv_sync_ci" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON SCHEMA "jw_dev" FROM PUBLIC;
REVOKE ALL ON SCHEMA "jw_dev" FROM "postgres";
GRANT USAGE ON SCHEMA "jw_dev" TO "jw_app_dev";
GRANT USAGE ON SCHEMA "jw_dev" TO "jw_auth_stage_v85";
GRANT USAGE ON SCHEMA "jw_dev" TO "naruv_identity_reader_ci";
GRANT USAGE ON SCHEMA "jw_dev" TO "naruv_messenger_executor_ci";
GRANT USAGE ON SCHEMA "jw_dev" TO "naruv_native_owner";
GRANT USAGE ON SCHEMA "jw_dev" TO "naruv_native_stage";
GRANT USAGE ON SCHEMA "jw_dev" TO "naruv_sync_owner_ci";
GRANT USAGE ON SCHEMA "jw_dev" TO "naruv_v85_writer_ci";
GRANT CREATE ON SCHEMA "jw_dev" TO "postgres";
GRANT USAGE ON SCHEMA "jw_dev" TO "postgres";
RESET ROLE;
SET ROLE "naruv_auth_fence_owner";
REVOKE ALL ON FUNCTION "naruv_auth_fence"."auth_change"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_auth_fence"."auth_change"() FROM "naruv_auth_fence_owner";
GRANT EXECUTE ON FUNCTION "naruv_auth_fence"."auth_change"() TO "naruv_auth_fence_owner";
RESET ROLE;
SET ROLE "naruv_auth_fence_owner";
REVOKE ALL ON FUNCTION "naruv_auth_fence"."lock_actor"(p_actor text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_auth_fence"."lock_actor"(p_actor text) FROM "naruv_auth_fence_owner";
GRANT EXECUTE ON FUNCTION "naruv_auth_fence"."lock_actor"(p_actor text) TO "naruv_auth_fence_owner";
GRANT EXECUTE ON FUNCTION "naruv_auth_fence"."lock_actor"(p_actor text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_auth_fence_owner";
REVOKE ALL ON TABLE "naruv_auth_fence"."epochs" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_auth_fence"."epochs" FROM "naruv_auth_fence_owner";
GRANT DELETE ON TABLE "naruv_auth_fence"."epochs" TO "naruv_auth_fence_owner";
GRANT INSERT ON TABLE "naruv_auth_fence"."epochs" TO "naruv_auth_fence_owner";
GRANT MAINTAIN ON TABLE "naruv_auth_fence"."epochs" TO "naruv_auth_fence_owner";
GRANT REFERENCES ON TABLE "naruv_auth_fence"."epochs" TO "naruv_auth_fence_owner";
GRANT SELECT ON TABLE "naruv_auth_fence"."epochs" TO "naruv_auth_fence_owner";
GRANT TRIGGER ON TABLE "naruv_auth_fence"."epochs" TO "naruv_auth_fence_owner";
GRANT TRUNCATE ON TABLE "naruv_auth_fence"."epochs" TO "naruv_auth_fence_owner";
GRANT UPDATE ON TABLE "naruv_auth_fence"."epochs" TO "naruv_auth_fence_owner";
RESET ROLE;
SET ROLE "naruv_hid_owner";
REVOKE ALL ON TABLE "naruv_hosted_identity_review"."organizations" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_hosted_identity_review"."organizations" FROM "naruv_hid_owner";
GRANT DELETE ON TABLE "naruv_hosted_identity_review"."organizations" TO "naruv_hid_owner";
GRANT INSERT ON TABLE "naruv_hosted_identity_review"."organizations" TO "naruv_hid_owner";
GRANT MAINTAIN ON TABLE "naruv_hosted_identity_review"."organizations" TO "naruv_hid_owner";
GRANT REFERENCES ON TABLE "naruv_hosted_identity_review"."organizations" TO "naruv_hid_owner";
GRANT SELECT ON TABLE "naruv_hosted_identity_review"."organizations" TO "naruv_hid_owner";
GRANT TRIGGER ON TABLE "naruv_hosted_identity_review"."organizations" TO "naruv_hid_owner";
GRANT TRUNCATE ON TABLE "naruv_hosted_identity_review"."organizations" TO "naruv_hid_owner";
GRANT UPDATE ON TABLE "naruv_hosted_identity_review"."organizations" TO "naruv_hid_owner";
GRANT SELECT ON TABLE "naruv_hosted_identity_review"."organizations" TO "naruv_hid_reader";
GRANT SELECT ON TABLE "naruv_hosted_identity_review"."organizations" TO "naruv_hid_writer";
RESET ROLE;
SET ROLE "naruv_hid_owner";
REVOKE ALL ON TABLE "naruv_hosted_identity_review"."sessions" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_hosted_identity_review"."sessions" FROM "naruv_hid_owner";
GRANT DELETE ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_hid_owner";
GRANT INSERT ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_hid_owner";
GRANT MAINTAIN ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_hid_owner";
GRANT REFERENCES ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_hid_owner";
GRANT SELECT ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_hid_owner";
GRANT TRIGGER ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_hid_owner";
GRANT TRUNCATE ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_hid_owner";
GRANT UPDATE ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_hid_owner";
GRANT SELECT ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_hid_reader";
GRANT INSERT ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_hid_writer";
GRANT SELECT ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_hid_writer";
GRANT INSERT ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_v85_writer_ci";
GRANT SELECT ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
REVOKE ALL ON TABLE "naruv_hosted_identity_review"."users" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_hosted_identity_review"."users" FROM "naruv_hid_owner";
GRANT DELETE ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_hid_owner";
GRANT INSERT ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_hid_owner";
GRANT MAINTAIN ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_hid_owner";
GRANT REFERENCES ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_hid_owner";
GRANT SELECT ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_hid_owner";
GRANT TRIGGER ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_hid_owner";
GRANT TRUNCATE ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_hid_owner";
GRANT UPDATE ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_hid_owner";
GRANT SELECT ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_hid_reader";
GRANT SELECT ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_hid_writer";
GRANT SELECT ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "naruv_hid_reader";
REVOKE ALL ON FUNCTION "naruv_hosted_identity_review"."stage_identity_v84"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_hosted_identity_review"."stage_identity_v84"() FROM "naruv_hid_reader";
GRANT EXECUTE ON FUNCTION "naruv_hosted_identity_review"."stage_identity_v84"() TO "naruv_hid_business";
GRANT EXECUTE ON FUNCTION "naruv_hosted_identity_review"."stage_identity_v84"() TO "naruv_hid_ingest";
GRANT EXECUTE ON FUNCTION "naruv_hosted_identity_review"."stage_identity_v84"() TO "naruv_hid_reader";
GRANT EXECUTE ON FUNCTION "naruv_hosted_identity_review"."stage_identity_v84"() TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_hid_writer";
REVOKE ALL ON FUNCTION "naruv_hosted_identity_review"."change_actor"(p_actor text, p_active boolean, p_role text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_hosted_identity_review"."change_actor"(p_actor text, p_active boolean, p_role text) FROM "naruv_hid_writer";
GRANT EXECUTE ON FUNCTION "naruv_hosted_identity_review"."change_actor"(p_actor text, p_active boolean, p_role text) TO "naruv_hid_writer";
GRANT EXECUTE ON FUNCTION "naruv_hosted_identity_review"."change_actor"(p_actor text, p_active boolean, p_role text) TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "naruv_hid_writer";
REVOKE ALL ON FUNCTION "naruv_hosted_identity_review"."issue"(p_actor text, p_hash text, p_csrf text, p_ttl integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_hosted_identity_review"."issue"(p_actor text, p_hash text, p_csrf text, p_ttl integer) FROM "naruv_hid_writer";
GRANT EXECUTE ON FUNCTION "naruv_hosted_identity_review"."issue"(p_actor text, p_hash text, p_csrf text, p_ttl integer) TO "naruv_hid_writer";
GRANT EXECUTE ON FUNCTION "naruv_hosted_identity_review"."issue"(p_actor text, p_hash text, p_csrf text, p_ttl integer) TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "naruv_hid_writer";
REVOKE ALL ON FUNCTION "naruv_hosted_identity_review"."lock_admin"(p_tenant text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_hosted_identity_review"."lock_admin"(p_tenant text, p_csrf text) FROM "naruv_hid_writer";
GRANT EXECUTE ON FUNCTION "naruv_hosted_identity_review"."lock_admin"(p_tenant text, p_csrf text) TO "naruv_hid_writer";
GRANT EXECUTE ON FUNCTION "naruv_hosted_identity_review"."lock_admin"(p_tenant text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_hid_writer";
REVOKE ALL ON FUNCTION "naruv_hosted_identity_review"."revoke"(p_hash text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_hosted_identity_review"."revoke"(p_hash text) FROM "naruv_hid_writer";
GRANT EXECUTE ON FUNCTION "naruv_hosted_identity_review"."revoke"(p_hash text) TO "naruv_hid_writer";
GRANT EXECUTE ON FUNCTION "naruv_hosted_identity_review"."revoke"(p_hash text) TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "naruv_identity_reader_ci";
REVOKE ALL ON FUNCTION "jw_dev"."current_actor_from_session_v82"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."current_actor_from_session_v82"() FROM "naruv_identity_reader_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."current_actor_from_session_v82"() TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "jw_dev"."current_actor_from_session_v82"() TO "naruv_identity_reader_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."current_actor_from_session_v82"() TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "naruv_identity_reader_ci";
REVOKE ALL ON FUNCTION "jw_dev"."current_org_from_session"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."current_org_from_session"() FROM "naruv_identity_reader_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."current_org_from_session"() TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "jw_dev"."current_org_from_session"() TO "naruv_identity_reader_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."current_org_from_session"() TO "naruv_messenger_executor_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."current_org_from_session"() TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_identity_reader_ci";
REVOKE ALL ON FUNCTION "jw_dev"."stage_identity_v84"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."stage_identity_v84"() FROM "naruv_identity_reader_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."stage_identity_v84"() TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "jw_dev"."stage_identity_v84"() TO "naruv_identity_reader_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."stage_identity_v84"() TO "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "jw_dev"."stage_identity_v84"() TO "naruv_native_stage";
RESET ROLE;
SET ROLE "naruv_identity_reader_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_auth_check_csrf"(p_token_hash text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."v85_auth_check_csrf"(p_token_hash text, p_csrf text) FROM "naruv_identity_reader_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."v85_auth_check_csrf"(p_token_hash text, p_csrf text) TO "jw_auth_stage_v85";
GRANT EXECUTE ON FUNCTION "jw_dev"."v85_auth_check_csrf"(p_token_hash text, p_csrf text) TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "naruv_messenger_executor_ci";
REVOKE ALL ON FUNCTION "jw_dev"."search_messenger_companies_v90"(p_query text, p_limit integer, p_offset integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."search_messenger_companies_v90"(p_query text, p_limit integer, p_offset integer) FROM "naruv_messenger_executor_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."search_messenger_companies_v90"(p_query text, p_limit integer, p_offset integer) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "jw_dev"."search_messenger_companies_v90"(p_query text, p_limit integer, p_offset integer) TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "naruv_messenger_executor_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v90_edit_text"(p_message_id text, p_new_body text, p_expected_version bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."v90_edit_text"(p_message_id text, p_new_body text, p_expected_version bigint) FROM "naruv_messenger_executor_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."v90_edit_text"(p_message_id text, p_new_body text, p_expected_version bigint) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "jw_dev"."v90_edit_text"(p_message_id text, p_new_body text, p_expected_version bigint) TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "naruv_messenger_executor_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v90_mark_read"(p_connection_id text, p_cursor bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."v90_mark_read"(p_connection_id text, p_cursor bigint) FROM "naruv_messenger_executor_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."v90_mark_read"(p_connection_id text, p_cursor bigint) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "jw_dev"."v90_mark_read"(p_connection_id text, p_cursor bigint) TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "naruv_messenger_executor_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v90_send_text"(p_connection_id text, p_request_id text, p_body text, p_filename text, p_mime text, p_data bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."v90_send_text"(p_connection_id text, p_request_id text, p_body text, p_filename text, p_mime text, p_data bytea) FROM "naruv_messenger_executor_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."v90_send_text"(p_connection_id text, p_request_id text, p_body text, p_filename text, p_mime text, p_data bytea) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "jw_dev"."v90_send_text"(p_connection_id text, p_request_id text, p_body text, p_filename text, p_mime text, p_data bytea) TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "naruv_messenger_executor_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v90_start_chat"(p_other_org text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."v90_start_chat"(p_other_org text) FROM "naruv_messenger_executor_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."v90_start_chat"(p_other_org text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "jw_dev"."v90_start_chat"(p_other_org text) TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "naruv_messenger_executor_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v90_sync_edits"(p_connection_id text, p_after_at timestamp with time zone, p_after_edit_id text, p_limit integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."v90_sync_edits"(p_connection_id text, p_after_at timestamp with time zone, p_after_edit_id text, p_limit integer) FROM "naruv_messenger_executor_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."v90_sync_edits"(p_connection_id text, p_after_at timestamp with time zone, p_after_edit_id text, p_limit integer) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "jw_dev"."v90_sync_edits"(p_connection_id text, p_after_at timestamp with time zone, p_after_edit_id text, p_limit integer) TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "naruv_messenger_executor_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v90_sync_messages"(p_connection_id text, p_after_cursor bigint, p_limit integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."v90_sync_messages"(p_connection_id text, p_after_cursor bigint, p_limit integer) FROM "naruv_messenger_executor_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."v90_sync_messages"(p_connection_id text, p_after_cursor bigint, p_limit integer) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "jw_dev"."v90_sync_messages"(p_connection_id text, p_after_cursor bigint, p_limit integer) TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_accounting"."close_period"(p_month text, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_accounting"."close_period"(p_month text, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_accounting"."close_period"(p_month text, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_accounting"."close_period"(p_month text, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_accounting"."inspect_bill"(p_bill text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_accounting"."inspect_bill"(p_bill text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_accounting"."inspect_bill"(p_bill text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_accounting"."inspect_bill"(p_bill text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_accounting"."period_guard"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_accounting"."period_guard"() FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_accounting"."period_guard"() TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_accounting"."post_finance"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_accounting"."post_finance"() FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_accounting"."post_finance"() TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_accounting"."validate_journal"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_accounting"."validate_journal"() FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_accounting"."validate_journal"() TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_bundle"."child_id"(p_type text, p_key text, p_line integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_bundle"."child_id"(p_type text, p_key text, p_line integer) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_bundle"."child_id"(p_type text, p_key text, p_line integer) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_bundle"."command"(p_bundle text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_bundle"."command"(p_bundle text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_bundle"."command"(p_bundle text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_bundle"."command"(p_bundle text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_bundle"."inspect"(p_bundle text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_bundle"."inspect"(p_bundle text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_bundle"."inspect"(p_bundle text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_bundle"."inspect"(p_bundle text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_customer_bridge"."apply_customer"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_customer_bridge"."apply_customer"() FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_customer_bridge"."apply_customer"() TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."admit_attendance"(p_worker text, p_period text, p_request text, p_day text, p_regular integer, p_additional integer, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."admit_attendance"(p_worker text, p_period text, p_request text, p_day text, p_regular integer, p_additional integer, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."admit_attendance"(p_worker text, p_period text, p_request text, p_day text, p_regular integer, p_additional integer, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_draft"."admit_attendance"(p_worker text, p_period text, p_request text, p_day text, p_regular integer, p_additional integer, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."admit_document"(p_doc text, p_request text, p_format text, p_raw bytea, p_observations jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."admit_document"(p_doc text, p_request text, p_format text, p_raw bytea, p_observations jsonb, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."admit_document"(p_doc text, p_request text, p_format text, p_raw bytea, p_observations jsonb, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_draft"."admit_document"(p_doc text, p_request text, p_format text, p_raw bytea, p_observations jsonb, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."amend_period"(p_worker text, p_period text, p_request text, p_expected text, p_kind text, p_data jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."amend_period"(p_worker text, p_period text, p_request text, p_expected text, p_kind text, p_data jsonb, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."amend_period"(p_worker text, p_period text, p_request text, p_expected text, p_kind text, p_data jsonb, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_draft"."amend_period"(p_worker text, p_period text, p_request text, p_expected text, p_kind text, p_data jsonb, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."archive_worker"(p_worker text, p_request text, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."archive_worker"(p_worker text, p_request text, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."archive_worker"(p_worker text, p_request text, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_draft"."archive_worker"(p_worker text, p_request text, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."document_source"(p_id text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."document_source"(p_id text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."document_source"(p_id text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_draft"."document_source"(p_id text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."inspect_worker"(p_worker text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."inspect_worker"(p_worker text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."inspect_worker"(p_worker text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_draft"."inspect_worker"(p_worker text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."list_workers"(p_after text, p_limit integer, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."list_workers"(p_after text, p_limit integer, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."list_workers"(p_after text, p_limit integer, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_draft"."list_workers"(p_after text, p_limit integer, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."pay_source"(p_worker text, p_period text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."pay_source"(p_worker text, p_period text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."pay_source"(p_worker text, p_period text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_draft"."pay_source"(p_worker text, p_period text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."period_digest"(p_org text, p_worker text, p_period text, p_revision text, p_rate bigint, p_bps integer, p_rows jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."period_digest"(p_org text, p_worker text, p_period text, p_revision text, p_rate bigint, p_bps integer, p_rows jsonb) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."period_digest"(p_org text, p_worker text, p_period text, p_revision text, p_rate bigint, p_bps integer, p_rows jsonb) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."profile_envelope"(p_worker text, p_revision text, p_envelope jsonb, p_expected text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."profile_envelope"(p_worker text, p_revision text, p_envelope jsonb, p_expected text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."profile_envelope"(p_worker text, p_revision text, p_envelope jsonb, p_expected text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_draft"."profile_envelope"(p_worker text, p_revision text, p_envelope jsonb, p_expected text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."purge_profile"(p_worker text, p_expected text, p_approval text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."purge_profile"(p_worker text, p_expected text, p_approval text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."purge_profile"(p_worker text, p_expected text, p_approval text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_draft"."purge_profile"(p_worker text, p_expected text, p_approval text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."record_statement_review"(p_worker text, p_period text, p_request text, p_review text, p_statement text, p_render text, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."record_statement_review"(p_worker text, p_period text, p_request text, p_review text, p_statement text, p_render text, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."record_statement_review"(p_worker text, p_period text, p_request text, p_review text, p_statement text, p_render text, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_draft"."record_statement_review"(p_worker text, p_period text, p_request text, p_review text, p_statement text, p_render text, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."review_period"(p_worker text, p_period text, p_request text, p_expected text, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."review_period"(p_worker text, p_period text, p_request text, p_expected text, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."review_period"(p_worker text, p_period text, p_request text, p_expected text, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_draft"."review_period"(p_worker text, p_period text, p_request text, p_expected text, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."revise_document"(p_doc text, p_request text, p_previous text, p_source_sha text, p_observations jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."revise_document"(p_doc text, p_request text, p_previous text, p_source_sha text, p_observations jsonb, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."revise_document"(p_doc text, p_request text, p_previous text, p_source_sha text, p_observations jsonb, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_draft"."revise_document"(p_doc text, p_request text, p_previous text, p_source_sha text, p_observations jsonb, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."setup_worker"(p_worker text, p_period text, p_request text, p_revision text, p_rate bigint, p_bps integer, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."setup_worker"(p_worker text, p_period text, p_request text, p_revision text, p_rate bigint, p_bps integer, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."setup_worker"(p_worker text, p_period text, p_request text, p_revision text, p_rate bigint, p_bps integer, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_draft"."setup_worker"(p_worker text, p_period text, p_request text, p_revision text, p_rate bigint, p_bps integer, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."validate_observations"(p_observations jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."validate_observations"(p_observations jsonb) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."validate_observations"(p_observations jsonb) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_draft"."verify_statement_review"(p_worker text, p_period text, p_request text, p_review text, p_statement text, p_render text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_draft"."verify_statement_review"(p_worker text, p_period text, p_request text, p_review text, p_statement text, p_render text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_draft"."verify_statement_review"(p_worker text, p_period text, p_request text, p_review text, p_statement text, p_render text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_draft"."verify_statement_review"(p_worker text, p_period text, p_request text, p_review text, p_statement text, p_render text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."adjusted_snapshot"(b naruv_finance.bills, p_paid bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_finance"."adjusted_snapshot"(b naruv_finance.bills, p_paid bigint) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_finance"."adjusted_snapshot"(b naruv_finance.bills, p_paid bigint) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."allocation"(p_amount numeric, p_total bigint, p_previous bigint, p_qty bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_finance"."allocation"(p_amount numeric, p_total bigint, p_previous bigint, p_qty bigint) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_finance"."allocation"(p_amount numeric, p_total bigint, p_previous bigint, p_qty bigint) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."command"(p_bill text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_finance"."command"(p_bill text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_finance"."command"(p_bill text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_finance"."command"(p_bill text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."command_bundle_internal"(p_bill text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_finance"."command_bundle_internal"(p_bill text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_finance"."command_bundle_internal"(p_bill text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."credit_sum"(p_org text, p_bill text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_finance"."credit_sum"(p_org text, p_bill text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_finance"."credit_sum"(p_org text, p_bill text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."credited"(p_org text, p_bill text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_finance"."credited"(p_org text, p_bill text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_finance"."credited"(p_org text, p_bill text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."inspect"(p_bill text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_finance"."inspect"(p_bill text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_finance"."inspect"(p_bill text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_finance"."inspect"(p_bill text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."paid"(p_org text, p_bill text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_finance"."paid"(p_org text, p_bill text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_finance"."paid"(p_org text, p_bill text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."returned_qty"(p_org text, p_bill text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_finance"."returned_qty"(p_org text, p_bill text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_finance"."returned_qty"(p_org text, p_bill text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_finance"."snapshot"(b naruv_finance.bills, p_paid bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_finance"."snapshot"(b naruv_finance.bills, p_paid bigint) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_finance"."snapshot"(b naruv_finance.bills, p_paid bigint) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_inventory"."import_item"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_inventory"."import_item"() FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_inventory"."import_item"() TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_inventory"."post_movement"(p_source text, p_item text, p_request text, p_from text, p_to text, p_qty bigint, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_inventory"."post_movement"(p_source text, p_item text, p_request text, p_from text, p_to text, p_qty bigint, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_inventory"."post_movement"(p_source text, p_item text, p_request text, p_from text, p_to text, p_qty bigint, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_inventory"."post_movement"(p_source text, p_item text, p_request text, p_from text, p_to text, p_qty bigint, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_inventory"."post_movement_internal"(p_source text, p_item text, p_request text, p_from text, p_to text, p_qty bigint, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_inventory"."post_movement_internal"(p_source text, p_item text, p_request text, p_from text, p_to text, p_qty bigint, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_inventory"."post_movement_internal"(p_source text, p_item text, p_request text, p_from text, p_to text, p_qty bigint, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_inventory"."read_stock"(p_source text, p_item text, p_warehouse text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_inventory"."read_stock"(p_source text, p_item text, p_warehouse text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_inventory"."read_stock"(p_source text, p_item text, p_warehouse text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_inventory"."read_stock"(p_source text, p_item text, p_warehouse text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_inventory"."receipt"(r naruv_inventory.movements) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_inventory"."receipt"(r naruv_inventory.movements) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_inventory"."receipt"(r naruv_inventory.movements) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."approve"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_confirmed boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_native_review"."approve"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_confirmed boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."approve"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_confirmed boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."approve"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_confirmed boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."commit_stage"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_reservation text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_native_review"."commit_stage"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_reservation text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."commit_stage"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_reservation text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."commit_stage"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_reservation text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."guard"(p_csrf text, p_kind text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_native_review"."guard"(p_csrf text, p_kind text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."guard"(p_csrf text, p_kind text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."immutable"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_native_review"."immutable"() FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."immutable"() TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."inspect"(p_id text, p_reservation text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_native_review"."inspect"(p_id text, p_reservation text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."inspect"(p_id text, p_reservation text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."inspect"(p_id text, p_reservation text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."read_source"(p_source text, p_entity text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_native_review"."read_source"(p_source text, p_entity text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."read_source"(p_source text, p_entity text, p_csrf text) TO "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."read_source"(p_source text, p_entity text, p_csrf text) TO "naruv_native_stage";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."receipt_json"(r naruv_native_review.receipts) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_native_review"."receipt_json"(r naruv_native_review.receipts) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."receipt_json"(r naruv_native_review.receipts) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."revoke"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_native_review"."revoke"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."revoke"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."revoke"(p_id text, p_digest text, p_canonical text, p_snapshot text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."store_stage"(p_id text, p_source text, p_entity text, p_format text, p_raw text, p_bytes integer, p_digest text, p_canonical text, p_rows_sha text, p_snapshot text, p_revision text, p_expected text[], p_rows_text text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_native_review"."store_stage"(p_id text, p_source text, p_entity text, p_format text, p_raw text, p_bytes integer, p_digest text, p_canonical text, p_rows_sha text, p_snapshot text, p_revision text, p_expected text[], p_rows_text text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."store_stage"(p_id text, p_source text, p_entity text, p_format text, p_raw text, p_bytes integer, p_digest text, p_canonical text, p_rows_sha text, p_snapshot text, p_revision text, p_expected text[], p_rows_text text, p_csrf text) TO "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."store_stage"(p_id text, p_source text, p_entity text, p_format text, p_raw text, p_bytes integer, p_digest text, p_canonical text, p_rows_sha text, p_snapshot text, p_revision text, p_expected text[], p_rows_text text, p_csrf text) TO "naruv_native_stage";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."target_digest"(p_org text, p_source text, p_entity text, p_rev text, p_ids text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_native_review"."target_digest"(p_org text, p_source text, p_entity text, p_rev text, p_ids text[]) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."target_digest"(p_org text, p_source text, p_entity text, p_rev text, p_ids text[]) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_native_review"."validated_ids"(p_entity text, p_rows jsonb, p_existing text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_native_review"."validated_ids"(p_entity text, p_rows jsonb, p_existing text[]) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_native_review"."validated_ids"(p_entity text, p_rows jsonb, p_existing text[]) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_production"."command"(p_key text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_production"."command"(p_key text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_production"."command"(p_key text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_production"."command"(p_key text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_production"."ident"(v text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_production"."ident"(v text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_production"."ident"(v text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_production"."inspect"(p_order text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_production"."inspect"(p_order text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_production"."inspect"(p_order text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_production"."inspect"(p_order text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_production"."plan"(p_org text, p_bom text, p_wh text, p_qty bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_production"."plan"(p_org text, p_bom text, p_wh text, p_qty bigint) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_production"."plan"(p_org text, p_bom text, p_wh text, p_qty bigint) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_production"."qty"(v jsonb, p_max bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_production"."qty"(v jsonb, p_max bigint) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_production"."qty"(v jsonb, p_max bigint) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_production"."requirements"(p_bom text, p_payload jsonb, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_production"."requirements"(p_bom text, p_payload jsonb, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_production"."requirements"(p_bom text, p_payload jsonb, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_production"."requirements"(p_bom text, p_payload jsonb, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_production"."snapshot"(o naruv_production.orders) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_production"."snapshot"(o naruv_production.orders) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_production"."snapshot"(o naruv_production.orders) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_quote_bundle"."allocate_vat"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_quote_bundle"."allocate_vat"() FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_quote_bundle"."allocate_vat"() TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_quote_bundle"."convert"(p_bundle text, p_request text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_quote_bundle"."convert"(p_bundle text, p_request text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_quote_bundle"."convert"(p_bundle text, p_request text, p_payload jsonb, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_quote_bundle"."convert"(p_bundle text, p_request text, p_payload jsonb, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_quote_bundle"."preview"(p_quote text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_quote_bundle"."preview"(p_quote text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_quote_bundle"."preview"(p_quote text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_quote_bundle"."preview"(p_quote text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_quote_bundle"."snapshot"(p_org text, p_quote text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_quote_bundle"."snapshot"(p_org text, p_quote text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_quote_bundle"."snapshot"(p_org text, p_quote text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_trade"."balance_guard"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_trade"."balance_guard"() FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_trade"."balance_guard"() TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_trade"."command"(p_doc text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_trade"."command"(p_doc text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_trade"."command"(p_doc text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_trade"."command"(p_doc text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_trade"."command_bundle_internal"(p_doc text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_trade"."command_bundle_internal"(p_doc text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_trade"."command_bundle_internal"(p_doc text, p_request text, p_action text, p_payload jsonb, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_trade"."inspect"(p_doc text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_trade"."inspect"(p_doc text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_trade"."inspect"(p_doc text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_trade"."inspect"(p_doc text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_trade"."reserved"(p_org text, p_source text, p_item text, p_wh text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_trade"."reserved"(p_org text, p_source text, p_item text, p_wh text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_trade"."reserved"(p_org text, p_source text, p_item text, p_wh text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_trade"."snapshot"(d naruv_trade.documents) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_trade"."snapshot"(d naruv_trade.documents) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_trade"."snapshot"(d naruv_trade.documents) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."apply"(p_org text, p_mid text, p_kind text, p_event text, p_incoming numeric) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_valuation"."apply"(p_org text, p_mid text, p_kind text, p_event text, p_incoming numeric) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."apply"(p_org text, p_mid text, p_kind text, p_event text, p_incoming numeric) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."audit_ledger"(p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_valuation"."audit_ledger"(p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."audit_ledger"(p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."audit_ledger"(p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."check_movement"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_valuation"."check_movement"() FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."check_movement"() TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."expected_posting"(p_kind text, p_amount numeric, OUT dr text, OUT cr text, OUT amount numeric) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_valuation"."expected_posting"(p_kind text, p_amount numeric, OUT dr text, OUT cr text, OUT amount numeric) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."expected_posting"(p_kind text, p_amount numeric, OUT dr text, OUT cr text, OUT amount numeric) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."inspect"(p_src text, p_item text, p_wh text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_valuation"."inspect"(p_src text, p_item text, p_wh text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."inspect"(p_src text, p_item text, p_wh text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."inspect"(p_src text, p_item text, p_wh text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."overview"(p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_valuation"."overview"(p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."overview"(p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."overview"(p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."post_cost_journal"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_valuation"."post_cost_journal"() FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."post_cost_journal"() TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."production_post"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_valuation"."production_post"() FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."production_post"() TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."receive"(p_item text, p_request text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_valuation"."receive"(p_item text, p_request text, p_payload jsonb, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."receive"(p_item text, p_request text, p_payload jsonb, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."receive"(p_item text, p_request text, p_payload jsonb, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."reconcile_bill"(p_bill text, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_valuation"."reconcile_bill"(p_bill text, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."reconcile_bill"(p_bill text, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."reconcile_bill"(p_bill text, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."return_adjusted"(p_bill text, p_request text, p_qty bigint, p_advanced boolean, p_ref text, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_valuation"."return_adjusted"(p_bill text, p_request text, p_qty bigint, p_advanced boolean, p_ref text, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."return_adjusted"(p_bill text, p_request text, p_qty bigint, p_advanced boolean, p_ref text, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."return_adjusted"(p_bill text, p_request text, p_qty bigint, p_advanced boolean, p_ref text, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."return_bill"(p_bill text, p_request text, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_valuation"."return_bill"(p_bill text, p_request text, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."return_bill"(p_bill text, p_request text, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."return_bill"(p_bill text, p_request text, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."return_quantity"(p_bill text, p_request text, p_qty bigint, p_confirm boolean, p_csrf text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_valuation"."return_quantity"(p_bill text, p_request text, p_qty bigint, p_confirm boolean, p_csrf text) FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."return_quantity"(p_bill text, p_request text, p_qty bigint, p_confirm boolean, p_csrf text) TO "jw_app_dev";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."return_quantity"(p_bill text, p_request text, p_qty bigint, p_confirm boolean, p_csrf text) TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."trade_post"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_valuation"."trade_post"() FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."trade_post"() TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON FUNCTION "naruv_valuation"."validate_cost_journal"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_valuation"."validate_cost_journal"() FROM "naruv_native_owner";
GRANT EXECUTE ON FUNCTION "naruv_valuation"."validate_cost_journal"() TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_accounting"."journals" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_accounting"."journals" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_accounting"."journals" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_accounting"."journals" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_accounting"."journals" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_accounting"."journals" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_accounting"."journals" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_accounting"."journals" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_accounting"."journals" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_accounting"."journals" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_accounting"."lines" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_accounting"."lines" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_accounting"."lines" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_accounting"."lines" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_accounting"."lines" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_accounting"."lines" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_accounting"."lines" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_accounting"."lines" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_accounting"."lines" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_accounting"."lines" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_accounting"."periods" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_accounting"."periods" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_accounting"."periods" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_accounting"."periods" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_accounting"."periods" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_accounting"."periods" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_accounting"."periods" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_accounting"."periods" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_accounting"."periods" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_accounting"."periods" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_bundle"."events" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_bundle"."events" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_bundle"."events" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_bundle"."events" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_bundle"."events" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_bundle"."events" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_bundle"."events" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_bundle"."events" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_bundle"."events" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_bundle"."events" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_bundle"."headers" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_bundle"."headers" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_bundle"."headers" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_bundle"."headers" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_bundle"."headers" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_bundle"."headers" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_bundle"."headers" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_bundle"."headers" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_bundle"."headers" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_bundle"."headers" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_bundle"."lines" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_bundle"."lines" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_bundle"."lines" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_bundle"."lines" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_bundle"."lines" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_bundle"."lines" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_bundle"."lines" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_bundle"."lines" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_bundle"."lines" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_bundle"."lines" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_customer_bridge"."crosswalk" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_customer_bridge"."crosswalk" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_customer_bridge"."crosswalk" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_customer_bridge"."crosswalk" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_customer_bridge"."crosswalk" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_customer_bridge"."crosswalk" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_customer_bridge"."crosswalk" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_customer_bridge"."crosswalk" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_customer_bridge"."crosswalk" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_customer_bridge"."crosswalk" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."attendance" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_draft"."attendance" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_draft"."attendance" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_draft"."attendance" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_draft"."attendance" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_draft"."attendance" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_draft"."attendance" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_draft"."attendance" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_draft"."attendance" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_draft"."attendance" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."attendance_receipts" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_draft"."attendance_receipts" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_draft"."attendance_receipts" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_draft"."attendance_receipts" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_draft"."attendance_receipts" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_draft"."attendance_receipts" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_draft"."attendance_receipts" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_draft"."attendance_receipts" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_draft"."attendance_receipts" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_draft"."attendance_receipts" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."document_admissions" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_draft"."document_admissions" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_draft"."document_admissions" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_draft"."document_admissions" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_draft"."document_admissions" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_draft"."document_admissions" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_draft"."document_admissions" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_draft"."document_admissions" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_draft"."document_admissions" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_draft"."document_admissions" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."document_revisions" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_draft"."document_revisions" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_draft"."document_revisions" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_draft"."document_revisions" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_draft"."document_revisions" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_draft"."document_revisions" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_draft"."document_revisions" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_draft"."document_revisions" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_draft"."document_revisions" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_draft"."document_revisions" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."documents" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_draft"."documents" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_draft"."documents" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_draft"."documents" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_draft"."documents" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_draft"."documents" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_draft"."documents" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_draft"."documents" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_draft"."documents" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_draft"."documents" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."pay_periods" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_draft"."pay_periods" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_draft"."pay_periods" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_draft"."pay_periods" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_draft"."pay_periods" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_draft"."pay_periods" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_draft"."pay_periods" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_draft"."pay_periods" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_draft"."pay_periods" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_draft"."pay_periods" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."period_amendments" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_draft"."period_amendments" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_draft"."period_amendments" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_draft"."period_amendments" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_draft"."period_amendments" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_draft"."period_amendments" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_draft"."period_amendments" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_draft"."period_amendments" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_draft"."period_amendments" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_draft"."period_amendments" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."period_confirmations" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_draft"."period_confirmations" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_draft"."period_confirmations" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_draft"."period_confirmations" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_draft"."period_confirmations" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_draft"."period_confirmations" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_draft"."period_confirmations" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_draft"."period_confirmations" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_draft"."period_confirmations" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_draft"."period_confirmations" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."profile_envelopes" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_draft"."profile_envelopes" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_draft"."profile_envelopes" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_draft"."profile_envelopes" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_draft"."profile_envelopes" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_draft"."profile_envelopes" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_draft"."profile_envelopes" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_draft"."profile_envelopes" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_draft"."profile_envelopes" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_draft"."profile_envelopes" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."profile_retention" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_draft"."profile_retention" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_draft"."profile_retention" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_draft"."profile_retention" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_draft"."profile_retention" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_draft"."profile_retention" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_draft"."profile_retention" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_draft"."profile_retention" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_draft"."profile_retention" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_draft"."profile_retention" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."profile_revision_history" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_draft"."profile_revision_history" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_draft"."profile_revision_history" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_draft"."profile_revision_history" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_draft"."profile_revision_history" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_draft"."profile_revision_history" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_draft"."profile_revision_history" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_draft"."profile_revision_history" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_draft"."profile_revision_history" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_draft"."profile_revision_history" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."setup_receipts" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_draft"."setup_receipts" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_draft"."setup_receipts" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_draft"."setup_receipts" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_draft"."setup_receipts" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_draft"."setup_receipts" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_draft"."setup_receipts" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_draft"."setup_receipts" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_draft"."setup_receipts" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_draft"."setup_receipts" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."staff" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_draft"."staff" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_draft"."staff" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_draft"."staff" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_draft"."staff" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_draft"."staff" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_draft"."staff" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_draft"."staff" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_draft"."staff" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_draft"."staff" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."staff_archivals" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_draft"."staff_archivals" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_draft"."staff_archivals" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_draft"."staff_archivals" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_draft"."staff_archivals" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_draft"."staff_archivals" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_draft"."staff_archivals" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_draft"."staff_archivals" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_draft"."staff_archivals" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_draft"."staff_archivals" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_draft"."statement_review_receipts" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_draft"."statement_review_receipts" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_draft"."statement_review_receipts" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_draft"."statement_review_receipts" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_draft"."statement_review_receipts" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_draft"."statement_review_receipts" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_draft"."statement_review_receipts" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_draft"."statement_review_receipts" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_draft"."statement_review_receipts" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_draft"."statement_review_receipts" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_finance"."bills" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_finance"."bills" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_finance"."bills" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_finance"."bills" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_finance"."bills" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_finance"."bills" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_finance"."bills" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_finance"."bills" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_finance"."bills" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_finance"."bills" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_finance"."events" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_finance"."events" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_finance"."events" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_finance"."events" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_finance"."events" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_finance"."events" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_finance"."events" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_finance"."events" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_finance"."events" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_finance"."events" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_inventory"."balances" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_inventory"."balances" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_inventory"."balances" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_inventory"."balances" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_inventory"."balances" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_inventory"."balances" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_inventory"."balances" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_inventory"."balances" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_inventory"."balances" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_inventory"."balances" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_inventory"."items" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_inventory"."items" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_inventory"."items" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_inventory"."items" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_inventory"."items" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_inventory"."items" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_inventory"."items" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_inventory"."items" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_inventory"."items" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_inventory"."items" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_inventory"."movements" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_inventory"."movements" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_inventory"."movements" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_inventory"."movements" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_inventory"."movements" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_inventory"."movements" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_inventory"."movements" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_inventory"."movements" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_inventory"."movements" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_inventory"."movements" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_inventory"."warehouses" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_inventory"."warehouses" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_inventory"."warehouses" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_inventory"."warehouses" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_inventory"."warehouses" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_inventory"."warehouses" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_inventory"."warehouses" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_inventory"."warehouses" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_inventory"."warehouses" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_inventory"."warehouses" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_native_review"."approvals" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_native_review"."approvals" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_native_review"."approvals" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_native_review"."approvals" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_native_review"."approvals" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_native_review"."approvals" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_native_review"."approvals" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_native_review"."approvals" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_native_review"."approvals" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_native_review"."approvals" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_native_review"."receipts" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_native_review"."receipts" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_native_review"."receipts" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_native_review"."receipts" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_native_review"."receipts" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_native_review"."receipts" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_native_review"."receipts" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_native_review"."receipts" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_native_review"."receipts" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_native_review"."receipts" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_native_review"."records" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_native_review"."records" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_native_review"."records" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_native_review"."records" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_native_review"."records" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_native_review"."records" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_native_review"."records" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_native_review"."records" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_native_review"."records" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_native_review"."records" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_native_review"."stages" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_native_review"."stages" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_native_review"."stages" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_native_review"."stages" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_native_review"."stages" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_native_review"."stages" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_native_review"."stages" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_native_review"."stages" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_native_review"."stages" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_native_review"."stages" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_production"."boms" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_production"."boms" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_production"."boms" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_production"."boms" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_production"."boms" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_production"."boms" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_production"."boms" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_production"."boms" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_production"."boms" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_production"."boms" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_production"."components" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_production"."components" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_production"."components" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_production"."components" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_production"."components" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_production"."components" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_production"."components" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_production"."components" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_production"."components" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_production"."components" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_production"."events" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_production"."events" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_production"."events" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_production"."events" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_production"."events" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_production"."events" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_production"."events" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_production"."events" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_production"."events" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_production"."events" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_production"."orders" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_production"."orders" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_production"."orders" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_production"."orders" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_production"."orders" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_production"."orders" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_production"."orders" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_production"."orders" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_production"."orders" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_production"."orders" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_quote_bundle"."conversions" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_quote_bundle"."conversions" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_quote_bundle"."conversions" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_quote_bundle"."conversions" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_quote_bundle"."conversions" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_quote_bundle"."conversions" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_quote_bundle"."conversions" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_quote_bundle"."conversions" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_quote_bundle"."conversions" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_quote_bundle"."conversions" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_trade"."documents" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_trade"."documents" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_trade"."documents" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_trade"."documents" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_trade"."documents" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_trade"."documents" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_trade"."documents" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_trade"."documents" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_trade"."documents" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_trade"."documents" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_trade"."events" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_trade"."events" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_trade"."events" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_trade"."events" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_trade"."events" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_trade"."events" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_trade"."events" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_trade"."events" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_trade"."events" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_trade"."events" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_valuation"."balances" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_valuation"."balances" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_valuation"."balances" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_valuation"."balances" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_valuation"."balances" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_valuation"."balances" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_valuation"."balances" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_valuation"."balances" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_valuation"."balances" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_valuation"."balances" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_valuation"."cost_journals" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_valuation"."cost_journals" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_valuation"."cost_journals" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_valuation"."cost_journals" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_valuation"."cost_journals" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_valuation"."cost_journals" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_valuation"."cost_journals" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_valuation"."cost_journals" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_valuation"."cost_journals" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_valuation"."cost_journals" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_native_owner";
REVOKE ALL ON TABLE "naruv_valuation"."entries" FROM PUBLIC;
REVOKE ALL ON TABLE "naruv_valuation"."entries" FROM "naruv_native_owner";
GRANT DELETE ON TABLE "naruv_valuation"."entries" TO "naruv_native_owner";
GRANT INSERT ON TABLE "naruv_valuation"."entries" TO "naruv_native_owner";
GRANT MAINTAIN ON TABLE "naruv_valuation"."entries" TO "naruv_native_owner";
GRANT REFERENCES ON TABLE "naruv_valuation"."entries" TO "naruv_native_owner";
GRANT SELECT ON TABLE "naruv_valuation"."entries" TO "naruv_native_owner";
GRANT TRIGGER ON TABLE "naruv_valuation"."entries" TO "naruv_native_owner";
GRANT TRUNCATE ON TABLE "naruv_valuation"."entries" TO "naruv_native_owner";
GRANT UPDATE ON TABLE "naruv_valuation"."entries" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "naruv_quote_fence";
REVOKE ALL ON FUNCTION "naruv_quote_fence"."freeze"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_quote_fence"."freeze"() FROM "naruv_quote_fence";
GRANT EXECUTE ON FUNCTION "naruv_quote_fence"."freeze"() TO "naruv_quote_fence";
RESET ROLE;
SET ROLE "naruv_sync_owner_ci";
REVOKE ALL ON FUNCTION "naruv_sync_ci"."change_actor"(p_actor text, p_active boolean, p_role text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_sync_ci"."change_actor"(p_actor text, p_active boolean, p_role text) FROM "naruv_sync_owner_ci";
GRANT EXECUTE ON FUNCTION "naruv_sync_ci"."change_actor"(p_actor text, p_active boolean, p_role text) TO "naruv_sync_broker_ci";
GRANT EXECUTE ON FUNCTION "naruv_sync_ci"."change_actor"(p_actor text, p_active boolean, p_role text) TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "naruv_sync_owner_ci";
REVOKE ALL ON FUNCTION "naruv_sync_ci"."issue"(p_id text, p_actor text, p_hash text, p_csrf text, p_ttl integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_sync_ci"."issue"(p_id text, p_actor text, p_hash text, p_csrf text, p_ttl integer) FROM "naruv_sync_owner_ci";
GRANT EXECUTE ON FUNCTION "naruv_sync_ci"."issue"(p_id text, p_actor text, p_hash text, p_csrf text, p_ttl integer) TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "naruv_sync_owner_ci";
REVOKE ALL ON FUNCTION "naruv_sync_ci"."revoke"(p_hash text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "naruv_sync_ci"."revoke"(p_hash text) FROM "naruv_sync_owner_ci";
GRANT EXECUTE ON FUNCTION "naruv_sync_ci"."revoke"(p_hash text) TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "naruv_v85_writer_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_auth_candidate"(p_email text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."v85_auth_candidate"(p_email text) FROM "naruv_v85_writer_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."v85_auth_candidate"(p_email text) TO "jw_auth_stage_v85";
GRANT EXECUTE ON FUNCTION "jw_dev"."v85_auth_candidate"(p_email text) TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "naruv_v85_writer_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_auth_failed"(p_email text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."v85_auth_failed"(p_email text) FROM "naruv_v85_writer_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."v85_auth_failed"(p_email text) TO "jw_auth_stage_v85";
GRANT EXECUTE ON FUNCTION "jw_dev"."v85_auth_failed"(p_email text) TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "naruv_v85_writer_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_auth_issue_session"(p_user_id text, p_token_hash text, p_csrf text, p_mfa_counter bigint, p_recovery_hash text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."v85_auth_issue_session"(p_user_id text, p_token_hash text, p_csrf text, p_mfa_counter bigint, p_recovery_hash text) FROM "naruv_v85_writer_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."v85_auth_issue_session"(p_user_id text, p_token_hash text, p_csrf text, p_mfa_counter bigint, p_recovery_hash text) TO "jw_auth_stage_v85";
GRANT EXECUTE ON FUNCTION "jw_dev"."v85_auth_issue_session"(p_user_id text, p_token_hash text, p_csrf text, p_mfa_counter bigint, p_recovery_hash text) TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "naruv_v85_writer_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_auth_revoke_session"(p_token_hash text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."v85_auth_revoke_session"(p_token_hash text) FROM "naruv_v85_writer_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."v85_auth_revoke_session"(p_token_hash text) TO "jw_auth_stage_v85";
GRANT EXECUTE ON FUNCTION "jw_dev"."v85_auth_revoke_session"(p_token_hash text) TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "naruv_v85_writer_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_candidate_native_ci"(p_email text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."v85_candidate_native_ci"(p_email text) FROM "naruv_v85_writer_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."v85_candidate_native_ci"(p_email text) TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "naruv_v85_writer_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_issue_native_ci"(p_user_id text, p_token_hash text, p_csrf text, p_mfa_counter bigint, p_recovery_hash text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."v85_issue_native_ci"(p_user_id text, p_token_hash text, p_csrf text, p_mfa_counter bigint, p_recovery_hash text) FROM "naruv_v85_writer_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."v85_issue_native_ci"(p_user_id text, p_token_hash text, p_csrf text, p_mfa_counter bigint, p_recovery_hash text) TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "naruv_v85_writer_ci";
REVOKE ALL ON FUNCTION "jw_dev"."v85_revoke_native_ci"(p_token_hash text) FROM PUBLIC;
REVOKE ALL ON FUNCTION "jw_dev"."v85_revoke_native_ci"(p_token_hash text) FROM "naruv_v85_writer_ci";
GRANT EXECUTE ON FUNCTION "jw_dev"."v85_revoke_native_ci"(p_token_hash text) TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON SEQUENCE "jw_dev"."messenger_seq_v90" FROM PUBLIC;
REVOKE ALL ON SEQUENCE "jw_dev"."messenger_seq_v90" FROM "postgres";
GRANT USAGE ON SEQUENCE "jw_dev"."messenger_seq_v90" TO "naruv_messenger_executor_ci";
GRANT SELECT ON SEQUENCE "jw_dev"."messenger_seq_v90" TO "postgres";
GRANT UPDATE ON SEQUENCE "jw_dev"."messenger_seq_v90" TO "postgres";
GRANT USAGE ON SEQUENCE "jw_dev"."messenger_seq_v90" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."audit_logs" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."audit_logs" FROM "postgres";
GRANT INSERT ON TABLE "jw_dev"."audit_logs" TO "jw_app_dev";
GRANT DELETE ON TABLE "jw_dev"."audit_logs" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."audit_logs" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."audit_logs" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."audit_logs" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."audit_logs" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."audit_logs" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."audit_logs" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."audit_logs" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."customers" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."customers" FROM "postgres";
GRANT SELECT ON TABLE "jw_dev"."customers" TO "jw_app_dev";
GRANT SELECT ON TABLE "jw_dev"."customers" TO "naruv_native_owner";
GRANT DELETE ON TABLE "jw_dev"."customers" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."customers" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."customers" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."customers" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."customers" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."customers" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."customers" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."customers" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."login_failures" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."login_failures" FROM "postgres";
GRANT DELETE ON TABLE "jw_dev"."login_failures" TO "naruv_v85_writer_ci";
GRANT INSERT ON TABLE "jw_dev"."login_failures" TO "naruv_v85_writer_ci";
GRANT SELECT ON TABLE "jw_dev"."login_failures" TO "naruv_v85_writer_ci";
GRANT DELETE ON TABLE "jw_dev"."login_failures" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."login_failures" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."login_failures" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."login_failures" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."login_failures" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."login_failures" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."login_failures" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."login_failures" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."messenger_attachments" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."messenger_attachments" FROM "postgres";
GRANT INSERT ON TABLE "jw_dev"."messenger_attachments" TO "naruv_messenger_executor_ci";
GRANT SELECT ON TABLE "jw_dev"."messenger_attachments" TO "naruv_messenger_executor_ci";
GRANT DELETE ON TABLE "jw_dev"."messenger_attachments" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."messenger_attachments" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."messenger_attachments" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."messenger_attachments" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."messenger_attachments" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."messenger_attachments" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."messenger_attachments" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."messenger_attachments" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."messenger_companies" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."messenger_companies" FROM "postgres";
GRANT DELETE ON TABLE "jw_dev"."messenger_companies" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."messenger_companies" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."messenger_companies" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."messenger_companies" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."messenger_companies" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."messenger_companies" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."messenger_companies" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."messenger_companies" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."messenger_connections" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."messenger_connections" FROM "postgres";
GRANT INSERT ON TABLE "jw_dev"."messenger_connections" TO "naruv_messenger_executor_ci";
GRANT SELECT ON TABLE "jw_dev"."messenger_connections" TO "naruv_messenger_executor_ci";
GRANT DELETE ON TABLE "jw_dev"."messenger_connections" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."messenger_connections" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."messenger_connections" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."messenger_connections" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."messenger_connections" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."messenger_connections" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."messenger_connections" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."messenger_connections" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."messenger_edits" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."messenger_edits" FROM "postgres";
GRANT INSERT ON TABLE "jw_dev"."messenger_edits" TO "naruv_messenger_executor_ci";
GRANT SELECT ON TABLE "jw_dev"."messenger_edits" TO "naruv_messenger_executor_ci";
GRANT DELETE ON TABLE "jw_dev"."messenger_edits" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."messenger_edits" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."messenger_edits" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."messenger_edits" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."messenger_edits" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."messenger_edits" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."messenger_edits" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."messenger_edits" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."messenger_messages" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."messenger_messages" FROM "postgres";
GRANT INSERT ON TABLE "jw_dev"."messenger_messages" TO "naruv_messenger_executor_ci";
GRANT SELECT ON TABLE "jw_dev"."messenger_messages" TO "naruv_messenger_executor_ci";
GRANT DELETE ON TABLE "jw_dev"."messenger_messages" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."messenger_messages" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."messenger_messages" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."messenger_messages" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."messenger_messages" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."messenger_messages" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."messenger_messages" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."messenger_messages" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."messenger_read_positions" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."messenger_read_positions" FROM "postgres";
GRANT INSERT ON TABLE "jw_dev"."messenger_read_positions" TO "naruv_messenger_executor_ci";
GRANT SELECT ON TABLE "jw_dev"."messenger_read_positions" TO "naruv_messenger_executor_ci";
GRANT DELETE ON TABLE "jw_dev"."messenger_read_positions" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."messenger_read_positions" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."messenger_read_positions" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."messenger_read_positions" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."messenger_read_positions" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."messenger_read_positions" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."messenger_read_positions" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."messenger_read_positions" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."mfa_credentials" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."mfa_credentials" FROM "postgres";
GRANT SELECT ON TABLE "jw_dev"."mfa_credentials" TO "naruv_v85_writer_ci";
GRANT DELETE ON TABLE "jw_dev"."mfa_credentials" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."mfa_credentials" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."mfa_credentials" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."mfa_credentials" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."mfa_credentials" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."mfa_credentials" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."mfa_credentials" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."mfa_credentials" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."mfa_recovery_codes" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."mfa_recovery_codes" FROM "postgres";
GRANT DELETE ON TABLE "jw_dev"."mfa_recovery_codes" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."mfa_recovery_codes" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."mfa_recovery_codes" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."mfa_recovery_codes" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."mfa_recovery_codes" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."mfa_recovery_codes" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."mfa_recovery_codes" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."mfa_recovery_codes" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."naruv_review_sources" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."naruv_review_sources" FROM "postgres";
GRANT SELECT ON TABLE "jw_dev"."naruv_review_sources" TO "jw_app_dev";
GRANT SELECT ON TABLE "jw_dev"."naruv_review_sources" TO "naruv_native_owner";
GRANT DELETE ON TABLE "jw_dev"."naruv_review_sources" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."naruv_review_sources" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."naruv_review_sources" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."naruv_review_sources" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."naruv_review_sources" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."naruv_review_sources" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."naruv_review_sources" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."naruv_review_sources" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."organizations" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."organizations" FROM "postgres";
GRANT DELETE ON TABLE "jw_dev"."organizations" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."organizations" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."organizations" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."organizations" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."organizations" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."organizations" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."organizations" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."organizations" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."quote_items" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."quote_items" FROM "postgres";
GRANT INSERT ON TABLE "jw_dev"."quote_items" TO "jw_app_dev";
GRANT SELECT ON TABLE "jw_dev"."quote_items" TO "jw_app_dev";
GRANT SELECT ON TABLE "jw_dev"."quote_items" TO "naruv_native_owner";
GRANT DELETE ON TABLE "jw_dev"."quote_items" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."quote_items" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."quote_items" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."quote_items" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."quote_items" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."quote_items" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."quote_items" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."quote_items" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."quotes" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."quotes" FROM "postgres";
GRANT INSERT ON TABLE "jw_dev"."quotes" TO "jw_app_dev";
GRANT SELECT ON TABLE "jw_dev"."quotes" TO "jw_app_dev";
GRANT SELECT ON TABLE "jw_dev"."quotes" TO "naruv_native_owner";
GRANT DELETE ON TABLE "jw_dev"."quotes" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."quotes" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."quotes" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."quotes" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."quotes" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."quotes" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."quotes" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."quotes" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."security_events" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."security_events" FROM "postgres";
GRANT INSERT ON TABLE "jw_dev"."security_events" TO "naruv_v85_writer_ci";
GRANT DELETE ON TABLE "jw_dev"."security_events" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."security_events" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."security_events" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."security_events" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."security_events" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."security_events" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."security_events" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."security_events" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."sessions" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."sessions" FROM "postgres";
GRANT DELETE ON TABLE "jw_dev"."sessions" TO "naruv_sync_owner_ci";
GRANT DELETE ON TABLE "jw_dev"."sessions" TO "naruv_v85_writer_ci";
GRANT INSERT ON TABLE "jw_dev"."sessions" TO "naruv_v85_writer_ci";
GRANT SELECT ON TABLE "jw_dev"."sessions" TO "naruv_v85_writer_ci";
GRANT DELETE ON TABLE "jw_dev"."sessions" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."sessions" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."sessions" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."sessions" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."sessions" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."sessions" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."sessions" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."sessions" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."staff_disabled" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."staff_disabled" FROM "postgres";
GRANT DELETE ON TABLE "jw_dev"."staff_disabled" TO "naruv_sync_owner_ci";
GRANT INSERT ON TABLE "jw_dev"."staff_disabled" TO "naruv_sync_owner_ci";
GRANT SELECT ON TABLE "jw_dev"."staff_disabled" TO "naruv_sync_owner_ci";
GRANT DELETE ON TABLE "jw_dev"."staff_disabled" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."staff_disabled" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."staff_disabled" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."staff_disabled" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."staff_disabled" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."staff_disabled" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."staff_disabled" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."staff_disabled" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
REVOKE ALL ON TABLE "jw_dev"."users" FROM PUBLIC;
REVOKE ALL ON TABLE "jw_dev"."users" FROM "postgres";
GRANT SELECT ON TABLE "jw_dev"."users" TO "naruv_v85_writer_ci";
GRANT DELETE ON TABLE "jw_dev"."users" TO "postgres";
GRANT INSERT ON TABLE "jw_dev"."users" TO "postgres";
GRANT MAINTAIN ON TABLE "jw_dev"."users" TO "postgres";
GRANT REFERENCES ON TABLE "jw_dev"."users" TO "postgres";
GRANT SELECT ON TABLE "jw_dev"."users" TO "postgres";
GRANT TRIGGER ON TABLE "jw_dev"."users" TO "postgres";
GRANT TRUNCATE ON TABLE "jw_dev"."users" TO "postgres";
GRANT UPDATE ON TABLE "jw_dev"."users" TO "postgres";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("action") ON TABLE "jw_dev"."audit_logs" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("actor_id") ON TABLE "jw_dev"."audit_logs" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("created_at") ON TABLE "jw_dev"."audit_logs" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("detail") ON TABLE "jw_dev"."audit_logs" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("entity_id") ON TABLE "jw_dev"."audit_logs" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("entity_type") ON TABLE "jw_dev"."audit_logs" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("id") ON TABLE "jw_dev"."audit_logs" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("org_id") ON TABLE "jw_dev"."audit_logs" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("business_number") ON TABLE "jw_dev"."customers" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("contact_name") ON TABLE "jw_dev"."customers" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("created_at") ON TABLE "jw_dev"."customers" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("email") ON TABLE "jw_dev"."customers" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("id") ON TABLE "jw_dev"."customers" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT REFERENCES ("id") ON TABLE "jw_dev"."customers" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("name") ON TABLE "jw_dev"."customers" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("org_id") ON TABLE "jw_dev"."customers" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT REFERENCES ("org_id") ON TABLE "jw_dev"."customers" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("phone") ON TABLE "jw_dev"."customers" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("attempts") ON TABLE "jw_dev"."login_failures" TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("first_failed_at") ON TABLE "jw_dev"."login_failures" TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("business_number") ON TABLE "jw_dev"."messenger_companies" TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("org_id") ON TABLE "jw_dev"."messenger_companies" TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("accepted_at") ON TABLE "jw_dev"."messenger_connections" TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("status") ON TABLE "jw_dev"."messenger_connections" TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("body") ON TABLE "jw_dev"."messenger_messages" TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("edited_at") ON TABLE "jw_dev"."messenger_messages" TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("version") ON TABLE "jw_dev"."messenger_messages" TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("last_read_seq") ON TABLE "jw_dev"."messenger_read_positions" TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("updated_at") ON TABLE "jw_dev"."messenger_read_positions" TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("last_counter") ON TABLE "jw_dev"."mfa_credentials" TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("code_hash") ON TABLE "jw_dev"."mfa_recovery_codes" TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("consumed_at") ON TABLE "jw_dev"."mfa_recovery_codes" TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("consumed_at") ON TABLE "jw_dev"."mfa_recovery_codes" TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("user_id") ON TABLE "jw_dev"."mfa_recovery_codes" TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("existing_ids") ON TABLE "jw_dev"."naruv_review_sources" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("revision") ON TABLE "jw_dev"."naruv_review_sources" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("id") ON TABLE "jw_dev"."organizations" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("id") ON TABLE "jw_dev"."organizations" TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("name") ON TABLE "jw_dev"."organizations" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("name") ON TABLE "jw_dev"."organizations" TO "naruv_messenger_executor_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT REFERENCES ("id") ON TABLE "jw_dev"."quote_items" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT REFERENCES ("id") ON TABLE "jw_dev"."quotes" TO "naruv_native_owner";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("created_at") ON TABLE "jw_dev"."sessions" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("csrf_token") ON TABLE "jw_dev"."sessions" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("csrf_token") ON TABLE "jw_dev"."sessions" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("expires_at") ON TABLE "jw_dev"."sessions" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("expires_at") ON TABLE "jw_dev"."sessions" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("id") ON TABLE "jw_dev"."sessions" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("id") ON TABLE "jw_dev"."sessions" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("id") ON TABLE "jw_dev"."sessions" TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("token_hash") ON TABLE "jw_dev"."sessions" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("token_hash") ON TABLE "jw_dev"."sessions" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("token_hash") ON TABLE "jw_dev"."sessions" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("user_id") ON TABLE "jw_dev"."sessions" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT INSERT ("user_id") ON TABLE "jw_dev"."sessions" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("user_id") ON TABLE "jw_dev"."sessions" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("user_id") ON TABLE "jw_dev"."staff_disabled" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("user_id") ON TABLE "jw_dev"."staff_disabled" TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("id") ON TABLE "jw_dev"."users" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("id") ON TABLE "jw_dev"."users" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("id") ON TABLE "jw_dev"."users" TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("org_id") ON TABLE "jw_dev"."users" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("org_id") ON TABLE "jw_dev"."users" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("role") ON TABLE "jw_dev"."users" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT SELECT ("role") ON TABLE "jw_dev"."users" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "postgres";
GRANT UPDATE ("role") ON TABLE "jw_dev"."users" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("actor_id") ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("actor_id") ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("csrf_token") ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("epoch") ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("expires_at") ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("expires_at") ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT UPDATE ("revoked") ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_hid_writer";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("revoked") ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("revoked") ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT UPDATE ("revoked") ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("token_hash") ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("token_hash") ON TABLE "naruv_hosted_identity_review"."sessions" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT UPDATE ("active") ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_hid_writer";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("active") ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("active") ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT UPDATE ("actor_role") ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_hid_writer";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("actor_role") ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("actor_role") ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT UPDATE ("epoch") ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_hid_writer";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("epoch") ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("id") ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("id") ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT UPDATE ("id") ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_v85_writer_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("org_id") ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_identity_reader_ci";
RESET ROLE;
SET ROLE "naruv_hid_owner";
GRANT SELECT ("org_id") ON TABLE "naruv_hosted_identity_review"."users" TO "naruv_sync_owner_ci";
RESET ROLE;
SET ROLE "naruv_native_owner";
GRANT SELECT ("quote_id") ON TABLE "naruv_quote_bundle"."conversions" TO "naruv_quote_fence";
RESET ROLE;

RESET ROLE;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL row_security=on;
SET LOCAL check_function_bodies=on;
DO $audit$ BEGIN
 IF (SELECT count(*) FROM pg_namespace WHERE nspname=ANY(ARRAY['jw_dev','naruv_accounting','naruv_auth_fence','naruv_bundle','naruv_customer_bridge','naruv_draft','naruv_finance','naruv_hosted_identity_review','naruv_inventory','naruv_native_review','naruv_production','naruv_quote_bundle','naruv_quote_fence','naruv_sync_ci','naruv_trade','naruv_valuation']))<>16 THEN RAISE EXCEPTION 'HOSTED_SCHEMA_COUNT'; END IF;
 IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=ANY(ARRAY['jw_dev','naruv_accounting','naruv_auth_fence','naruv_bundle','naruv_customer_bridge','naruv_draft','naruv_finance','naruv_hosted_identity_review','naruv_inventory','naruv_native_review','naruv_production','naruv_quote_bundle','naruv_quote_fence','naruv_sync_ci','naruv_trade','naruv_valuation']) AND c.relkind IN ('r','p'))<>65 OR
 (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=ANY(ARRAY['jw_dev','naruv_accounting','naruv_auth_fence','naruv_bundle','naruv_customer_bridge','naruv_draft','naruv_finance','naruv_hosted_identity_review','naruv_inventory','naruv_native_review','naruv_production','naruv_quote_bundle','naruv_quote_fence','naruv_sync_ci','naruv_trade','naruv_valuation']) AND c.relkind IN ('r','p') AND c.relrowsecurity AND c.relforcerowsecurity)<>65 THEN RAISE EXCEPTION 'HOSTED_TABLE_RLS'; END IF;
 IF (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=ANY(ARRAY['jw_dev','naruv_accounting','naruv_auth_fence','naruv_bundle','naruv_customer_bridge','naruv_draft','naruv_finance','naruv_hosted_identity_review','naruv_inventory','naruv_native_review','naruv_production','naruv_quote_bundle','naruv_quote_fence','naruv_sync_ci','naruv_trade','naruv_valuation']))<>113 THEN RAISE EXCEPTION 'HOSTED_FUNCTION_COUNT'; END IF;
 IF (SELECT count(*) FROM pg_policies WHERE schemaname=ANY(ARRAY['jw_dev','naruv_accounting','naruv_auth_fence','naruv_bundle','naruv_customer_bridge','naruv_draft','naruv_finance','naruv_hosted_identity_review','naruv_inventory','naruv_native_review','naruv_production','naruv_quote_bundle','naruv_quote_fence','naruv_sync_ci','naruv_trade','naruv_valuation']))<>110 THEN RAISE EXCEPTION 'HOSTED_POLICY_COUNT'; END IF;
 IF (SELECT count(*) FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE NOT g.tgisinternal AND n.nspname=ANY(ARRAY['jw_dev','naruv_accounting','naruv_auth_fence','naruv_bundle','naruv_customer_bridge','naruv_draft','naruv_finance','naruv_hosted_identity_review','naruv_inventory','naruv_native_review','naruv_production','naruv_quote_bundle','naruv_quote_fence','naruv_sync_ci','naruv_trade','naruv_valuation']))<>52 OR
 (SELECT count(*) FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE NOT g.tgisinternal AND g.tgconstraint<>0 AND n.nspname=ANY(ARRAY['jw_dev','naruv_accounting','naruv_auth_fence','naruv_bundle','naruv_customer_bridge','naruv_draft','naruv_finance','naruv_hosted_identity_review','naruv_inventory','naruv_native_review','naruv_production','naruv_quote_bundle','naruv_quote_fence','naruv_sync_ci','naruv_trade','naruv_valuation']))<>5 THEN RAISE EXCEPTION 'HOSTED_TRIGGER_COUNT'; END IF;
 IF (SELECT count(*) FROM pg_roles WHERE rolname=ANY(ARRAY['jw_app_dev','jw_auth_stage_v85','jw_ci_auth','jw_ci_trade','naruv_auth_fence_owner','naruv_ci_ingest','naruv_hid_auth','naruv_hid_business','naruv_hid_ingest','naruv_hid_owner','naruv_hid_reader','naruv_hid_writer','naruv_identity_reader_ci','naruv_messenger_executor_ci','naruv_native_owner','naruv_native_stage','naruv_quote_fence','naruv_sync_broker_ci','naruv_sync_owner_ci','naruv_v85_cutover_ci','naruv_v85_writer_ci']) AND NOT(rolcanlogin OR rolsuper OR rolinherit OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))<>21 THEN RAISE EXCEPTION 'HOSTED_ROLE_FLAGS'; END IF;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=ANY(ARRAY['jw_app_dev','jw_auth_stage_v85','jw_ci_auth','jw_ci_trade','naruv_auth_fence_owner','naruv_ci_ingest','naruv_hid_auth','naruv_hid_business','naruv_hid_ingest','naruv_hid_owner','naruv_hid_reader','naruv_hid_writer','naruv_identity_reader_ci','naruv_messenger_executor_ci','naruv_native_owner','naruv_native_stage','naruv_quote_fence','naruv_sync_broker_ci','naruv_sync_owner_ci','naruv_v85_cutover_ci','naruv_v85_writer_ci']) AND has_database_privilege(rolname,current_database(),'CREATE')) THEN RAISE EXCEPTION 'HOSTED_TEMP_CREATE'; END IF;
 IF (SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE r.rolname=ANY(ARRAY['jw_app_dev','jw_auth_stage_v85','jw_ci_auth','jw_ci_trade','naruv_auth_fence_owner','naruv_ci_ingest','naruv_hid_auth','naruv_hid_business','naruv_hid_ingest','naruv_hid_owner','naruv_hid_reader','naruv_hid_writer','naruv_identity_reader_ci','naruv_messenger_executor_ci','naruv_native_owner','naruv_native_stage','naruv_quote_fence','naruv_sync_broker_ci','naruv_sync_owner_ci','naruv_v85_cutover_ci','naruv_v85_writer_ci']) AND u.rolname<>'postgres')<>4 THEN RAISE EXCEPTION 'HOSTED_ROLE_EDGES'; END IF;
 IF EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE r.rolname=ANY(ARRAY['jw_app_dev','jw_auth_stage_v85','jw_ci_auth','jw_ci_trade','naruv_auth_fence_owner','naruv_ci_ingest','naruv_hid_auth','naruv_hid_business','naruv_hid_ingest','naruv_hid_owner','naruv_hid_reader','naruv_hid_writer','naruv_identity_reader_ci','naruv_messenger_executor_ci','naruv_native_owner','naruv_native_stage','naruv_quote_fence','naruv_sync_broker_ci','naruv_sync_owner_ci','naruv_v85_cutover_ci','naruv_v85_writer_ci']) AND u.rolname<>'postgres' AND (m.admin_option OR m.inherit_option OR NOT m.set_option OR NOT(u.rolname=ANY(ARRAY['jw_app_dev','jw_auth_stage_v85','jw_ci_auth','jw_ci_trade','naruv_auth_fence_owner','naruv_ci_ingest','naruv_hid_auth','naruv_hid_business','naruv_hid_ingest','naruv_hid_owner','naruv_hid_reader','naruv_hid_writer','naruv_identity_reader_ci','naruv_messenger_executor_ci','naruv_native_owner','naruv_native_stage','naruv_quote_fence','naruv_sync_broker_ci','naruv_sync_owner_ci','naruv_v85_cutover_ci','naruv_v85_writer_ci'])))) THEN RAISE EXCEPTION 'HOSTED_ROLE_EDGE_FLAGS'; END IF;
 IF EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN unnest(ARRAY['anon','authenticated','service_role','authenticator']) r WHERE n.nspname=ANY(ARRAY['jw_dev','naruv_accounting','naruv_auth_fence','naruv_bundle','naruv_customer_bridge','naruv_draft','naruv_finance','naruv_hosted_identity_review','naruv_inventory','naruv_native_review','naruv_production','naruv_quote_bundle','naruv_quote_fence','naruv_sync_ci','naruv_trade','naruv_valuation']) AND has_schema_privilege(r,n.oid,'USAGE')) THEN RAISE EXCEPTION 'HOSTED_API_SCHEMA'; END IF;
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN unnest(ARRAY['anon','authenticated','service_role','authenticator']) r WHERE n.nspname=ANY(ARRAY['jw_dev','naruv_accounting','naruv_auth_fence','naruv_bundle','naruv_customer_bridge','naruv_draft','naruv_finance','naruv_hosted_identity_review','naruv_inventory','naruv_native_review','naruv_production','naruv_quote_bundle','naruv_quote_fence','naruv_sync_ci','naruv_trade','naruv_valuation']) AND c.relkind IN ('r','p') AND (has_table_privilege(r,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))) THEN RAISE EXCEPTION 'HOSTED_API_TABLE'; END IF;
 IF EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN unnest(ARRAY['anon','authenticated','service_role','authenticator']) r WHERE n.nspname=ANY(ARRAY['jw_dev','naruv_accounting','naruv_auth_fence','naruv_bundle','naruv_customer_bridge','naruv_draft','naruv_finance','naruv_hosted_identity_review','naruv_inventory','naruv_native_review','naruv_production','naruv_quote_bundle','naruv_quote_fence','naruv_sync_ci','naruv_trade','naruv_valuation']) AND has_function_privilege(r,p.oid,'EXECUTE')) THEN RAISE EXCEPTION 'HOSTED_API_FUNCTION'; END IF;
 IF EXISTS(SELECT * FROM pg_temp.naruv_qa_platform_roles EXCEPT SELECT rolname,rolsuper,rolinherit,rolcanlogin,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication FROM pg_roles WHERE rolname=ANY(ARRAY['postgres','anon','authenticated','service_role','authenticator','supabase_admin'])) THEN RAISE EXCEPTION 'HOSTED_PLATFORM_ROLE_DRIFT'; END IF;
 IF EXISTS(SELECT * FROM pg_temp.naruv_qa_platform_graph EXCEPT SELECT r.rolname AS granted_role,u.rolname AS member_role,g.rolname AS grantor_role,m.admin_option,m.inherit_option,m.set_option FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member JOIN pg_roles g ON g.oid=m.grantor WHERE r.rolname=ANY(ARRAY['postgres','anon','authenticated','service_role','authenticator','supabase_admin']) AND u.rolname=ANY(ARRAY['postgres','anon','authenticated','service_role','authenticator','supabase_admin'])) OR EXISTS(SELECT r.rolname AS granted_role,u.rolname AS member_role,g.rolname AS grantor_role,m.admin_option,m.inherit_option,m.set_option FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member JOIN pg_roles g ON g.oid=m.grantor WHERE r.rolname=ANY(ARRAY['postgres','anon','authenticated','service_role','authenticator','supabase_admin']) AND u.rolname=ANY(ARRAY['postgres','anon','authenticated','service_role','authenticator','supabase_admin']) EXCEPT SELECT * FROM pg_temp.naruv_qa_platform_graph) THEN RAISE EXCEPTION 'HOSTED_PLATFORM_GRAPH_DRIFT'; END IF;
 IF EXISTS(SELECT * FROM pg_temp.naruv_qa_db_acl EXCEPT SELECT a.grantor,a.grantee,a.privilege_type,a.is_grantable FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname=current_database()) OR EXISTS(SELECT a.grantor,a.grantee,a.privilege_type,a.is_grantable FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname=current_database() EXCEPT SELECT * FROM pg_temp.naruv_qa_db_acl) THEN RAISE EXCEPTION 'HOSTED_DB_ACL_DRIFT'; END IF;
END $audit$;
COMMIT;
