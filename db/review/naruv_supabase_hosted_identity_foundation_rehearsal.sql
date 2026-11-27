-- Managed QA identity contract rehearsal; always rolled back.
BEGIN;
SET LOCAL statement_timeout='15s';
SET LOCAL lock_timeout='2s';
SET LOCAL search_path=pg_catalog,pg_temp;
DO $g$ BEGIN
 IF current_user<>'postgres' OR session_user<>'postgres' OR current_database()<>'postgres' OR current_setting('server_version_num')::int/10000<>17 OR to_regclass('naruv_qa_probe.fixture') IS NULL OR to_regnamespace('jw_dev') IS NOT NULL OR to_regnamespace('naruv_hosted_identity_review') IS NOT NULL OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname LIKE 'naruv_hid_%') THEN RAISE EXCEPTION 'IDENTITY_SCOPE'; END IF;
 IF (SELECT count(*) FROM naruv_qa_probe.fixture)<>2 THEN RAISE EXCEPTION 'IDENTITY_MARKER'; END IF;
END $g$;
CREATE ROLE naruv_hid_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_hid_reader NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_hid_writer NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_hid_business NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_hid_auth NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_hid_ingest NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT naruv_hid_owner,naruv_hid_reader,naruv_hid_writer,naruv_hid_business,naruv_hid_auth,naruv_hid_ingest TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE SCHEMA naruv_hosted_identity_review AUTHORIZATION naruv_hid_owner;
SET LOCAL ROLE naruv_hid_owner;
REVOKE ALL ON SCHEMA naruv_hosted_identity_review FROM PUBLIC,anon,authenticated,service_role;
CREATE TABLE naruv_hosted_identity_review.organizations(id text PRIMARY KEY,name text NOT NULL);
CREATE TABLE naruv_hosted_identity_review.users(id text PRIMARY KEY,org_id text NOT NULL REFERENCES naruv_hosted_identity_review.organizations,actor_role text NOT NULL CHECK(actor_role IN ('admin','member')),active boolean NOT NULL,epoch bigint NOT NULL DEFAULT 0 CHECK(epoch>=0));
CREATE TABLE naruv_hosted_identity_review.sessions(token_hash text PRIMARY KEY CHECK(token_hash~'^[0-9a-f]{64}$'),actor_id text NOT NULL REFERENCES naruv_hosted_identity_review.users,epoch bigint NOT NULL,csrf_token text NOT NULL CHECK(length(csrf_token) BETWEEN 32 AND 256),expires_at timestamptz NOT NULL,revoked boolean NOT NULL DEFAULT false);
INSERT INTO naruv_hosted_identity_review.organizations VALUES ('ci-a','Company A'),('ci-b','Company B');
INSERT INTO naruv_hosted_identity_review.users VALUES ('actor-a','ci-a','admin',true,0),('actor-b','ci-b','admin',true,0),('member-a','ci-a','member',true,0);
ALTER TABLE naruv_hosted_identity_review.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_hosted_identity_review.organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY read_internal ON naruv_hosted_identity_review.organizations FOR SELECT TO naruv_hid_reader,naruv_hid_writer USING(true);
ALTER TABLE naruv_hosted_identity_review.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_hosted_identity_review.users FORCE ROW LEVEL SECURITY;
CREATE POLICY read_internal ON naruv_hosted_identity_review.users FOR SELECT TO naruv_hid_reader,naruv_hid_writer USING(true);
ALTER TABLE naruv_hosted_identity_review.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_hosted_identity_review.sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY read_internal ON naruv_hosted_identity_review.sessions FOR SELECT TO naruv_hid_reader,naruv_hid_writer USING(true);
CREATE POLICY update_user ON naruv_hosted_identity_review.users FOR UPDATE TO naruv_hid_writer USING(true) WITH CHECK(true);
CREATE POLICY insert_session ON naruv_hosted_identity_review.sessions FOR INSERT TO naruv_hid_writer WITH CHECK(true);
CREATE POLICY update_session ON naruv_hosted_identity_review.sessions FOR UPDATE TO naruv_hid_writer USING(true) WITH CHECK(true);
REVOKE ALL ON ALL TABLES IN SCHEMA naruv_hosted_identity_review FROM PUBLIC,anon,authenticated,service_role;
GRANT USAGE ON SCHEMA naruv_hosted_identity_review TO naruv_hid_reader,naruv_hid_writer,naruv_hid_business,naruv_hid_auth,naruv_hid_ingest;
GRANT CREATE ON SCHEMA naruv_hosted_identity_review TO naruv_hid_reader,naruv_hid_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA naruv_hosted_identity_review TO naruv_hid_reader,naruv_hid_writer;
GRANT UPDATE(active,epoch,actor_role) ON naruv_hosted_identity_review.users TO naruv_hid_writer;
GRANT INSERT,UPDATE(revoked) ON naruv_hosted_identity_review.sessions TO naruv_hid_writer;
RESET ROLE;
SET LOCAL ROLE naruv_hid_reader;
CREATE FUNCTION naruv_hosted_identity_review.stage_identity_v84()
RETURNS TABLE(actor_id text,org_id text,actor_role text,csrf_token text,org_name text)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT u.id,u.org_id,u.actor_role,s.csrf_token,o.name FROM naruv_hosted_identity_review.sessions s JOIN naruv_hosted_identity_review.users u ON u.id=s.actor_id JOIN naruv_hosted_identity_review.organizations o ON o.id=u.org_id
 WHERE s.token_hash=nullif(current_setting('jw.session_hash',true),'') AND s.expires_at>clock_timestamp() AND NOT s.revoked AND u.active AND s.epoch=u.epoch
$fn$;
REVOKE ALL ON FUNCTION naruv_hosted_identity_review.stage_identity_v84() FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION naruv_hosted_identity_review.stage_identity_v84() TO naruv_hid_business,naruv_hid_ingest;
RESET ROLE;
SET LOCAL ROLE naruv_hid_writer;
CREATE FUNCTION naruv_hosted_identity_review.issue(p_actor text,p_hash text,p_csrf text,p_ttl integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE u naruv_hosted_identity_review.users%ROWTYPE;
BEGIN
 IF p_hash IS NULL OR p_hash !~ '^[0-9a-f]{64}$' OR p_csrf IS NULL OR length(p_csrf) NOT BETWEEN 32 AND 256 OR p_ttl IS NULL OR p_ttl NOT BETWEEN 1 AND 43200 THEN RAISE EXCEPTION 'IDENTITY_INPUT' USING ERRCODE='23514'; END IF;
 SELECT * INTO u FROM naruv_hosted_identity_review.users WHERE id=p_actor FOR UPDATE;
 IF NOT FOUND OR NOT u.active THEN RAISE EXCEPTION 'IDENTITY_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 INSERT INTO naruv_hosted_identity_review.sessions(token_hash,actor_id,epoch,csrf_token,expires_at) VALUES(p_hash,u.id,u.epoch,p_csrf,clock_timestamp()+make_interval(secs=>p_ttl));
 RETURN true;
END $fn$;
CREATE FUNCTION naruv_hosted_identity_review.revoke(p_hash text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE n int;
BEGIN
 UPDATE naruv_hosted_identity_review.sessions SET revoked=true WHERE token_hash=p_hash AND NOT revoked;
 GET DIAGNOSTICS n=ROW_COUNT; RETURN n=1;
END $fn$;
CREATE FUNCTION naruv_hosted_identity_review.change_actor(p_actor text,p_active boolean,p_role text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE n int;
BEGIN
 IF p_active IS NULL OR p_role IS NULL OR p_role NOT IN ('admin','member') THEN RAISE EXCEPTION 'IDENTITY_INPUT' USING ERRCODE='23514'; END IF;
 UPDATE naruv_hosted_identity_review.users SET active=p_active,actor_role=p_role,epoch=epoch+1 WHERE id=p_actor;
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n<>1 THEN RAISE EXCEPTION 'IDENTITY_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 UPDATE naruv_hosted_identity_review.sessions SET revoked=true WHERE actor_id=p_actor AND NOT revoked;
 RETURN true;
END $fn$;
REVOKE ALL ON FUNCTION naruv_hosted_identity_review.issue(text,text,text,integer),naruv_hosted_identity_review.revoke(text),naruv_hosted_identity_review.change_actor(text,boolean,text) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION naruv_hosted_identity_review.issue(text,text,text,integer),naruv_hosted_identity_review.revoke(text),naruv_hosted_identity_review.change_actor(text,boolean,text) TO naruv_hid_auth;
RESET ROLE;
SET LOCAL ROLE naruv_hid_owner;
REVOKE CREATE ON SCHEMA naruv_hosted_identity_review FROM naruv_hid_reader,naruv_hid_writer;
RESET ROLE;
SET LOCAL ROLE naruv_hid_auth;
DO $t$ BEGIN
 IF NOT naruv_hosted_identity_review.issue('actor-a',repeat('a',64),repeat('c',32),3600) OR NOT naruv_hosted_identity_review.issue('actor-b',repeat('b',64),repeat('d',32),3600) OR NOT naruv_hosted_identity_review.issue('member-a',repeat('e',64),repeat('f',32),3600) THEN RAISE EXCEPTION 'ISSUE'; END IF;
 BEGIN PERFORM naruv_hosted_identity_review.issue('actor-b',repeat('a',64),repeat('d',32),3600); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN unique_violation THEN NULL; END;
 BEGIN PERFORM naruv_hosted_identity_review.issue('actor-a',NULL,repeat('c',32),3600); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN PERFORM naruv_hosted_identity_review.issue('actor-a',repeat('1',64),repeat('c',32),43201); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN PERFORM naruv_hosted_identity_review.stage_identity_v84(); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $t$;
RESET ROLE;
SET LOCAL ROLE naruv_hid_business;
DO $t$ BEGIN
 PERFORM set_config('jw.session_hash',repeat('a',64),true);
 IF (SELECT count(*) FROM naruv_hosted_identity_review.stage_identity_v84() WHERE actor_id='actor-a' AND org_id='ci-a' AND actor_role='admin' AND csrf_token=repeat('c',32) AND org_name='Company A')<>1 THEN RAISE EXCEPTION 'IDENTITY_A'; END IF;
 PERFORM set_config('jw.session_hash',repeat('b',64),true);
 IF (SELECT count(*) FROM naruv_hosted_identity_review.stage_identity_v84() WHERE actor_id='actor-b' AND org_id='ci-b')<>1 THEN RAISE EXCEPTION 'IDENTITY_B'; END IF;
 PERFORM set_config('jw.session_hash',repeat('e',64),true);
 IF (SELECT count(*) FROM naruv_hosted_identity_review.stage_identity_v84() WHERE actor_role='member')<>1 THEN RAISE EXCEPTION 'MEMBER'; END IF;
 PERFORM set_config('jw.session_hash',repeat('0',64),true);
 IF EXISTS(SELECT 1 FROM naruv_hosted_identity_review.stage_identity_v84()) THEN RAISE EXCEPTION 'UNKNOWN_TOKEN'; END IF;
 PERFORM set_config('jw.session_hash','',true);
 IF EXISTS(SELECT 1 FROM naruv_hosted_identity_review.stage_identity_v84()) THEN RAISE EXCEPTION 'EMPTY_TOKEN'; END IF;
 BEGIN PERFORM token_hash FROM naruv_hosted_identity_review.sessions; RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM naruv_hosted_identity_review.issue('actor-a',repeat('2',64),repeat('c',32),3600); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM naruv_hosted_identity_review.change_actor('actor-b',false,'admin'); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 IF pg_has_role(current_user,'naruv_hid_writer','SET') OR pg_has_role(current_user,'naruv_hid_reader','SET') OR pg_has_role(current_user,'naruv_hid_owner','SET') OR pg_has_role(current_user,'naruv_hid_auth','SET') THEN RAISE EXCEPTION 'ROLE_ESCAPE'; END IF;
END $t$;
RESET ROLE;
SET LOCAL ROLE naruv_hid_ingest;
DO $t$ BEGIN
 PERFORM set_config('jw.session_hash',repeat('a',64),true);
 IF (SELECT count(*) FROM naruv_hosted_identity_review.stage_identity_v84() WHERE actor_id='actor-a' AND org_id='ci-a' AND actor_role='admin' AND csrf_token=repeat('c',32) AND org_name='Company A')<>1 THEN RAISE EXCEPTION 'IDENTITY_A'; END IF;
 PERFORM set_config('jw.session_hash',repeat('b',64),true);
 IF (SELECT count(*) FROM naruv_hosted_identity_review.stage_identity_v84() WHERE actor_id='actor-b' AND org_id='ci-b')<>1 THEN RAISE EXCEPTION 'IDENTITY_B'; END IF;
 PERFORM set_config('jw.session_hash',repeat('e',64),true);
 IF (SELECT count(*) FROM naruv_hosted_identity_review.stage_identity_v84() WHERE actor_role='member')<>1 THEN RAISE EXCEPTION 'MEMBER'; END IF;
 PERFORM set_config('jw.session_hash',repeat('0',64),true);
 IF EXISTS(SELECT 1 FROM naruv_hosted_identity_review.stage_identity_v84()) THEN RAISE EXCEPTION 'UNKNOWN_TOKEN'; END IF;
 PERFORM set_config('jw.session_hash','',true);
 IF EXISTS(SELECT 1 FROM naruv_hosted_identity_review.stage_identity_v84()) THEN RAISE EXCEPTION 'EMPTY_TOKEN'; END IF;
 BEGIN PERFORM token_hash FROM naruv_hosted_identity_review.sessions; RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM naruv_hosted_identity_review.issue('actor-a',repeat('2',64),repeat('c',32),3600); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM naruv_hosted_identity_review.change_actor('actor-b',false,'admin'); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 IF pg_has_role(current_user,'naruv_hid_writer','SET') OR pg_has_role(current_user,'naruv_hid_reader','SET') OR pg_has_role(current_user,'naruv_hid_owner','SET') OR pg_has_role(current_user,'naruv_hid_auth','SET') THEN RAISE EXCEPTION 'ROLE_ESCAPE'; END IF;
END $t$;
RESET ROLE;
SET LOCAL ROLE naruv_hid_auth;
DO $t$ BEGIN
 IF NOT naruv_hosted_identity_review.change_actor('actor-a',false,'admin') THEN RAISE EXCEPTION 'DISABLE'; END IF;
 BEGIN PERFORM naruv_hosted_identity_review.issue('actor-a',repeat('2',64),repeat('c',32),3600); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 IF NOT naruv_hosted_identity_review.change_actor('actor-a',true,'member') THEN RAISE EXCEPTION 'REACTIVATE'; END IF;
 BEGIN PERFORM naruv_hosted_identity_review.issue('actor-a',repeat('a',64),repeat('c',32),3600); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN unique_violation THEN NULL; END;
 IF NOT naruv_hosted_identity_review.issue('actor-a',repeat('3',64),repeat('c',32),3600) THEN RAISE EXCEPTION 'REISSUE'; END IF;
 IF NOT naruv_hosted_identity_review.revoke(repeat('e',64)) OR naruv_hosted_identity_review.revoke(repeat('e',64)) THEN RAISE EXCEPTION 'REVOKE'; END IF;
 IF NOT naruv_hosted_identity_review.issue('actor-b',repeat('4',64),repeat('d',32),1) THEN RAISE EXCEPTION 'EXPIRY_ISSUE'; END IF;
END $t$;
RESET ROLE;
SET LOCAL ROLE naruv_hid_business;
DO $t$ BEGIN
 PERFORM set_config('jw.session_hash',repeat('4',64),true);
 IF NOT EXISTS(SELECT 1 FROM naruv_hosted_identity_review.stage_identity_v84()) THEN RAISE EXCEPTION 'EARLY_EXPIRY'; END IF;
 PERFORM pg_sleep(1.2);
 IF EXISTS(SELECT 1 FROM naruv_hosted_identity_review.stage_identity_v84()) THEN RAISE EXCEPTION 'EXPIRY_FAILED'; END IF;
 PERFORM set_config('jw.session_hash',repeat('a',64),true);
 IF EXISTS(SELECT 1 FROM naruv_hosted_identity_review.stage_identity_v84()) THEN RAISE EXCEPTION 'REVIVED'; END IF;
 PERFORM set_config('jw.session_hash',repeat('3',64),true);
 IF (SELECT count(*) FROM naruv_hosted_identity_review.stage_identity_v84() WHERE actor_role='member' AND org_id='ci-a')<>1 THEN RAISE EXCEPTION 'ROLE_STALE'; END IF;
 PERFORM set_config('jw.session_hash',repeat('e',64),true);
 IF EXISTS(SELECT 1 FROM naruv_hosted_identity_review.stage_identity_v84()) THEN RAISE EXCEPTION 'REVOKE_FAILED'; END IF;
 PERFORM set_config('jw.session_hash',repeat('b',64),true);
 IF (SELECT count(*) FROM naruv_hosted_identity_review.stage_identity_v84() WHERE org_id='ci-b')<>1 THEN RAISE EXCEPTION 'OTHER_TENANT'; END IF;
END $t$;
RESET ROLE;
SET LOCAL ROLE naruv_hid_reader;
DO $t$ BEGIN
 IF (SELECT count(*) FROM naruv_hosted_identity_review.sessions)<>5 OR (SELECT count(*) FROM naruv_hosted_identity_review.sessions WHERE revoked)<>2 THEN RAISE EXCEPTION 'IDENTITY_STATE'; END IF;
END $t$;
RESET ROLE;
DO $a$ BEGIN
 IF (SELECT count(*) FROM pg_class WHERE relnamespace='naruv_hosted_identity_review'::regnamespace AND relkind='r' AND relrowsecurity AND relforcerowsecurity)<>3 THEN RAISE EXCEPTION 'IDENTITY_RLS'; END IF;
 IF (SELECT count(*) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.pronamespace='naruv_hosted_identity_review'::regnamespace AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog'] AND NOT(r.rolcanlogin OR r.rolsuper OR r.rolbypassrls) AND r.rolname IN ('naruv_hid_reader','naruv_hid_writer'))<>4 THEN RAISE EXCEPTION 'IDENTITY_DEFINERS'; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['anon','authenticated','service_role']) r CROSS JOIN pg_proc p WHERE p.pronamespace='naruv_hosted_identity_review'::regnamespace AND (has_schema_privilege(r,'naruv_hosted_identity_review','USAGE') OR has_function_privilege(r,p.oid,'EXECUTE'))) THEN RAISE EXCEPTION 'IDENTITY_API_GRANTS'; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['naruv_hid_business','naruv_hid_ingest','naruv_hid_auth']) r CROSS JOIN pg_class c WHERE c.relnamespace='naruv_hosted_identity_review'::regnamespace AND c.relkind='r' AND (has_table_privilege(r,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))) THEN RAISE EXCEPTION 'IDENTITY_DIRECT_GRANTS'; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['naruv_hid_reader','naruv_hid_writer','naruv_hid_business','naruv_hid_auth','naruv_hid_ingest']) r WHERE has_schema_privilege(r,'naruv_hosted_identity_review','CREATE')) THEN RAISE EXCEPTION 'IDENTITY_CREATE_GRANT'; END IF;
END $a$;
SELECT 'HOSTED_IDENTITY_FOUNDATION_REVIEW_PASS' AS result,3 AS force_rls_tables,4 AS restricted_definer_functions,3 AS runtime_roles,3 AS external_roles_denied,5 AS session_records,2 AS revoked_records,1 AS expired_records,false AS production_authorized;
ROLLBACK;
