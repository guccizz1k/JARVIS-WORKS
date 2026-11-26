-- Dedicated Supabase QA capability rehearsal only. Execute only after trusted
-- provider identity preflight. Every object and role is rolled back.
BEGIN;
SET LOCAL statement_timeout='8s';
SET LOCAL lock_timeout='2s';
DO $guard$ BEGIN
 IF current_user<>'postgres' OR current_database()<>'postgres' OR current_setting('server_version_num')::int/10000<>17
 OR to_regclass('naruv_qa_probe.fixture') IS NULL OR to_regnamespace('jw_dev') IS NOT NULL
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('naruv_qa_rehearsal_owner','naruv_qa_rehearsal_runtime'))
 THEN RAISE EXCEPTION 'QA_SCOPE'; END IF;
END $guard$;
CREATE ROLE naruv_qa_rehearsal_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_qa_rehearsal_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT naruv_qa_rehearsal_owner,naruv_qa_rehearsal_runtime TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE SCHEMA naruv_qa_rehearsal AUTHORIZATION naruv_qa_rehearsal_owner;
SET LOCAL ROLE naruv_qa_rehearsal_owner;
REVOKE ALL ON SCHEMA naruv_qa_rehearsal FROM PUBLIC,anon,authenticated,service_role;
CREATE TABLE naruv_qa_rehearsal.fixture (tenant text PRIMARY KEY, value_krw int NOT NULL);
INSERT INTO naruv_qa_rehearsal.fixture VALUES ('ci-a',100),('ci-b',200);
ALTER TABLE naruv_qa_rehearsal.fixture ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_qa_rehearsal.fixture FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_read_a ON naruv_qa_rehearsal.fixture FOR SELECT TO naruv_qa_rehearsal_owner USING (tenant='ci-a');
REVOKE ALL ON naruv_qa_rehearsal.fixture FROM PUBLIC,anon,authenticated,service_role,naruv_qa_rehearsal_runtime;
CREATE FUNCTION naruv_qa_rehearsal.read_a() RETURNS integer LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $fn$ SELECT value_krw FROM naruv_qa_rehearsal.fixture $fn$;
REVOKE ALL ON FUNCTION naruv_qa_rehearsal.read_a() FROM PUBLIC,anon,authenticated,service_role;
GRANT USAGE ON SCHEMA naruv_qa_rehearsal TO naruv_qa_rehearsal_runtime;
GRANT EXECUTE ON FUNCTION naruv_qa_rehearsal.read_a() TO naruv_qa_rehearsal_runtime;
RESET ROLE;
SET LOCAL ROLE naruv_qa_rehearsal_runtime;
DO $test$ BEGIN
 IF naruv_qa_rehearsal.read_a() IS DISTINCT FROM 100 OR pg_has_role(current_user,'naruv_qa_rehearsal_owner','SET') THEN RAISE EXCEPTION 'QA_ROLE_BOUNDARY'; END IF;
 BEGIN PERFORM value_krw FROM naruv_qa_rehearsal.fixture; RAISE EXCEPTION 'DIRECT_TABLE_ALLOWED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $test$;
SELECT 'MANAGED_ROLE_RPC_REHEARSAL_PASS' AS result, naruv_qa_rehearsal.read_a() AS value_krw,
 pg_has_role(current_user,'naruv_qa_rehearsal_owner','SET') AS can_assume_owner;
RESET ROLE;
ROLLBACK;
