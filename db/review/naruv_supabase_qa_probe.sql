-- Review record of the approved dedicated Supabase QA-only migration.
-- Never apply to existing WORKS databases. Verify provider project identity first.
DO $guard$
BEGIN
 IF current_database() <> 'postgres' OR current_setting('server_version_num')::int/10000 <> 17
 OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspname LIKE 'naruv_%' OR nspname LIKE 'jw_%')
 OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname LIKE 'naruv_%') THEN
 RAISE EXCEPTION 'NARUV_QA_NOT_FRESH';
 END IF;
END $guard$;
CREATE ROLE naruv_qa_probe_a NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_qa_probe_b NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT naruv_qa_probe_a,naruv_qa_probe_b TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE SCHEMA naruv_qa_probe;
REVOKE ALL ON SCHEMA naruv_qa_probe FROM PUBLIC,anon,authenticated,service_role;
CREATE TABLE naruv_qa_probe.fixture (
 tenant text NOT NULL CHECK (tenant IN ('ci-a','ci-b')),
 item_id integer NOT NULL,
 value_krw integer NOT NULL CHECK(value_krw>=0),
 PRIMARY KEY(tenant,item_id));
REVOKE ALL ON TABLE naruv_qa_probe.fixture FROM PUBLIC,anon,authenticated,service_role;
INSERT INTO naruv_qa_probe.fixture VALUES ('ci-a',1,1000),('ci-b',1,2000);
ALTER TABLE naruv_qa_probe.fixture ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_qa_probe.fixture FORCE ROW LEVEL SECURITY;
CREATE POLICY fixture_a ON naruv_qa_probe.fixture FOR SELECT TO naruv_qa_probe_a USING (tenant='ci-a');
CREATE POLICY fixture_b ON naruv_qa_probe.fixture FOR SELECT TO naruv_qa_probe_b USING (tenant='ci-b');
GRANT USAGE ON SCHEMA naruv_qa_probe TO naruv_qa_probe_a,naruv_qa_probe_b;
GRANT SELECT ON naruv_qa_probe.fixture TO naruv_qa_probe_a,naruv_qa_probe_b;
