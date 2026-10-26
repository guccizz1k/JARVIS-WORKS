-- Synthetic ephemeral PostgreSQL 17 schema only. Never apply to a shared DB.
CREATE SCHEMA jw_dev;
REVOKE ALL ON SCHEMA jw_dev FROM PUBLIC;
GRANT USAGE ON SCHEMA jw_dev TO jw_app_dev;
CREATE TABLE jw_dev.organizations (id text PRIMARY KEY,name text NOT NULL,created_at text NOT NULL);
CREATE TABLE jw_dev.users (id text PRIMARY KEY,org_id text NOT NULL REFERENCES jw_dev.organizations(id),email text NOT NULL,password_hash text NOT NULL,name text NOT NULL,role text NOT NULL,created_at text NOT NULL);
CREATE TABLE jw_dev.sessions (id text PRIMARY KEY,token_hash text NOT NULL UNIQUE,user_id text NOT NULL REFERENCES jw_dev.users(id),expires_at text NOT NULL,csrf_token text NOT NULL,created_at text NOT NULL);
CREATE TABLE jw_dev.messenger_companies (org_id text PRIMARY KEY REFERENCES jw_dev.organizations(id),business_number text NOT NULL,verified_at text,verification_kind text);
CREATE TABLE jw_dev.messenger_connections (id text PRIMARY KEY,org_a text NOT NULL REFERENCES jw_dev.organizations(id),org_b text NOT NULL REFERENCES jw_dev.organizations(id),requester_org text NOT NULL,status text NOT NULL,created_at text NOT NULL,accepted_at text,UNIQUE(org_a,org_b));
CREATE TABLE jw_dev.messenger_messages (id text PRIMARY KEY,connection_id text NOT NULL REFERENCES jw_dev.messenger_connections(id),sender_org text NOT NULL,sender_user text NOT NULL,kind text NOT NULL,body text NOT NULL,actor_name text NOT NULL,request_id text NOT NULL,version bigint NOT NULL,created_at text NOT NULL,edited_at text,message_seq bigint,UNIQUE(sender_org,request_id));
CREATE TABLE jw_dev.messenger_attachments (message_id text PRIMARY KEY REFERENCES jw_dev.messenger_messages(id),filename text NOT NULL,mime text NOT NULL,data bytea NOT NULL,size_bytes bigint NOT NULL,content_hash text NOT NULL);
CREATE TABLE jw_dev.messenger_edits (id text PRIMARY KEY,message_id text NOT NULL REFERENCES jw_dev.messenger_messages(id),previous_body text,new_body text,actor_user text,edited_at text NOT NULL,version bigint NOT NULL);
CREATE TABLE jw_dev.messenger_read_positions (connection_id text NOT NULL REFERENCES jw_dev.messenger_connections(id),org_id text NOT NULL,last_read_rowid bigint,updated_at text,last_read_seq bigint,PRIMARY KEY(connection_id,org_id));

-- Synthetic identity functions intentionally simplified. These are CI-only and
-- do not purport to replace actual V8.5 auth/strong session issuance.
CREATE OR REPLACE FUNCTION jw_dev.current_org_from_session() RETURNS text
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $body$
 SELECT u.org_id FROM jw_dev.sessions s JOIN jw_dev.users u ON u.id=s.user_id
 WHERE s.token_hash=current_setting('jw.session_hash',true)
   AND s.expires_at::timestamptz>clock_timestamp() LIMIT 1
$body$;
CREATE OR REPLACE FUNCTION jw_dev.current_actor_from_session_v82() RETURNS text
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $body$
 SELECT u.id FROM jw_dev.sessions s JOIN jw_dev.users u ON u.id=s.user_id
 WHERE s.token_hash=current_setting('jw.session_hash',true)
   AND s.expires_at::timestamptz>clock_timestamp() LIMIT 1
$body$;
REVOKE ALL ON ALL TABLES IN SCHEMA jw_dev FROM PUBLIC;
DO $rls$
DECLARE tbl text;
BEGIN
 FOREACH tbl IN ARRAY ARRAY['organizations','users','sessions','messenger_companies','messenger_connections','messenger_messages','messenger_attachments','messenger_edits','messenger_read_positions'] LOOP
  EXECUTE format('ALTER TABLE jw_dev.%I ENABLE ROW LEVEL SECURITY',tbl);
  EXECUTE format('ALTER TABLE jw_dev.%I FORCE ROW LEVEL SECURITY',tbl);
 END LOOP;
END $rls$;

INSERT INTO jw_dev.organizations(id,name,created_at) VALUES ('ci-a','Company A',now()::text),('ci-b','Company B',now()::text),('ci-c','Company C',now()::text);
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES ('ci-ua','ci-a','a@invalid.test','synthetic','A','admin',now()::text),('ci-ub','ci-b','b@invalid.test','synthetic','B','admin',now()::text),('ci-uc','ci-c','c@invalid.test','synthetic','C','admin',now()::text);
INSERT INTO jw_dev.messenger_companies(org_id,business_number,verified_at,verification_kind) VALUES ('ci-a','1010101010',now()::text,'ci'),('ci-b','2020202020',now()::text,'ci'),('ci-c','3030303030',now()::text,'ci');
