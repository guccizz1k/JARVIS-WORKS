-- Disposable PG17 CI stage ONLY. Apply after ci_v90_postgres_browser.bootstrap().
-- NEVER migrate onto Supabase or any persistent database.
CREATE TABLE jw_dev.customers(
 id text PRIMARY KEY,org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 name text NOT NULL,business_number text NOT NULL DEFAULT '',
 contact_name text NOT NULL DEFAULT '',email text NOT NULL DEFAULT '',
 phone text NOT NULL DEFAULT '',created_at text NOT NULL
);
CREATE TABLE jw_dev.quotes(
 id text PRIMARY KEY,org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 customer_id text NOT NULL REFERENCES jw_dev.customers(id),
 customer_name_snapshot text NOT NULL,doc_no text NOT NULL,title text NOT NULL,
 status text NOT NULL,vat_mode text NOT NULL,created_at text NOT NULL,
 updated_at text NOT NULL, source_import_id text UNIQUE,
 source_document_meta text NOT NULL DEFAULT '{}',
 UNIQUE(org_id,doc_no)
);
CREATE TABLE jw_dev.quote_items(
 id text PRIMARY KEY,quote_id text NOT NULL REFERENCES jw_dev.quotes(id),
 name text NOT NULL,quantity bigint NOT NULL,unit_price bigint NOT NULL,
 position bigint NOT NULL
);
CREATE TABLE jw_dev.audit_logs(
 id text PRIMARY KEY,org_id text NOT NULL,actor_id text NOT NULL,
 entity_type text NOT NULL,entity_id text NOT NULL,
 action text NOT NULL,detail text NOT NULL,created_at text NOT NULL
);
DO $body$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['customers','quotes','quote_items','audit_logs'] LOOP
  EXECUTE format('ALTER TABLE jw_dev.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE jw_dev.%I FORCE ROW LEVEL SECURITY',t);
 END LOOP;
END $body$;

REVOKE ALL ON ALL TABLES IN SCHEMA jw_dev FROM PUBLIC;
GRANT SELECT ON jw_dev.customers TO jw_app_dev;
GRANT SELECT,INSERT ON jw_dev.quotes TO jw_app_dev;
GRANT SELECT,INSERT ON jw_dev.quote_items TO jw_app_dev;
GRANT INSERT ON jw_dev.audit_logs TO jw_app_dev;

CREATE POLICY ci_customers_tenant ON jw_dev.customers FOR SELECT TO jw_app_dev
 USING(org_id=jw_dev.current_org_from_session());
CREATE POLICY ci_quote_select ON jw_dev.quotes FOR SELECT TO jw_app_dev
 USING(org_id=jw_dev.current_org_from_session());
CREATE POLICY ci_quote_insert ON jw_dev.quotes FOR INSERT TO jw_app_dev
 WITH CHECK(org_id=jw_dev.current_org_from_session());
CREATE POLICY ci_quote_item_select ON jw_dev.quote_items FOR SELECT TO jw_app_dev
 USING(EXISTS(SELECT 1 FROM jw_dev.quotes q WHERE q.id=quote_id
              AND q.org_id=jw_dev.current_org_from_session()));
CREATE POLICY ci_quote_item_insert ON jw_dev.quote_items FOR INSERT TO jw_app_dev
 WITH CHECK(EXISTS(SELECT 1 FROM jw_dev.quotes q WHERE q.id=quote_id
              AND q.org_id=jw_dev.current_org_from_session()));
CREATE POLICY ci_audit_insert ON jw_dev.audit_logs FOR INSERT TO jw_app_dev
 WITH CHECK(org_id=jw_dev.current_org_from_session()
    AND actor_id=jw_dev.current_actor_from_session_v82());

CREATE OR REPLACE FUNCTION jw_dev.stage_identity_v84()
RETURNS TABLE(actor_id text,org_id text,actor_role text,csrf_token text,org_name text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT u.id,u.org_id,u.role,s.csrf_token,o.name
 FROM jw_dev.sessions s
 JOIN jw_dev.users u ON u.id=s.user_id
 JOIN jw_dev.organizations o ON o.id=u.org_id
 WHERE s.token_hash=current_setting('jw.session_hash',true)
 AND s.expires_at::timestamptz>clock_timestamp()
 LIMIT 1
$$;
REVOKE ALL ON FUNCTION jw_dev.stage_identity_v84() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION jw_dev.stage_identity_v84() TO jw_app_dev;
INSERT INTO jw_dev.customers(id,org_id,name,created_at)
VALUES ('ci-customer-a','ci-a','CI Customer A',now()::text),
       ('ci-customer-b','ci-b','CI Customer B',now()::text);
