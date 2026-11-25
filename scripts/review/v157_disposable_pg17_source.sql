-- V15.7 completely disposable local PostgreSQL 17 fixture.
-- A GitHub Actions service DB only; never Supabase or persistent staging.
CREATE SCHEMA jw_dev;
REVOKE ALL ON SCHEMA jw_dev FROM PUBLIC;
GRANT USAGE ON SCHEMA jw_dev TO jw_app_dev;
CREATE TABLE jw_dev.organizations(id text PRIMARY KEY,name text NOT NULL,created_at text NOT NULL);
CREATE TABLE jw_dev.users(id text PRIMARY KEY,org_id text NOT NULL REFERENCES jw_dev.organizations(id),email text NOT NULL,password_hash text NOT NULL,name text NOT NULL,role text NOT NULL CHECK (role IN ('admin','member')),created_at text NOT NULL);
CREATE TABLE jw_dev.sessions(token_hash text PRIMARY KEY,user_id text NOT NULL REFERENCES jw_dev.users(id),expires_at text NOT NULL,csrf_token text NOT NULL,created_at text NOT NULL);
CREATE TABLE jw_dev.customers(id text PRIMARY KEY,org_id text NOT NULL REFERENCES jw_dev.organizations(id),name text NOT NULL,created_at text NOT NULL);
CREATE TABLE jw_dev.quotes(id text PRIMARY KEY,org_id text NOT NULL REFERENCES jw_dev.organizations(id),customer_id text NOT NULL REFERENCES jw_dev.customers(id),doc_no text NOT NULL);
CREATE TABLE jw_dev.orders(
 id text PRIMARY KEY,org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 customer_id text NOT NULL REFERENCES jw_dev.customers(id),
 quote_id text NOT NULL REFERENCES jw_dev.quotes(id),
 customer_name_snapshot text NOT NULL,doc_no text NOT NULL,title text NOT NULL,
 status text NOT NULL,review_state text NOT NULL,vat_mode text NOT NULL);
CREATE TABLE jw_dev.order_items(
 id text PRIMARY KEY,order_id text NOT NULL REFERENCES jw_dev.orders(id),
 name text NOT NULL,quantity bigint NOT NULL,unit_price bigint NOT NULL,position bigint NOT NULL);
CREATE TABLE jw_dev.invoices(id text PRIMARY KEY,org_id text NOT NULL REFERENCES jw_dev.organizations(id),order_id text NOT NULL REFERENCES jw_dev.orders(id));
CREATE TABLE jw_dev.audit_logs(
 id text PRIMARY KEY,org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 actor_id text NOT NULL REFERENCES jw_dev.users(id),entity_type text NOT NULL,
 entity_id text NOT NULL,action text NOT NULL,detail text NOT NULL,created_at text NOT NULL);

CREATE FUNCTION jw_dev.current_org_from_session() RETURNS text
 LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT u.org_id FROM jw_dev.sessions s JOIN jw_dev.users u ON u.id=s.user_id
 WHERE s.token_hash=current_setting('jw.session_hash',true)
 AND s.expires_at::timestamptz > clock_timestamp() LIMIT 1
 $$;
CREATE FUNCTION jw_dev.current_actor_from_session_v82() RETURNS text
 LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT u.id FROM jw_dev.sessions s JOIN jw_dev.users u ON u.id=s.user_id
 WHERE s.token_hash=current_setting('jw.session_hash',true)
 AND s.expires_at::timestamptz > clock_timestamp() LIMIT 1
 $$;
CREATE FUNCTION jw_dev.stage_identity_v84()
 RETURNS TABLE(actor_id text,org_id text,actor_role text,csrf_token text,org_name text)
 LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT u.id,u.org_id,u.role,s.csrf_token,o.name
 FROM jw_dev.sessions s
 JOIN jw_dev.users u ON u.id=s.user_id
 JOIN jw_dev.organizations o ON o.id=u.org_id
 WHERE s.token_hash=current_setting('jw.session_hash',true)
 AND s.expires_at::timestamptz>clock_timestamp() LIMIT 1
 $$;
REVOKE ALL ON FUNCTION jw_dev.current_org_from_session(),jw_dev.current_actor_from_session_v82(),jw_dev.stage_identity_v84() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION jw_dev.current_org_from_session(),jw_dev.current_actor_from_session_v82(),jw_dev.stage_identity_v84() TO jw_app_dev;
GRANT SELECT ON jw_dev.orders,jw_dev.order_items,jw_dev.invoices TO jw_app_dev;
GRANT UPDATE ON jw_dev.orders TO jw_app_dev; -- Required only by existing SELECT FOR UPDATE; unchanged application authorization.
GRANT INSERT ON jw_dev.audit_logs TO jw_app_dev;
DO $$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['organizations','users','sessions','customers','quotes','orders','order_items','invoices','audit_logs']
 LOOP
  EXECUTE format('ALTER TABLE jw_dev.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE jw_dev.%I FORCE ROW LEVEL SECURITY',t);
 END LOOP;
END $$;
CREATE POLICY ci_v157_order_read ON jw_dev.orders FOR SELECT TO jw_app_dev
 USING(org_id=jw_dev.current_org_from_session());
CREATE POLICY ci_v157_order_update ON jw_dev.orders FOR UPDATE TO jw_app_dev
 USING(org_id=jw_dev.current_org_from_session()) WITH CHECK(org_id=jw_dev.current_org_from_session());
CREATE POLICY ci_v157_order_lines_read ON jw_dev.order_items FOR SELECT TO jw_app_dev
 USING(EXISTS(SELECT 1 FROM jw_dev.orders o WHERE o.id=order_id AND o.org_id=jw_dev.current_org_from_session()));
CREATE POLICY ci_v157_invoice_read ON jw_dev.invoices FOR SELECT TO jw_app_dev
 USING(org_id=jw_dev.current_org_from_session());
CREATE POLICY ci_v157_audit_insert ON jw_dev.audit_logs FOR INSERT TO jw_app_dev
 WITH CHECK(org_id=jw_dev.current_org_from_session()
 AND actor_id=jw_dev.current_actor_from_session_v82());

INSERT INTO jw_dev.organizations(id,name,created_at) VALUES
 (repeat('a',32),'Synthetic A',now()::text),
 (repeat('b',32),'Synthetic B',now()::text);
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES
 (repeat('1',32),repeat('a',32),'a@invalid.test','synthetic','Admin A','admin',now()::text),
 (repeat('2',32),repeat('b',32),'b@invalid.test','synthetic','Admin B','admin',now()::text),
 (repeat('9',32),repeat('a',32),'m@invalid.test','synthetic','Member A','member',now()::text);
INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES
 (repeat('0',32),repeat('a',32),'Customer A',now()::text),
 (repeat('8',32),repeat('b',32),'Customer B',now()::text);
INSERT INTO jw_dev.quotes(id,org_id,customer_id,doc_no) VALUES
 (repeat('e',32),repeat('a',32),repeat('0',32),'Q-A'),
 (repeat('f',32),repeat('b',32),repeat('8',32),'Q-B');
INSERT INTO jw_dev.orders(id,org_id,customer_id,quote_id,customer_name_snapshot,doc_no,title,status,review_state,vat_mode) VALUES
 (repeat('c',32),repeat('a',32),repeat('0',32),repeat('e',32),'Customer A','O-A','Synthetic Delivery A','fulfilled','acknowledged','taxable'),
 (repeat('d',32),repeat('b',32),repeat('8',32),repeat('f',32),'Customer B','O-B','Synthetic Delivery B','fulfilled','acknowledged','taxable');
INSERT INTO jw_dev.order_items(id,order_id,name,quantity,unit_price,position) VALUES
 (repeat('3',32),repeat('c',32),'Synthetic line A',2,3500,0),
 (repeat('4',32),repeat('d',32),'Synthetic line B',2,3500,0);
