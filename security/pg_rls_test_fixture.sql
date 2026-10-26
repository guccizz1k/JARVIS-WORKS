-- SYNTHETIC SCHEMA ONLY. Never apply on production or an existing user database.
DO $s$
BEGIN
  IF current_database() !~ '^jw_v(19|20)_test_' THEN
    RAISE EXCEPTION 'Refusing fixture outside jw_v19_test_* or jw_v20_test_* database';
  END IF;
  IF to_regclass('public.customers') IS NOT NULL THEN
    RAISE EXCEPTION 'Fixture requires an empty throwaway test database';
  END IF;
END $s$;
BEGIN;
CREATE TABLE public.organizations(id text PRIMARY KEY, name text);
CREATE TABLE public.users(id text PRIMARY KEY,org_id text NOT NULL,password_hash text);
CREATE TABLE public.customers(id text PRIMARY KEY,org_id text NOT NULL,name text);
CREATE TABLE public.quotes(id text PRIMARY KEY,org_id text NOT NULL,customer_id text);
CREATE TABLE public.quote_items(id text PRIMARY KEY,org_id text NOT NULL,quote_id text NOT NULL,name text);
CREATE TABLE public.orders(id text PRIMARY KEY,org_id text NOT NULL,quote_id text);
CREATE TABLE public.order_items(id text PRIMARY KEY,org_id text NOT NULL,order_id text NOT NULL,source_quote_item_id text);
CREATE TABLE public.invoices(id text PRIMARY KEY,org_id text NOT NULL,order_id text);
CREATE TABLE public.invoice_items(id text PRIMARY KEY,org_id text NOT NULL,invoice_id text NOT NULL,name text);
CREATE TABLE public.payments(id text PRIMARY KEY,org_id text NOT NULL,invoice_id text);
CREATE TABLE public.audit_logs(id text PRIMARY KEY,org_id text NOT NULL,actor_id text);
CREATE TABLE public.security_events(id text PRIMARY KEY,org_id text NOT NULL,actor_id text);
CREATE TABLE public.import_previews(id text PRIMARY KEY,org_id text NOT NULL,uploaded_by text);
CREATE TABLE public.sessions(token_hash text PRIMARY KEY);
CREATE TABLE public.mfa_credentials(user_id text PRIMARY KEY);
CREATE TABLE public.mfa_recovery_codes(user_id text);
CREATE TABLE public.login_failures(email text PRIMARY KEY);
-- Tenant-scoped composite references are REQUIRED; one-row IDs alone do not
-- prevent company A records pointing to company B records through foreign keys.
ALTER TABLE public.users ADD CONSTRAINT jw_u_users_tenant UNIQUE(id,org_id);
ALTER TABLE public.customers ADD CONSTRAINT jw_u_customers_tenant UNIQUE(id,org_id);
ALTER TABLE public.quotes ADD CONSTRAINT jw_u_quotes_tenant UNIQUE(id,org_id);
ALTER TABLE public.quote_items ADD CONSTRAINT jw_u_quote_items_tenant UNIQUE(id,org_id);
ALTER TABLE public.orders ADD CONSTRAINT jw_u_orders_tenant UNIQUE(id,org_id);
ALTER TABLE public.invoices ADD CONSTRAINT jw_u_invoices_tenant UNIQUE(id,org_id);
ALTER TABLE public.quotes ADD CONSTRAINT jw_fk_quotes_customer_tenant
  FOREIGN KEY(customer_id,org_id) REFERENCES public.customers(id,org_id);
ALTER TABLE public.quote_items ADD CONSTRAINT jw_fk_quote_items_quote_tenant
  FOREIGN KEY(quote_id,org_id) REFERENCES public.quotes(id,org_id);
ALTER TABLE public.orders ADD CONSTRAINT jw_fk_orders_quote_tenant
  FOREIGN KEY(quote_id,org_id) REFERENCES public.quotes(id,org_id);
ALTER TABLE public.order_items ADD CONSTRAINT jw_fk_order_items_order_tenant
  FOREIGN KEY(order_id,org_id) REFERENCES public.orders(id,org_id);
ALTER TABLE public.order_items ADD CONSTRAINT jw_fk_order_items_source_quote_tenant
  FOREIGN KEY(source_quote_item_id,org_id) REFERENCES public.quote_items(id,org_id);
ALTER TABLE public.invoices ADD CONSTRAINT jw_fk_invoices_order_tenant
  FOREIGN KEY(order_id,org_id) REFERENCES public.orders(id,org_id);
ALTER TABLE public.invoice_items ADD CONSTRAINT jw_fk_invoice_items_invoice_tenant
  FOREIGN KEY(invoice_id,org_id) REFERENCES public.invoices(id,org_id);
ALTER TABLE public.payments ADD CONSTRAINT jw_fk_payments_invoice_tenant
  FOREIGN KEY(invoice_id,org_id) REFERENCES public.invoices(id,org_id);

INSERT INTO public.organizations VALUES ('tenant_a','Test A'),('tenant_b','Test B');
INSERT INTO public.users VALUES ('ua','tenant_a','fake'),('ub','tenant_b','fake');
INSERT INTO public.customers VALUES ('ca','tenant_a','A Customer'),('cb','tenant_b','B Customer');
INSERT INTO public.quotes VALUES ('qa','tenant_a','ca'),('qb','tenant_b','cb');
INSERT INTO public.quote_items VALUES ('qia','tenant_a','qa','A Item'),('qib','tenant_b','qb','B Item');
INSERT INTO public.orders VALUES ('oa','tenant_a','qa'),('ob','tenant_b','qb');
INSERT INTO public.order_items VALUES ('oia','tenant_a','oa','qia'),('oib','tenant_b','ob','qib');
INSERT INTO public.invoices VALUES ('ia','tenant_a','oa'),('ib','tenant_b','ob');
INSERT INTO public.invoice_items VALUES ('iia','tenant_a','ia','A Invoice Item'),('iib','tenant_b','ib','B Invoice Item');
INSERT INTO public.payments VALUES ('pa','tenant_a','ia'),('pb','tenant_b','ib');
INSERT INTO public.audit_logs VALUES ('aa','tenant_a','ua'),('ab','tenant_b','ub');
INSERT INTO public.security_events VALUES ('sa','tenant_a','ua'),('sb','tenant_b','ub');
INSERT INTO public.import_previews VALUES ('pra','tenant_a','ua'),('prb','tenant_b','ub');
COMMIT;
