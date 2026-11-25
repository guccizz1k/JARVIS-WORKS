-- V13.2 disposable pg17 CI fixtures ONLY. Never run on Supabase, Render or a persistent database.
-- This contains only supporting tables for original jw_dev_v83_payment_rpc.sql, not reimplementations of the ledger RPC.
CREATE TABLE jw_dev.orders (
 id text PRIMARY KEY, org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 customer_id text NOT NULL REFERENCES jw_dev.customers(id),
 quote_id text NOT NULL UNIQUE REFERENCES jw_dev.quotes(id),
 status text NOT NULL CHECK(status='fulfilled')
);
CREATE TABLE jw_dev.invoices (
 id text PRIMARY KEY, org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 order_id text NOT NULL UNIQUE REFERENCES jw_dev.orders(id),
 customer_id text NOT NULL REFERENCES jw_dev.customers(id),
 vat_mode text NOT NULL CHECK(vat_mode IN ('taxable','exempt')),
 status text NOT NULL CHECK(status='issued')
);
CREATE TABLE jw_dev.invoice_items (
 id text PRIMARY KEY, invoice_id text NOT NULL REFERENCES jw_dev.invoices(id),
 name text NOT NULL, quantity bigint NOT NULL CHECK(quantity BETWEEN 1 AND 100000),
 unit_price bigint NOT NULL CHECK(unit_price BETWEEN 0 AND 1000000000)
);
CREATE TABLE jw_dev.payments (
 id text PRIMARY KEY, org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 invoice_id text NOT NULL REFERENCES jw_dev.invoices(id),
 amount bigint NOT NULL CHECK(amount>0), paid_at text NOT NULL, note text NOT NULL,
 created_at text NOT NULL, reference text NOT NULL,
 reversed_at text, reversed_by text REFERENCES jw_dev.users(id),
 UNIQUE(org_id,invoice_id,reference)
);
CREATE TABLE jw_dev.invoice_adjustments_v69 (
 id text PRIMARY KEY, invoice_id text NOT NULL REFERENCES jw_dev.invoices(id),
 org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 kind text NOT NULL, item_id text, quantity bigint, amount bigint
);
CREATE TABLE jw_dev.invoice_adjustment_decisions_v69 (
 id text PRIMARY KEY, adjustment_id text NOT NULL REFERENCES jw_dev.invoice_adjustments_v69(id),
 org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 decision text NOT NULL
);
DO $secure$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['orders','invoices','invoice_items','payments',
 'invoice_adjustments_v69','invoice_adjustment_decisions_v69'] LOOP
   EXECUTE format('ALTER TABLE jw_dev.%I ENABLE ROW LEVEL SECURITY',t);
   EXECUTE format('ALTER TABLE jw_dev.%I FORCE ROW LEVEL SECURITY',t);
   EXECUTE format('REVOKE ALL ON jw_dev.%I FROM PUBLIC,anon,authenticated,service_role',t);
 END LOOP;
END $secure$;
GRANT SELECT ON jw_dev.orders,jw_dev.invoices,jw_dev.invoice_items,jw_dev.payments TO jw_app_dev;
CREATE POLICY ci_v132_orders_r ON jw_dev.orders FOR SELECT TO jw_app_dev
 USING(org_id=jw_dev.current_org_from_session());
CREATE POLICY ci_v132_invoices_r ON jw_dev.invoices FOR SELECT TO jw_app_dev
 USING(org_id=jw_dev.current_org_from_session());
CREATE POLICY ci_v132_invoice_items_r ON jw_dev.invoice_items FOR SELECT TO jw_app_dev
 USING(EXISTS(SELECT 1 FROM jw_dev.invoices i WHERE i.id=invoice_id
 AND i.org_id=jw_dev.current_org_from_session()));
CREATE POLICY ci_v132_payments_r ON jw_dev.payments FOR SELECT TO jw_app_dev
 USING(org_id=jw_dev.current_org_from_session()
 AND EXISTS(SELECT 1 FROM jw_dev.invoices i WHERE i.id=invoice_id AND i.org_id=org_id));
