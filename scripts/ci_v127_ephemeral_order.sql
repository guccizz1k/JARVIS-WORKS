-- V12.7: ephemeral PG17 CI ONLY, never persistent Supabase or Render.
-- Apply only after the frozen 13-table pg_dump/pg_restore has been independently verified.
CREATE TABLE jw_dev.order_drafts_v127 (
 id text PRIMARY KEY,org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 customer_id text NOT NULL REFERENCES jw_dev.customers(id),
 quote_id text NOT NULL REFERENCES jw_dev.quotes(id),
 customer_name_snapshot text NOT NULL, doc_no text NOT NULL, title text NOT NULL,
 status text NOT NULL CHECK(status='draft'),
 review_state text NOT NULL CHECK(review_state='preview_acknowledged'),
 vat_mode text NOT NULL CHECK(vat_mode IN ('taxable','exempt')),
 due_date text NOT NULL,created_at text NOT NULL,updated_at text NOT NULL,
 order_date text NOT NULL,source_import_id text NOT NULL UNIQUE,
 source_document_meta text NOT NULL, UNIQUE(org_id,quote_id), UNIQUE(org_id,doc_no)
);
CREATE TABLE jw_dev.order_draft_items_v127 (
 id text PRIMARY KEY,order_id text NOT NULL REFERENCES jw_dev.order_drafts_v127(id),
 source_quote_item_id text NOT NULL REFERENCES jw_dev.quote_items(id),
 name text NOT NULL,quantity bigint NOT NULL CHECK(quantity BETWEEN 1 AND 100000),
 unit_price bigint NOT NULL CHECK(unit_price BETWEEN 0 AND 1000000000),
 position bigint NOT NULL CHECK(position BETWEEN 0 AND 39),
 UNIQUE(order_id,position), UNIQUE(order_id,source_quote_item_id)
);
ALTER TABLE jw_dev.order_drafts_v127 ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.order_drafts_v127 FORCE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.order_draft_items_v127 ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.order_draft_items_v127 FORCE ROW LEVEL SECURITY;
GRANT SELECT,INSERT ON jw_dev.order_drafts_v127,jw_dev.order_draft_items_v127 TO jw_app_dev;
CREATE POLICY ci_order_select ON jw_dev.order_drafts_v127 FOR SELECT TO jw_app_dev
 USING(org_id=jw_dev.current_org_from_session());
CREATE POLICY ci_order_insert ON jw_dev.order_drafts_v127 FOR INSERT TO jw_app_dev
 WITH CHECK(org_id=jw_dev.current_org_from_session() AND EXISTS(
 SELECT 1 FROM jw_dev.quotes q WHERE q.id=quote_id AND q.org_id=org_id
 AND q.customer_id=customer_id));
CREATE POLICY ci_order_item_select ON jw_dev.order_draft_items_v127 FOR SELECT TO jw_app_dev
 USING(EXISTS(SELECT 1 FROM jw_dev.order_drafts_v127 o WHERE o.id=order_id
 AND o.org_id=jw_dev.current_org_from_session()));
CREATE POLICY ci_order_item_insert ON jw_dev.order_draft_items_v127 FOR INSERT TO jw_app_dev
 WITH CHECK(EXISTS(SELECT 1 FROM jw_dev.order_drafts_v127 o
 JOIN jw_dev.quote_items q ON q.id=source_quote_item_id
 AND q.quote_id=o.quote_id WHERE o.id=order_id
 AND o.org_id=jw_dev.current_org_from_session()));

-- V12.8 isolated receipt: authenticated reviewer, tenant and frozen quote digest.
CREATE TABLE jw_dev.quote_review_receipts_v128 (
 id text PRIMARY KEY, org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 actor_id text NOT NULL, quote_id text NOT NULL REFERENCES jw_dev.quotes(id),
 source_sha256 text NOT NULL CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
 created_epoch bigint NOT NULL,
 UNIQUE(org_id,actor_id,quote_id,source_sha256)
);
ALTER TABLE jw_dev.quote_review_receipts_v128 ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.quote_review_receipts_v128 FORCE ROW LEVEL SECURITY;
GRANT SELECT,INSERT ON jw_dev.quote_review_receipts_v128 TO jw_app_dev;
CREATE POLICY ci_review_select ON jw_dev.quote_review_receipts_v128
 FOR SELECT TO jw_app_dev
 USING(org_id=jw_dev.current_org_from_session() AND
       actor_id=(SELECT actor_id FROM jw_dev.stage_identity_v84()));
CREATE POLICY ci_review_insert ON jw_dev.quote_review_receipts_v128
 FOR INSERT TO jw_app_dev
 WITH CHECK(org_id=jw_dev.current_org_from_session() AND
            actor_id=(SELECT actor_id FROM jw_dev.stage_identity_v84()) AND
            EXISTS(SELECT 1 FROM jw_dev.quotes q WHERE q.id=quote_id AND q.org_id=org_id));
