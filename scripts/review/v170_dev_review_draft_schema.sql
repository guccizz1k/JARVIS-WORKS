-- V17.0 DEV-only additive schema promotion for existing V12.7/12.8 human-review APIs.
-- Approved review branch only. No production, no main, no customer data mutation.
-- Preflight: exactly 40 original forced-RLS tables, 56 policies, empty companies,
-- all three target tables absent. Deliberately non-idempotent / fail-closed.
-- This script must NEVER be used with the ephemeral V127 fixture in a shared DB.
BEGIN;
SET LOCAL lock_timeout = '1000ms';
SET LOCAL statement_timeout = '20s';
DO $v170_gate$
DECLARE role_ok boolean; forced integer; policies integer;
BEGIN
 SELECT count(*) INTO forced FROM pg_class c
 JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='jw_dev' AND c.relkind='r'
 AND c.relrowsecurity AND c.relforcerowsecurity;
 SELECT count(*) INTO policies FROM pg_policies WHERE schemaname='jw_dev';
 SELECT rolcanlogin = false AND rolbypassrls = false AND rolsuper = false
   INTO role_ok FROM pg_roles WHERE rolname='jw_app_dev';
 IF current_database() <> 'postgres' OR current_user <> 'postgres'
    OR forced <> 40 OR policies <> 56 OR COALESCE(role_ok,false) = false
    OR to_regclass('jw_dev.order_drafts_v127') IS NOT NULL
    OR to_regclass('jw_dev.order_draft_items_v127') IS NOT NULL
    OR to_regclass('jw_dev.quote_review_receipts_v128') IS NOT NULL
    OR EXISTS(SELECT 1 FROM jw_dev.organizations)
    OR EXISTS(SELECT 1 FROM jw_dev.sessions)
    OR EXISTS(SELECT 1 FROM jw_dev.orders)
    OR EXISTS(SELECT 1 FROM jw_dev.payments)
 THEN RAISE EXCEPTION 'V170_NONEMPTY_OR_UNEXPECTED_DATABASE_BLOCKED'; END IF;
END $v170_gate$;
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
CREATE POLICY jw_v170_order_select ON jw_dev.order_drafts_v127 FOR SELECT TO jw_app_dev
 USING(org_id=jw_dev.current_org_from_session());
CREATE POLICY jw_v170_order_insert ON jw_dev.order_drafts_v127 FOR INSERT TO jw_app_dev
 WITH CHECK(org_id=jw_dev.current_org_from_session() AND EXISTS(
 SELECT 1 FROM jw_dev.quotes q WHERE q.id=order_drafts_v127.quote_id AND q.org_id=order_drafts_v127.org_id
 AND q.customer_id=order_drafts_v127.customer_id));
CREATE POLICY jw_v170_item_select ON jw_dev.order_draft_items_v127 FOR SELECT TO jw_app_dev
 USING(EXISTS(SELECT 1 FROM jw_dev.order_drafts_v127 o WHERE o.id=order_id
 AND o.org_id=jw_dev.current_org_from_session()));
CREATE POLICY jw_v170_item_insert ON jw_dev.order_draft_items_v127 FOR INSERT TO jw_app_dev
 WITH CHECK(EXISTS(SELECT 1 FROM jw_dev.order_drafts_v127 o
 JOIN jw_dev.quote_items q ON q.id=source_quote_item_id
 AND q.quote_id=o.quote_id WHERE o.id=order_id
 AND o.org_id=jw_dev.current_org_from_session()));

-- V12.8 isolated receipt: authenticated reviewer, tenant and frozen quote digest.
CREATE TABLE jw_dev.quote_review_receipts_v128 (
 id text PRIMARY KEY, org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 actor_id text NOT NULL, quote_id text NOT NULL REFERENCES jw_dev.quotes(id),
 source_sha256 text NOT NULL CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
 created_epoch bigint NOT NULL
);
ALTER TABLE jw_dev.quote_review_receipts_v128 ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.quote_review_receipts_v128 FORCE ROW LEVEL SECURITY;
GRANT SELECT,INSERT ON jw_dev.quote_review_receipts_v128 TO jw_app_dev;
CREATE POLICY jw_v170_receipt_select ON jw_dev.quote_review_receipts_v128
 FOR SELECT TO jw_app_dev
 USING(org_id=jw_dev.current_org_from_session() AND
       actor_id=(SELECT actor_id FROM jw_dev.stage_identity_v84()));
CREATE POLICY jw_v170_receipt_insert ON jw_dev.quote_review_receipts_v128
 FOR INSERT TO jw_app_dev
 WITH CHECK(org_id=jw_dev.current_org_from_session() AND
            actor_id=(SELECT actor_id FROM jw_dev.stage_identity_v84()) AND
            EXISTS(SELECT 1 FROM jw_dev.quotes q WHERE q.id=quote_review_receipts_v128.quote_id AND q.org_id=quote_review_receipts_v128.org_id));

-- Every new table has forced RLS and only scoped SELECT/INSERT grants.
-- The existing quote review API returns draft_only / approval_posted=false.
DO $v170_verify$
DECLARE forced integer; policies integer; inserted integer;
BEGIN
 SELECT count(*) INTO forced FROM pg_class c
 JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='jw_dev' AND c.relkind='r'
 AND c.relrowsecurity AND c.relforcerowsecurity;
 SELECT count(*) INTO policies FROM pg_policies WHERE schemaname='jw_dev';
 SELECT count(*) INTO inserted FROM (
   SELECT 1 FROM jw_dev.order_drafts_v127
   UNION ALL SELECT 1 FROM jw_dev.order_draft_items_v127
   UNION ALL SELECT 1 FROM jw_dev.quote_review_receipts_v128
 ) q;
 IF forced <> 43 OR policies <> 62 OR inserted <> 0
 THEN RAISE EXCEPTION 'V170_POSTCONDITION_FAILED'; END IF;
 IF EXISTS (
   SELECT 1 FROM information_schema.role_table_grants
   WHERE table_schema='jw_dev'
     AND table_name IN ('order_drafts_v127','order_draft_items_v127','quote_review_receipts_v128')
     AND grantee='jw_app_dev'
     AND privilege_type NOT IN ('SELECT','INSERT')
 )
 THEN RAISE EXCEPTION 'V170_PRIVILEGE_ESCALATION_BLOCKED'; END IF;
END $v170_verify$;
COMMIT;
SELECT 'PASS_V170_REVIEW_ONLY_SCHEMA_43_FORCED_RLS_62_POLICIES' AS verdict;
