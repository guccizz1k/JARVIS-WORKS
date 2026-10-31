-- Approved DEV-only V163 migration. Never PROD or main. Exact GitHub sources:
-- scripts/review/v151_private_review_ledger_candidate.sql
-- scripts/review/v153_restricted_review_writer_candidate.sql
-- scripts/review/v159_dedicated_delivery_writer_candidate.sql
-- Previously tested with BEGIN / ROLLBACK on jarvis-works-dev.
DO $guard$ BEGIN
IF current_database() IS NULL OR
   (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='jw_dev' AND c.relkind='r')<>35 OR
   (SELECT count(*) FROM pg_policies WHERE schemaname='jw_dev')<>40 OR
   (SELECT count(*) FROM pg_roles WHERE rolname='jw_delivery_writer_v159')<>0 OR
   to_regclass('jw_dev.review_delivery_receipts_v151') IS NOT NULL OR
   (SELECT count(*) FROM jw_dev.orders)<>0
THEN RAISE EXCEPTION 'V163_PRECONDITION_DENIED'; END IF;
END $guard$;
-- V15.1: CANDIDATE PRIVATE SCHEMA ONLY, REVIEW-ONLY.
-- This is NOT an applied migration. Execute only in an isolated transaction
-- with BEGIN; <this DDL>; inspected assertions; ROLLBACK; on approved empty DEV.
-- Do not grant application INSERT/UPDATE/DELETE until issuer verification,
-- session-bound actor authorization, audit, and a separate deployment approval.
-- NOT compatible with public signup until external official proof integrations exist.

CREATE TABLE jw_dev.review_signup_requests_v151 (
  request_id text PRIMARY KEY CHECK(request_id ~ '^[0-9a-f]{32}$'),
  company_name text NOT NULL CHECK(length(company_name) BETWEEN 2 AND 120 AND company_name=btrim(company_name)),
  email text NOT NULL UNIQUE CHECK(email=lower(btrim(email))
    AND length(email) <= 254
    AND email ~ '^[a-z0-9][a-z0-9._+-]*@[a-z0-9.-]+[.][a-z]{2,}$'),
  business_number text NOT NULL UNIQUE CHECK(business_number ~ '^[0-9]{10}$'),
  intent_sha256 text NOT NULL UNIQUE CHECK(intent_sha256 ~ '^[0-9a-f]{64}$'),
  status text NOT NULL DEFAULT 'PENDING_HUMAN_REVIEW'
     CHECK(status='PENDING_HUMAN_REVIEW'),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE jw_dev.review_signup_nonces_v151 (
  nonce text PRIMARY KEY CHECK(nonce ~ '^[0-9a-f]{32}$'),
  request_id text NOT NULL REFERENCES jw_dev.review_signup_requests_v151(request_id) ON DELETE RESTRICT,
  purpose text NOT NULL CHECK(purpose IN ('email_control','business_control')),
  issuer text NOT NULL CHECK(length(issuer) BETWEEN 5 AND 120),
  envelope_sha256 text NOT NULL CHECK(envelope_sha256 ~ '^[0-9a-f]{64}$'),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  CHECK(expires_at > issued_at AND expires_at <= issued_at + interval '15 minutes'),
  UNIQUE(request_id,purpose)
);
CREATE TABLE jw_dev.review_delivery_receipts_v151 (
  order_id text PRIMARY KEY REFERENCES jw_dev.orders(id) ON DELETE RESTRICT,
  org_id text NOT NULL,
  source_sha256 text NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
  evidence_sha256 text NOT NULL UNIQUE CHECK(evidence_sha256 ~ '^[0-9a-f]{64}$'),
  dispatch_document_sha256 text NOT NULL CHECK(dispatch_document_sha256 ~ '^[0-9a-f]{64}$'),
  recipient_document_sha256 text NOT NULL CHECK(recipient_document_sha256 ~ '^[0-9a-f]{64}$'),
  dispatch_actor text NOT NULL CHECK(dispatch_actor ~ '^[0-9a-f]{32}$'),
  recipient_actor text NOT NULL CHECK(recipient_actor ~ '^[0-9a-f]{32}$'),
  subtotal_krw bigint NOT NULL CHECK(subtotal_krw > 0),
  vat_krw bigint NOT NULL CHECK(vat_krw >= 0),
  total_krw bigint NOT NULL CHECK(total_krw > 0
    AND total_krw = subtotal_krw + vat_krw),
  status text NOT NULL DEFAULT 'PENDING_HUMAN_REVIEW'
     CHECK(status='PENDING_HUMAN_REVIEW'),
  physical_delivery_verified boolean NOT NULL DEFAULT false
     CHECK(physical_delivery_verified=false),
  invoice_posted boolean NOT NULL DEFAULT false
     CHECK(invoice_posted=false),
  payment_posted boolean NOT NULL DEFAULT false
     CHECK(payment_posted=false),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK(dispatch_actor <> recipient_actor)
);
CREATE TABLE jw_dev.review_delivery_nonces_v151 (
  nonce text PRIMARY KEY CHECK(nonce ~ '^[0-9a-f]{32}$'),
  order_id text NOT NULL REFERENCES jw_dev.review_delivery_receipts_v151(order_id) ON DELETE RESTRICT,
  purpose text NOT NULL CHECK(purpose IN ('dispatch','receipt')),
  issuer text NOT NULL CHECK(length(issuer) BETWEEN 5 AND 120),
  proof_sha256 text NOT NULL CHECK(proof_sha256 ~ '^[0-9a-f]{64}$'),
  UNIQUE(order_id,purpose)
);
CREATE TABLE jw_dev.review_delivery_items_v151 (
  order_id text NOT NULL REFERENCES jw_dev.review_delivery_receipts_v151(order_id) ON DELETE RESTRICT,
  source_item_id text NOT NULL REFERENCES jw_dev.order_items(id) ON DELETE RESTRICT,
  position integer NOT NULL CHECK(position BETWEEN 0 AND 39),
  quantity bigint NOT NULL CHECK(quantity BETWEEN 1 AND 100000),
  unit_price_krw bigint NOT NULL CHECK(unit_price_krw BETWEEN 0 AND 1000000000),
  PRIMARY KEY(order_id,source_item_id),
  UNIQUE(order_id,position)
);

-- Defense in depth, not a claim of completed authorization.
ALTER TABLE jw_dev.review_signup_requests_v151 ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.review_signup_requests_v151 FORCE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.review_signup_nonces_v151 ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.review_signup_nonces_v151 FORCE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.review_delivery_receipts_v151 ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.review_delivery_receipts_v151 FORCE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.review_delivery_nonces_v151 ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.review_delivery_nonces_v151 FORCE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.review_delivery_items_v151 ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.review_delivery_items_v151 FORCE ROW LEVEL SECURITY;

-- Deliberate default deny: NO policies, public access, or application grants.
-- Even if a review-eligible proof exists, none of these tables activate a user,
-- prove physical shipment, issue an invoice, or post a payment.
REVOKE ALL ON TABLE
 jw_dev.review_signup_requests_v151,
 jw_dev.review_signup_nonces_v151,
 jw_dev.review_delivery_receipts_v151,
 jw_dev.review_delivery_nonces_v151,
 jw_dev.review_delivery_items_v151
 FROM PUBLIC, anon, authenticated, jw_app_dev, jw_auth_stage_v85,
      jw_stage1_trade_20261030, jw_stage1_auth_20261030;

-- Restrict future INSERTs to the existing tenant's acknowledged fulfilled
-- order and exact source item snapshots. SECURITY INVOKER preserves source RLS.
-- New functions are NON-PUBLIC and never activate posting/approvals.
CREATE FUNCTION jw_dev.v151_order_source_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, jw_dev
AS $v151order$
BEGIN
 IF NOT EXISTS (
  SELECT 1 FROM jw_dev.orders o
   WHERE o.id=NEW.order_id AND o.org_id=NEW.org_id
     AND o.status='fulfilled' AND o.review_state='acknowledged'
 ) THEN
  RAISE EXCEPTION USING ERRCODE='23514',
    MESSAGE='V151_SOURCE_ORDER_REJECTED';
 END IF;
 RETURN NEW;
END $v151order$;

CREATE TRIGGER v151_order_source_insert
 BEFORE INSERT ON jw_dev.review_delivery_receipts_v151
 FOR EACH ROW EXECUTE FUNCTION jw_dev.v151_order_source_guard();

CREATE FUNCTION jw_dev.v151_line_source_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, jw_dev
AS $v151line$
BEGIN
 IF NOT EXISTS (
  SELECT 1 FROM jw_dev.order_items i
   WHERE i.id=NEW.source_item_id AND i.order_id=NEW.order_id
     AND i.position=NEW.position AND i.quantity=NEW.quantity
     AND i.unit_price=NEW.unit_price_krw
 ) THEN
  RAISE EXCEPTION USING ERRCODE='23514',
    MESSAGE='V151_SOURCE_ITEM_REJECTED';
 END IF;
 RETURN NEW;
END $v151line$;

CREATE TRIGGER v151_line_source_insert
 BEFORE INSERT ON jw_dev.review_delivery_items_v151
 FOR EACH ROW EXECUTE FUNCTION jw_dev.v151_line_source_guard();

REVOKE ALL ON FUNCTION jw_dev.v151_order_source_guard(),
                       jw_dev.v151_line_source_guard()
 FROM PUBLIC, anon, authenticated, jw_app_dev, jw_auth_stage_v85,
      jw_stage1_trade_20261030, jw_stage1_auth_20261030;


-- V15.2 proof audit integrity: review rows are write-once.
-- A second privileged, audited approval record is required to progress; never
-- mutate, delete or silently overwrite the original evidence. The owner/
-- superuser can still manage schema, so this is not an independent trust root.
CREATE FUNCTION jw_dev.v152_reject_evidence_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, jw_dev
AS $reject$
BEGIN
 RAISE EXCEPTION USING ERRCODE='42501',
   MESSAGE='V152_REVIEW_EVIDENCE_IMMUTABLE';
END $reject$;

CREATE TRIGGER v152_review_signup_immutable
 BEFORE UPDATE OR DELETE ON jw_dev.review_signup_requests_v151
 FOR EACH ROW EXECUTE FUNCTION jw_dev.v152_reject_evidence_mutation();

CREATE TRIGGER v152_review_signup_nonce_immutable
 BEFORE UPDATE OR DELETE ON jw_dev.review_signup_nonces_v151
 FOR EACH ROW EXECUTE FUNCTION jw_dev.v152_reject_evidence_mutation();

CREATE TRIGGER v152_review_delivery_immutable
 BEFORE UPDATE OR DELETE ON jw_dev.review_delivery_receipts_v151
 FOR EACH ROW EXECUTE FUNCTION jw_dev.v152_reject_evidence_mutation();

CREATE TRIGGER v152_review_delivery_nonce_immutable
 BEFORE UPDATE OR DELETE ON jw_dev.review_delivery_nonces_v151
 FOR EACH ROW EXECUTE FUNCTION jw_dev.v152_reject_evidence_mutation();

CREATE TRIGGER v152_review_delivery_item_immutable
 BEFORE UPDATE OR DELETE ON jw_dev.review_delivery_items_v151
 FOR EACH ROW EXECUTE FUNCTION jw_dev.v152_reject_evidence_mutation();

REVOKE ALL ON FUNCTION jw_dev.v152_reject_evidence_mutation()
 FROM PUBLIC, anon, authenticated, jw_app_dev, jw_auth_stage_v85,
      jw_stage1_trade_20261030, jw_stage1_auth_20261030;


-- V15.3: RESTRICTED TRADE-ROLE REVIEW WRITES ONLY.
-- DO NOT APPLY PERSISTENTLY. Test in BEGIN + V15.1/2 candidate DDL + this
-- candidate + synthetic assertions + ROLLBACK in the existing empty DEV.
-- Explicit approval AND verified independent issuer integration required before
-- production installation. This is not an account or payment permission.

-- Receipt source can only be read/written by the authenticated tenant's
-- admin, and source must be an existing fulfilled+acknowledged order.
CREATE POLICY v153_receipt_tenant_select
 ON jw_dev.review_delivery_receipts_v151 FOR SELECT TO jw_app_dev
 USING (
   org_id = (SELECT jw_dev.current_org_from_session())
   AND EXISTS (
     SELECT 1 FROM jw_dev.stage_identity_v84() a
     WHERE a.org_id=review_delivery_receipts_v151.org_id
       AND a.actor_role='admin'
   )
 );

CREATE POLICY v153_receipt_admin_insert
 ON jw_dev.review_delivery_receipts_v151 FOR INSERT TO jw_app_dev
 WITH CHECK (
   org_id = (SELECT jw_dev.current_org_from_session())
   AND EXISTS (
      SELECT 1 FROM jw_dev.stage_identity_v84() a
      WHERE a.org_id = review_delivery_receipts_v151.org_id
        AND a.actor_role = 'admin'
   )
   AND EXISTS (
      SELECT 1 FROM jw_dev.orders o
       WHERE o.id=review_delivery_receipts_v151.order_id
         AND o.org_id=review_delivery_receipts_v151.org_id
         AND o.status='fulfilled'
         AND o.review_state='acknowledged'
   )
 );

-- Nonces and line items may be inserted ONLY through an already authorized
-- parent review receipt. The entire reservation must use one transaction.
CREATE POLICY v153_delivery_nonce_select
 ON jw_dev.review_delivery_nonces_v151 FOR SELECT TO jw_app_dev
 USING (EXISTS (
   SELECT 1 FROM jw_dev.review_delivery_receipts_v151 r
    WHERE r.order_id=review_delivery_nonces_v151.order_id
 ));

CREATE POLICY v153_delivery_nonce_insert
 ON jw_dev.review_delivery_nonces_v151 FOR INSERT TO jw_app_dev
 WITH CHECK (EXISTS (
   SELECT 1 FROM jw_dev.review_delivery_receipts_v151 r
   JOIN jw_dev.stage_identity_v84() a ON a.org_id=r.org_id
    WHERE r.order_id=review_delivery_nonces_v151.order_id
      AND a.actor_role='admin'
 ));

CREATE POLICY v153_delivery_line_select
 ON jw_dev.review_delivery_items_v151 FOR SELECT TO jw_app_dev
 USING (EXISTS (
   SELECT 1 FROM jw_dev.review_delivery_receipts_v151 r
    WHERE r.order_id=review_delivery_items_v151.order_id
 ));

CREATE POLICY v153_delivery_line_insert
 ON jw_dev.review_delivery_items_v151 FOR INSERT TO jw_app_dev
 WITH CHECK (EXISTS (
   SELECT 1 FROM jw_dev.review_delivery_receipts_v151 r
   JOIN jw_dev.stage_identity_v84() a ON a.org_id=r.org_id
    WHERE r.order_id=review_delivery_items_v151.order_id
      AND a.actor_role='admin'
 ));

-- App trade role cannot directly UPDATE or DELETE anything in these ledgers.
-- No direct user or public access and no signup write authorization.
GRANT SELECT, INSERT ON TABLE
 jw_dev.review_delivery_receipts_v151,
 jw_dev.review_delivery_nonces_v151,
 jw_dev.review_delivery_items_v151
 TO jw_app_dev;


-- V15.9 isolated review-writer privilege boundary candidate. NEVER auto-migrate.
-- Precondition: V15.1 ledger and V15.3 scoped RLS have been created in a
-- disposable PG17 test instance; never run on live Supabase without approval.
-- This deliberately makes legacy V15.4 POST fail closed until the service has
-- a SEPARATE dedicated writer login and externally verified issuer integration.
-- No direct INSERT may remain on generic jw_app_dev, anon, authenticated,
-- or the general API's SQL login.
CREATE ROLE jw_delivery_writer_v159 NOLOGIN NOINHERIT NOBYPASSRLS;
REVOKE INSERT ON
 jw_dev.review_delivery_receipts_v151,
 jw_dev.review_delivery_nonces_v151,
 jw_dev.review_delivery_items_v151
 FROM jw_app_dev, PUBLIC, anon, authenticated;
GRANT USAGE ON SCHEMA jw_dev TO jw_delivery_writer_v159;
GRANT EXECUTE ON FUNCTION
 jw_dev.stage_identity_v84(), jw_dev.current_org_from_session(),
 jw_dev.current_actor_from_session_v82()
 TO jw_delivery_writer_v159;
GRANT SELECT ON
 jw_dev.orders, jw_dev.order_items, jw_dev.invoices,
 jw_dev.review_delivery_receipts_v151,
 jw_dev.review_delivery_nonces_v151,
 jw_dev.review_delivery_items_v151
 TO jw_delivery_writer_v159;
GRANT INSERT ON
 jw_dev.review_delivery_receipts_v151,
 jw_dev.review_delivery_nonces_v151,
 jw_dev.review_delivery_items_v151,
 jw_dev.audit_logs
 TO jw_delivery_writer_v159;

CREATE POLICY v159_order_read ON jw_dev.orders
 FOR SELECT TO jw_delivery_writer_v159
 USING(org_id=jw_dev.current_org_from_session());

CREATE POLICY v159_line_read ON jw_dev.order_items
 FOR SELECT TO jw_delivery_writer_v159
 USING(EXISTS(SELECT 1 FROM jw_dev.orders o
              WHERE o.id=order_id AND o.org_id=jw_dev.current_org_from_session()));

CREATE POLICY v159_invoice_read ON jw_dev.invoices
 FOR SELECT TO jw_delivery_writer_v159
 USING(org_id=jw_dev.current_org_from_session());

CREATE POLICY v159_receipt_read ON jw_dev.review_delivery_receipts_v151
 FOR SELECT TO jw_delivery_writer_v159
 USING(review_delivery_receipts_v151.org_id=jw_dev.current_org_from_session() AND EXISTS
  (SELECT 1 FROM jw_dev.stage_identity_v84() a
   WHERE a.org_id=review_delivery_receipts_v151.org_id AND a.actor_role='admin'));

CREATE POLICY v159_receipt_insert ON jw_dev.review_delivery_receipts_v151
 FOR INSERT TO jw_delivery_writer_v159
 WITH CHECK(review_delivery_receipts_v151.org_id=jw_dev.current_org_from_session() AND EXISTS
  (SELECT 1 FROM jw_dev.stage_identity_v84() a
   WHERE a.org_id=org_id AND a.actor_role='admin') AND EXISTS
  (SELECT 1 FROM jw_dev.orders o
   WHERE o.id=review_delivery_receipts_v151.order_id
     AND o.org_id=review_delivery_receipts_v151.org_id
     AND o.status='fulfilled' AND o.review_state='acknowledged'));

CREATE POLICY v159_nonce_read ON jw_dev.review_delivery_nonces_v151
 FOR SELECT TO jw_delivery_writer_v159
 USING(EXISTS(SELECT 1 FROM jw_dev.review_delivery_receipts_v151 r
              WHERE r.order_id=review_delivery_nonces_v151.order_id));

CREATE POLICY v159_nonce_insert ON jw_dev.review_delivery_nonces_v151
 FOR INSERT TO jw_delivery_writer_v159
 WITH CHECK(EXISTS(SELECT 1 FROM jw_dev.review_delivery_receipts_v151 r
    JOIN jw_dev.stage_identity_v84() a ON a.org_id=r.org_id
    WHERE r.order_id=review_delivery_nonces_v151.order_id
      AND a.actor_role='admin'));

CREATE POLICY v159_item_read ON jw_dev.review_delivery_items_v151
 FOR SELECT TO jw_delivery_writer_v159
 USING(EXISTS(SELECT 1 FROM jw_dev.review_delivery_receipts_v151 r
              WHERE r.order_id=review_delivery_items_v151.order_id));

CREATE POLICY v159_item_insert ON jw_dev.review_delivery_items_v151
 FOR INSERT TO jw_delivery_writer_v159
 WITH CHECK(EXISTS(SELECT 1 FROM jw_dev.review_delivery_receipts_v151 r
    JOIN jw_dev.stage_identity_v84() a ON a.org_id=r.org_id
    WHERE r.order_id=review_delivery_items_v151.order_id
      AND a.actor_role='admin'));

CREATE POLICY v159_audit_insert ON jw_dev.audit_logs
 FOR INSERT TO jw_delivery_writer_v159
 WITH CHECK(org_id=jw_dev.current_org_from_session()
       AND actor_id=jw_dev.current_actor_from_session_v82());

-- No UPDATE/DELETE on ledger, and crucially no UPDATE on source orders.
-- The dedicated writer MUST use advisory serialization + exact-RLS SELECT
-- and must never be granted admin authentication permissions.

DO $verify$ DECLARE nt integer; np integer; BEGIN
 SELECT count(*) INTO nt FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='jw_dev' AND c.relkind='r' AND c.relforcerowsecurity;
 SELECT count(*) INTO np FROM pg_policies WHERE schemaname='jw_dev';
 IF nt<>40 OR np<>56
 OR (SELECT count(*) FROM pg_roles WHERE rolname='jw_delivery_writer_v159' AND NOT rolcanlogin AND NOT rolbypassrls)<>1
 OR has_table_privilege('jw_app_dev','jw_dev.review_delivery_receipts_v151','INSERT')
 OR has_table_privilege('anon','jw_dev.review_delivery_receipts_v151','INSERT')
 OR has_table_privilege('authenticated','jw_dev.review_delivery_receipts_v151','INSERT')
 OR NOT has_table_privilege('jw_delivery_writer_v159','jw_dev.review_delivery_receipts_v151','INSERT')
 OR has_table_privilege('jw_delivery_writer_v159','jw_dev.orders','UPDATE')
 THEN RAISE EXCEPTION 'V163_POSTCONDITION_DENIED_%,%',nt,np; END IF;
END $verify$;
