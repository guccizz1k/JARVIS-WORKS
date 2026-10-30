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
 USING(org_id=jw_dev.current_org_from_session() AND EXISTS
  (SELECT 1 FROM jw_dev.stage_identity_v84() a
   WHERE a.org_id=org_id AND a.actor_role='admin'));

CREATE POLICY v159_receipt_insert ON jw_dev.review_delivery_receipts_v151
 FOR INSERT TO jw_delivery_writer_v159
 WITH CHECK(org_id=jw_dev.current_org_from_session() AND EXISTS
  (SELECT 1 FROM jw_dev.stage_identity_v84() a
   WHERE a.org_id=org_id AND a.actor_role='admin') AND EXISTS
  (SELECT 1 FROM jw_dev.orders o
   WHERE o.id=order_id AND o.org_id=org_id
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
