-- V15.3: RESTRICTED TRADE-ROLE REVIEW WRITES ONLY.
-- DO NOT APPLY PERSISTENTLY. Test in BEGIN + V15.1/2 candidate DDL + this
-- candidate + synthetic assertions + ROLLBACK in the existing empty DEV.
-- Explicit approval AND verified independent issuer integration required before
-- production installation. This is not an account or payment permission.

-- Receipt source can only be read/written by the authenticated tenant's
-- admin, and source must be an existing fulfilled+acknowledged order.
CREATE POLICY v153_receipt_tenant_select
 ON jw_dev.review_delivery_receipts_v151 FOR SELECT TO jw_app_dev
 USING (org_id = (SELECT jw_dev.current_org_from_session()));

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
