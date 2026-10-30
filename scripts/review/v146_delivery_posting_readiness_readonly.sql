-- V14.6: conservative catalog-only preflight, no writes, no real customer data.
-- A missing physical delivery record/source MUST block invoice/payment posting.
WITH present AS (
    SELECT
      to_regclass('jw_dev.orders') IS NOT NULL AS order_source,
      to_regclass('jw_dev.order_items') IS NOT NULL AS order_items,
      to_regclass('jw_dev.invoices') IS NOT NULL AS invoices,
      to_regclass('jw_dev.invoice_items') IS NOT NULL AS invoice_items,
      to_regclass('jw_dev.payments') IS NOT NULL AS payments,
      (to_regclass('jw_dev.delivery_notes') IS NOT NULL
       OR to_regclass('jw_dev.delivery_notes_v146') IS NOT NULL
       OR to_regclass('jw_dev.shipments') IS NOT NULL) AS physical_delivery_ledger,
      EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
              WHERE n.nspname='jw_dev' AND p.proname='record_payment_v83') AS payment_rpc,
      EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
              WHERE n.nspname='jw_dev' AND p.proname='reverse_payment_v83') AS reversal_rpc
)
SELECT *,
 CASE WHEN order_source AND order_items AND invoices AND invoice_items AND
           payments AND physical_delivery_ledger AND payment_rpc AND reversal_rpc
      THEN 'CATALOG_PREREQUISITES_PRESENT_NOT_APPROVAL'
      ELSE 'BLOCKED_MISSING_REAL_DELIVERY_POSTING_PREREQUISITES'
 END AS posting_gate,
 'NOT_VERIFIED'::text AS physical_delivery_human_acceptance,
 'NOT_VERIFIED'::text AS exact_sha_hosted_business_e2e,
 'BLOCKED'::text AS stage3_release_acceptance
FROM present;
