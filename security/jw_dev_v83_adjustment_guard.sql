-- JARVIS WORKS V8.3 – approved adjustments serialize on the invoice row.
-- If a credit would make outstanding balance negative, approval is denied.
-- Run only against the reviewed jw_dev staging schema.
BEGIN;
CREATE FUNCTION jw_dev.guard_adjustment_balance_v83()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $body$
DECLARE
 v_invoice text; v_org text; v_existing_org text; v_kind text; v_item text;
 v_qty bigint; v_amount bigint; v_item_qty bigint; v_unit_price bigint;
 v_returned bigint; v_sub numeric; v_ret numeric; v_discount numeric; v_freight numeric;
 v_paid numeric; v_next numeric; v_total numeric;
BEGIN
 SELECT a.invoice_id,a.org_id,a.kind,a.item_id,a.quantity,a.amount
 INTO v_invoice,v_org,v_kind,v_item,v_qty,v_amount
 FROM jw_dev.invoice_adjustments_v69 a WHERE a.id=NEW.adjustment_id;
 IF v_invoice IS NULL OR NEW.org_id IS DISTINCT FROM v_org THEN
 RAISE EXCEPTION 'Adjustment decision tenant mismatch' USING ERRCODE='23514'; END IF;
 SELECT i.org_id INTO v_existing_org FROM jw_dev.invoices i
 WHERE i.id=v_invoice FOR UPDATE;
 IF v_existing_org IS DISTINCT FROM v_org THEN
 RAISE EXCEPTION 'Adjustment invoice tenant mismatch' USING ERRCODE='23514'; END IF;
 IF NEW.decision='approved' THEN
   SELECT COALESCE(SUM(it.quantity::numeric*it.unit_price::numeric),0)
   INTO v_sub FROM jw_dev.invoice_items it WHERE it.invoice_id=v_invoice;
   SELECT COALESCE(SUM(CASE WHEN a.kind='return' THEN a.quantity::numeric*it.unit_price ELSE 0 END),0),
   COALESCE(SUM(CASE WHEN a.kind='discount' THEN a.amount ELSE 0 END),0),
   COALESCE(SUM(CASE WHEN a.kind='freight' THEN a.amount ELSE 0 END),0)
   INTO v_ret,v_discount,v_freight
   FROM jw_dev.invoice_adjustments_v69 a
   JOIN jw_dev.invoice_adjustment_decisions_v69 d ON d.adjustment_id=a.id AND d.decision='approved'
   LEFT JOIN jw_dev.invoice_items it ON it.id=a.item_id AND it.invoice_id=v_invoice
   WHERE a.invoice_id=v_invoice AND a.org_id=v_org;
   v_next:=v_sub-v_ret-v_discount+v_freight;
   IF v_kind='return' THEN
      SELECT it.quantity,it.unit_price INTO v_item_qty,v_unit_price
      FROM jw_dev.invoice_items it WHERE it.id=v_item AND it.invoice_id=v_invoice;
      SELECT COALESCE(SUM(a.quantity),0) INTO v_returned
      FROM jw_dev.invoice_adjustments_v69 a
      JOIN jw_dev.invoice_adjustment_decisions_v69 d ON d.adjustment_id=a.id AND d.decision='approved'
      WHERE a.invoice_id=v_invoice AND a.kind='return' AND a.item_id=v_item;
      IF v_item_qty IS NULL OR v_returned+v_qty>v_item_qty THEN
         RAISE EXCEPTION 'Cumulative return exceeds invoice quantity' USING ERRCODE='23514'; END IF;
      v_next:=v_next-(v_qty::numeric*v_unit_price);
   ELSIF v_kind='discount' THEN v_next:=v_next-v_amount;
   ELSIF v_kind='freight' THEN v_next:=v_next+v_amount;
   ELSE RAISE EXCEPTION 'Unknown adjustment kind' USING ERRCODE='23514';
   END IF;
   IF v_next<0 OR v_next>10000000000000000 THEN
      RAISE EXCEPTION 'Invalid adjusted subtotal' USING ERRCODE='23514'; END IF;
   SELECT COALESCE(SUM(p.amount),0)::numeric INTO v_paid FROM jw_dev.payments p
     WHERE p.invoice_id=v_invoice AND p.org_id=v_org AND p.reversed_at IS NULL;
   v_total:=v_next+CASE WHEN EXISTS(SELECT 1 FROM jw_dev.invoices i WHERE i.id=v_invoice AND i.vat_mode='taxable')
      THEN floor((v_next+5)/10) ELSE 0 END;
   IF v_total<v_paid THEN
      RAISE EXCEPTION 'Adjustment below collected balance; refund review required' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $body$;
REVOKE ALL ON FUNCTION jw_dev.guard_adjustment_balance_v83() FROM PUBLIC,anon,authenticated,service_role,jw_app_dev;
CREATE TRIGGER jw_v83_approval_lock_and_balance BEFORE INSERT ON jw_dev.invoice_adjustment_decisions_v69
FOR EACH ROW EXECUTE FUNCTION jw_dev.guard_adjustment_balance_v83();
COMMIT;
