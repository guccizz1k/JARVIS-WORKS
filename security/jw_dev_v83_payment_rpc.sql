-- JARVIS WORKS V8.3 – review-only staging migration.
-- Do not apply to production; session identity must already be in jw_dev.sessions.
BEGIN;
CREATE FUNCTION jw_dev.financial_state_v83(p_invoice_id text)
RETURNS TABLE(adjusted_total bigint, active_paid bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $body$
DECLARE v_org text; v_mode text; v_sub numeric; v_returns numeric; v_discount numeric; v_freight numeric;
BEGIN
  SELECT i.org_id, i.vat_mode INTO v_org,v_mode FROM jw_dev.invoices i WHERE i.id=p_invoice_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'Invoice absent' USING ERRCODE='23514'; END IF;
  SELECT SUM(it.quantity::numeric * it.unit_price::numeric) INTO v_sub
    FROM jw_dev.invoice_items it WHERE it.invoice_id=p_invoice_id;
  IF v_sub IS NULL THEN RAISE EXCEPTION 'Invoice has no line items' USING ERRCODE='23514'; END IF;
  IF EXISTS(
    SELECT 1 FROM jw_dev.invoice_adjustments_v69 a
    JOIN jw_dev.invoice_adjustment_decisions_v69 d ON d.adjustment_id=a.id AND d.decision='approved'
    LEFT JOIN jw_dev.invoice_items it ON it.id=a.item_id AND it.invoice_id=a.invoice_id
    WHERE a.invoice_id=p_invoice_id AND a.kind='return'
    GROUP BY a.item_id, it.quantity
    HAVING it.quantity IS NULL OR SUM(a.quantity) > it.quantity
  ) THEN RAISE EXCEPTION 'Approved returns exceed invoice items' USING ERRCODE='23514'; END IF;
  SELECT COALESCE(SUM(CASE WHEN a.kind='return' THEN a.quantity::numeric * it.unit_price ELSE 0 END),0),
         COALESCE(SUM(CASE WHEN a.kind='discount' THEN a.amount ELSE 0 END),0),
         COALESCE(SUM(CASE WHEN a.kind='freight' THEN a.amount ELSE 0 END),0)
    INTO v_returns,v_discount,v_freight
    FROM jw_dev.invoice_adjustments_v69 a
    JOIN jw_dev.invoice_adjustment_decisions_v69 d ON d.adjustment_id=a.id AND d.decision='approved'
    LEFT JOIN jw_dev.invoice_items it ON it.id=a.item_id AND it.invoice_id=p_invoice_id
    WHERE a.invoice_id=p_invoice_id AND a.org_id=v_org;
  v_sub:=v_sub-v_returns-v_discount+v_freight;
  IF v_sub < 0 OR v_sub>10000000000000000 THEN
    RAISE EXCEPTION 'Invalid adjusted subtotal' USING ERRCODE='23514'; END IF;
  adjusted_total:=(v_sub + CASE WHEN v_mode='taxable' THEN floor((v_sub+5)/10) ELSE 0 END)::bigint;
  SELECT COALESCE(SUM(p.amount),0)::bigint INTO active_paid FROM jw_dev.payments p
   WHERE p.invoice_id=p_invoice_id AND p.org_id=v_org AND p.reversed_at IS NULL;
  RETURN NEXT;
END $body$;
REVOKE ALL ON FUNCTION jw_dev.financial_state_v83(text) FROM PUBLIC,anon,authenticated,service_role,jw_app_dev;

CREATE FUNCTION jw_dev.record_payment_v83(p_invoice text,p_amount bigint,p_date date,p_reference text,p_note text DEFAULT '')
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $body$
DECLARE v_org text; v_actor text; v_inv_org text; v_existing jw_dev.payments%ROWTYPE;
        v_total bigint; v_paid bigint; v_id text;
BEGIN
  v_org:=jw_dev.current_org_from_session(); v_actor:=jw_dev.current_actor_from_session_v82();
  IF v_org IS NULL OR v_actor IS NULL THEN RAISE EXCEPTION 'Authenticated session required' USING ERRCODE='42501'; END IF;
  IF p_amount IS NULL OR p_amount<=0 OR p_amount>10000000000000000 OR p_date IS NULL
   OR p_date>(clock_timestamp() AT TIME ZONE 'Asia/Seoul')::date
   OR p_reference IS NULL OR length(p_reference) NOT BETWEEN 8 AND 100
   OR p_note IS NULL OR length(p_note)>300 THEN
    RAISE EXCEPTION 'Invalid payment request' USING ERRCODE='23514'; END IF;
  SELECT i.org_id INTO v_inv_org FROM jw_dev.invoices i WHERE i.id=p_invoice FOR UPDATE;
  IF v_inv_org IS DISTINCT FROM v_org THEN RAISE EXCEPTION 'Invoice outside tenant' USING ERRCODE='42501'; END IF;
  SELECT * INTO v_existing FROM jw_dev.payments
   WHERE org_id=v_org AND invoice_id=p_invoice AND reference=p_reference;
  IF FOUND THEN
   IF v_existing.reversed_at IS NOT NULL OR v_existing.amount<>p_amount
    OR v_existing.paid_at<>p_date::text OR v_existing.note<>p_note THEN
    RAISE EXCEPTION 'Conflicting or reversed payment request key' USING ERRCODE='23514'; END IF;
   RETURN v_existing.id;
  END IF;
  SELECT fs.adjusted_total,fs.active_paid INTO v_total,v_paid
    FROM jw_dev.financial_state_v83(p_invoice) fs;
  IF p_amount>v_total-v_paid THEN
    RAISE EXCEPTION 'Payment exceeds outstanding balance' USING ERRCODE='23514'; END IF;
  v_id:=gen_random_uuid()::text;
  INSERT INTO jw_dev.payments(id,org_id,invoice_id,amount,paid_at,note,created_at,reference)
  VALUES(v_id,v_org,p_invoice,p_amount,p_date::text,p_note,clock_timestamp()::text,p_reference);
  INSERT INTO jw_dev.audit_logs(id,org_id,actor_id,entity_type,entity_id,action,detail,created_at)
   VALUES(gen_random_uuid()::text,v_org,v_actor,'payment',v_id,'create',
     jsonb_build_object('invoice_id',p_invoice,'amount',p_amount,'reference',p_reference)::text,clock_timestamp()::text);
  RETURN v_id;
END $body$;
REVOKE ALL ON FUNCTION jw_dev.record_payment_v83(text,bigint,date,text,text) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION jw_dev.record_payment_v83(text,bigint,date,text,text) TO jw_app_dev;

CREATE FUNCTION jw_dev.reverse_payment_v83(p_invoice text,p_payment_id text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $body$
DECLARE v_org text; v_actor text; v_inv_org text; v_pay jw_dev.payments%ROWTYPE;
BEGIN
 v_org:=jw_dev.current_org_from_session(); v_actor:=jw_dev.current_actor_from_session_v82();
 IF v_org IS NULL OR v_actor IS NULL OR NOT EXISTS (
   SELECT 1 FROM jw_dev.users u WHERE u.id=v_actor AND u.org_id=v_org AND u.role='admin'
 ) THEN RAISE EXCEPTION 'Admin session required' USING ERRCODE='42501'; END IF;
 SELECT i.org_id INTO v_inv_org FROM jw_dev.invoices i WHERE i.id=p_invoice FOR UPDATE;
 IF v_inv_org IS DISTINCT FROM v_org THEN RAISE EXCEPTION 'Invoice outside tenant' USING ERRCODE='42501'; END IF;
 SELECT * INTO v_pay FROM jw_dev.payments
  WHERE id=p_payment_id AND org_id=v_org AND invoice_id=p_invoice FOR UPDATE;
 IF NOT FOUND OR v_pay.reversed_at IS NOT NULL THEN
  RAISE EXCEPTION 'Payment missing or already reversed' USING ERRCODE='23514'; END IF;
 UPDATE jw_dev.payments SET reversed_at=clock_timestamp()::text,reversed_by=v_actor WHERE id=p_payment_id;
 INSERT INTO jw_dev.audit_logs(id,org_id,actor_id,entity_type,entity_id,action,detail,created_at)
  VALUES(gen_random_uuid()::text,v_org,v_actor,'payment',p_payment_id,'reverse',
    jsonb_build_object('invoice_id',p_invoice,'amount',v_pay.amount,'reference',v_pay.reference)::text,clock_timestamp()::text);
 RETURN true;
END $body$;
REVOKE ALL ON FUNCTION jw_dev.reverse_payment_v83(text,text) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION jw_dev.reverse_payment_v83(text,text) TO jw_app_dev;

CREATE FUNCTION jw_dev.guard_payment_history_v83()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $body$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Payment history cannot be deleted' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' AND (
  NEW.id IS DISTINCT FROM OLD.id OR NEW.org_id IS DISTINCT FROM OLD.org_id OR
  NEW.invoice_id IS DISTINCT FROM OLD.invoice_id OR NEW.amount IS DISTINCT FROM OLD.amount OR
  NEW.paid_at IS DISTINCT FROM OLD.paid_at OR NEW.note IS DISTINCT FROM OLD.note OR
  NEW.reference IS DISTINCT FROM OLD.reference OR NEW.created_at IS DISTINCT FROM OLD.created_at OR
  OLD.reversed_at IS NOT NULL OR NEW.reversed_at IS NULL OR NEW.reversed_by IS NULL OR
  NOT EXISTS(SELECT 1 FROM jw_dev.users u WHERE u.id=NEW.reversed_by AND u.org_id=OLD.org_id AND u.role='admin')
 ) THEN RAISE EXCEPTION 'Invalid payment record mutation' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' THEN RETURN NEW; END IF;
 RETURN OLD;
END $body$;
REVOKE ALL ON FUNCTION jw_dev.guard_payment_history_v83() FROM PUBLIC,anon,authenticated,service_role,jw_app_dev;
CREATE TRIGGER jw_v83_payment_history_guard BEFORE UPDATE OR DELETE ON jw_dev.payments
 FOR EACH ROW EXECUTE FUNCTION jw_dev.guard_payment_history_v83();
COMMIT;
