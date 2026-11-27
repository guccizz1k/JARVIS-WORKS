-- REVIEW ONLY. Candidate for a newly created disposable workload DB.
-- Execute as namespaced owner, in same session as verified postgres login.
-- Do not use on original postgres or production. No adoption until full lifecycle and concurrency regression.
BEGIN;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='20s';
DO $guard$ BEGIN
 IF current_database() !~ '^naruv_qa_workload_[a-f0-9]{12}$' OR session_user<>'postgres'
 OR current_user !~ '^nq_[a-f0-9]{12}_naruv_native_owner$'
 OR NOT EXISTS (SELECT 1 FROM pg_proc WHERE oid='naruv_valuation.reconcile_bill(text,text)'::regprocedure AND pg_get_userbyid(proowner)=current_user AND md5(prosrc)='bae4c77687cd2b3106a4efca3ded6850')
 THEN RAISE EXCEPTION 'RECONCILE_CANDIDATE_SCOPE'; END IF;
END $guard$;
CREATE OR REPLACE FUNCTION naruv_valuation.reconcile_bill(p_bill text, p_csrf text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE a record; a2 record; b naruv_finance.bills; f naruv_trade.events;
 d naruv_trade.documents; m naruv_inventory.movements; e naruv_valuation.entries;
 j jsonb; cj naruv_valuation.cost_journals; clearing numeric; sales numeric; credited boolean; ce naruv_finance.events; re naruv_valuation.entries; rm naruv_inventory.movements; q bigint:=0; rq bigint; rn numeric:=0; rv numeric:=0; rc numeric:=0; en numeric; ev numeric; ec numeric; variance numeric; vs numeric:=0; rf naruv_finance.events; refund_amount bigint; refund_id text; refund_total numeric:=0; vat_balance numeric; cash_balance numeric; variance_balance numeric;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF NOT naruv_production.ident(p_bill) THEN RAISE EXCEPTION 'COST_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM
 (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO b FROM naruv_finance.bills z WHERE z.org_id=a.org_id AND z.bill_id=p_bill;
 IF NOT FOUND THEN RAISE EXCEPTION 'INV_NOT_FOUND'; END IF;
 SELECT * INTO d FROM naruv_trade.documents z WHERE z.org_id=a.org_id AND z.doc_id=b.doc_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 SELECT * INTO f FROM naruv_trade.events z WHERE z.org_id=a.org_id AND z.request_id=b.fulfillment_id AND z.doc_id=b.doc_id AND z.action='fulfill';
 IF NOT FOUND THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 SELECT * INTO m FROM naruv_inventory.movements z WHERE z.org_id=a.org_id AND z.request_id=f.movement_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 SELECT * INTO e FROM naruv_valuation.entries z WHERE z.org_id=a.org_id AND z.movement_id=m.request_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 IF (b.kind,b.quantity,b.subtotal,m.source_id,m.normalized_id,m.actor_id,e.kind,e.source_event_id)
 IS DISTINCT FROM (d.kind,m.quantity,m.quantity*d.unit_price,d.source_id,d.item_id,f.actor_id,d.kind,f.request_id)
 OR m.from_warehouse IS DISTINCT FROM (CASE WHEN d.kind='sale' THEN d.warehouse_id ELSE NULL END)
 OR m.to_warehouse IS DISTINCT FROM (CASE WHEN d.kind='purchase' THEN d.warehouse_id ELSE NULL END)
 OR (b.kind='purchase' AND e.amount_krw<>b.subtotal)
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 SELECT * INTO cj FROM naruv_valuation.cost_journals z WHERE z.org_id=a.org_id AND z.movement_id=m.request_id;
 IF NOT FOUND OR cj.amount_krw<>e.amount_krw
 OR (e.amount_krw>0 AND (cj.debit_account,cj.credit_account) IS DISTINCT FROM
 (CASE WHEN b.kind='purchase' THEN 'INVENTORY' ELSE 'COGS' END,
  CASE WHEN b.kind='purchase' THEN 'PURCHASE_CLEARING' ELSE 'INVENTORY' END))
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 j:=naruv_accounting.inspect_bill(p_bill,p_csrf);
 FOR ce IN SELECT * FROM naruv_finance.events z WHERE z.org_id=a.org_id AND z.bill_id=p_bill AND z.action='credit'
 ORDER BY (z.payload->>'prior_quantity')::bigint LOOP
  rq:=(ce.payload->>'quantity')::bigint;
  IF rq IS NULL OR rq<1 OR q+rq>b.quantity OR (ce.payload->>'prior_quantity')::bigint IS DISTINCT FROM q THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  en:=naruv_finance.allocation(b.subtotal,b.quantity,q,rq);
  ev:=naruv_finance.allocation(b.vat,b.quantity,q,rq);
  ec:=naruv_finance.allocation(e.amount_krw,b.quantity,q,rq);
  SELECT * INTO re FROM naruv_valuation.entries z WHERE z.org_id=a.org_id AND z.movement_id=ce.payload->>'movement_id';
  variance:=coalesce((ce.payload->>'variance')::numeric,0);
  IF NOT FOUND OR (re.kind,re.source_event_id,re.amount_krw,ce.amount,(ce.payload->>'net')::numeric,(ce.payload->>'vat')::numeric)
   IS DISTINCT FROM (b.kind||'_return',ce.request_id,ec-variance,(en+ev)::bigint,en,ev)
   OR (b.kind='sale' AND variance<>0) THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  vs:=vs+variance;
  refund_amount:=coalesce((ce.payload->>'refund_amount')::bigint,0);refund_id:=ce.payload->>'refund_id';
  IF refund_amount>0 THEN
   SELECT * INTO rf FROM naruv_finance.events z WHERE z.org_id=a.org_id AND z.request_id=refund_id;
   IF NOT FOUND OR (rf.action,rf.bill_id,rf.actor_id,rf.amount,rf.payload->>'credit_request_id')
    IS DISTINCT FROM ('refund'::text,p_bill,ce.actor_id,refund_amount,ce.request_id) THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  ELSIF refund_id IS NOT NULL THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  refund_total:=refund_total+refund_amount;
  SELECT * INTO rm FROM naruv_inventory.movements z WHERE z.org_id=a.org_id AND z.request_id=re.movement_id;
  IF NOT FOUND OR (rm.source_id,rm.normalized_id,rm.from_warehouse,rm.to_warehouse,rm.quantity,rm.actor_id)
   IS DISTINCT FROM (m.source_id,m.normalized_id,m.to_warehouse,m.from_warehouse,rq,ce.actor_id) THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  q:=q+rq;rn:=rn+en;rv:=rv+ev;rc:=rc+ec;
 END LOOP;
 IF refund_total<>(SELECT coalesce(sum(amount),0) FROM naruv_finance.events WHERE org_id=a.org_id AND bill_id=p_bill AND action='refund')
 OR EXISTS(SELECT 1 FROM naruv_finance.events x WHERE x.org_id=a.org_id AND x.bill_id=p_bill AND x.action='refund'
 AND NOT EXISTS(SELECT 1 FROM naruv_finance.events z WHERE z.org_id=x.org_id AND z.bill_id=x.bill_id AND z.action='credit' AND z.request_id=x.payload->>'credit_request_id' AND z.payload->>'refund_id'=x.request_id))
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 SELECT coalesce(sum(l.debit::numeric-l.credit) FILTER(WHERE l.account='PURCHASE_CLEARING'),0),
 coalesce(sum(l.credit::numeric-l.debit) FILTER(WHERE l.account='SALES'),0),
coalesce(sum(CASE WHEN b.kind='sale' AND l.account='VAT_OUTPUT' THEN l.credit-l.debit WHEN b.kind='purchase' AND l.account='VAT_INPUT' THEN l.debit-l.credit ELSE 0 END),0),
 coalesce(sum(CASE WHEN l.account='CASH_CLEARING' THEN CASE WHEN b.kind='sale' THEN l.debit-l.credit ELSE l.credit-l.debit END ELSE 0 END),0),
 coalesce(sum(CASE WHEN l.account='PURCHASE_COST_VARIANCE' THEN l.credit-l.debit ELSE 0 END),0)
 INTO clearing,sales,vat_balance,cash_balance,variance_balance FROM naruv_accounting.lines l JOIN naruv_accounting.journals h USING(org_id,event_id)
 WHERE h.org_id=a.org_id AND h.bill_id=p_bill;
 IF vat_balance<>b.vat-rv OR cash_balance<>naruv_finance.paid(a.org_id,p_bill) OR variance_balance<>vs THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 credited:=q=b.quantity;
 IF clearing<>(CASE WHEN b.kind='purchase' THEN b.subtotal-rn+vs ELSE 0 END)
 OR sales<>(CASE WHEN b.kind='sale' THEN b.subtotal-rn ELSE 0 END)
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 RETURN jsonb_build_object('bill_id',p_bill,'fulfillment_id',b.fulfillment_id,'kind',b.kind,
 'net_krw',(b.subtotal-rn)::text,'inventory_cost_krw',(e.amount_krw-rc)::text,
 'purchase_clearing_difference_krw',CASE WHEN b.kind='purchase' THEN (clearing-e.amount_krw+rc-vs)::text ELSE NULL END,
 'sales_margin_krw',CASE WHEN b.kind='sale' THEN (sales-e.amount_krw+rc)::text ELSE NULL END,
 'credited',credited,'returned_quantity',q,'purchase_cost_variance_krw',vs::text,'credited_krw',(rn+rv)::text,'outstanding_krw',j->>'outstanding','cost_journal_posted',true,'statutory_posted',false,'production_authorized',false);
END $$;
COMMIT;
