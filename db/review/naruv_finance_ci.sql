-- Disposable PG17 only. Internal billing and settlement evidence, never tax issuance.
DO $$ BEGIN
 IF current_database()<>'postgres' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user<>'postgres' OR current_setting('naruv.finance_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'NARUV_FINANCE_DISPOSABLE_ONLY'; END IF;
END $$;
CREATE SCHEMA naruv_finance AUTHORIZATION naruv_native_owner;
REVOKE ALL ON SCHEMA naruv_finance FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT USAGE ON SCHEMA naruv_finance TO jw_app_dev;
SET ROLE naruv_native_owner;
CREATE TABLE naruv_finance.bills(
 org_id text NOT NULL,bill_id text NOT NULL,doc_id text NOT NULL,fulfillment_id text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('sale','purchase')),actor_id text NOT NULL,
 quantity bigint NOT NULL CHECK(quantity BETWEEN 1 AND 100000),
 subtotal bigint NOT NULL CHECK(subtotal BETWEEN 0 AND 100000000000000),
 vat bigint NOT NULL CHECK(vat>=0 AND vat<=subtotal),
 total bigint GENERATED ALWAYS AS(subtotal+vat) STORED,created_at timestamptz NOT NULL,
 PRIMARY KEY(org_id,bill_id),UNIQUE(org_id,fulfillment_id),
 FOREIGN KEY(org_id,doc_id) REFERENCES naruv_trade.documents,
 FOREIGN KEY(org_id,fulfillment_id) REFERENCES naruv_trade.events(org_id,request_id)
);
CREATE TABLE naruv_finance.events(
 org_id text NOT NULL,request_id text NOT NULL,bill_id text NOT NULL,actor_id text NOT NULL,
 action text NOT NULL CHECK(action IN ('bill','pay','reverse','credit')),payload jsonb NOT NULL,
 amount bigint NOT NULL CHECK(amount BETWEEN 0 AND 110000000000000),
 payment_ref text,reversal_of text,receipt jsonb NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(org_id,request_id),UNIQUE(org_id,payment_ref),UNIQUE(org_id,reversal_of),
 FOREIGN KEY(org_id,bill_id) REFERENCES naruv_finance.bills,
 FOREIGN KEY(org_id,reversal_of) REFERENCES naruv_finance.events(org_id,request_id),
 CHECK((action='pay')=(payment_ref IS NOT NULL)),
 CHECK((action='reverse')=(reversal_of IS NOT NULL)),
 CHECK((action='bill' AND amount=0) OR (action IN ('pay','reverse') AND amount>0) OR action='credit')
);
CREATE INDEX finance_credit_bill ON naruv_finance.events(org_id,bill_id) WHERE action='credit';
CREATE INDEX finance_bill_doc ON naruv_finance.bills(org_id,doc_id);
CREATE INDEX finance_event_bill ON naruv_finance.events(org_id,bill_id);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['bills','events'] LOOP
  EXECUTE format('ALTER TABLE naruv_finance.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE naruv_finance.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY finance_scope ON naruv_finance.%I TO naruv_native_owner USING (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin'')) WITH CHECK (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin''))',t);
  EXECUTE format('REVOKE ALL ON naruv_finance.%I FROM PUBLIC,jw_app_dev,naruv_native_stage',t);
 END LOOP;
END $$;
CREATE TRIGGER bills_immutable BEFORE UPDATE OR DELETE ON naruv_finance.bills FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE TRIGGER events_immutable BEFORE UPDATE OR DELETE ON naruv_finance.events FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE FUNCTION naruv_finance.paid(p_org text,p_bill text) RETURNS bigint
 LANGUAGE sql VOLATILE SET search_path=pg_catalog AS $$
 SELECT coalesce(sum(CASE WHEN action='pay' THEN amount WHEN action='reverse' THEN -amount ELSE 0 END),0)::bigint
 FROM naruv_finance.events WHERE org_id=p_org AND bill_id=p_bill
$$;
CREATE FUNCTION naruv_finance.credited(p_org text,p_bill text) RETURNS boolean
 LANGUAGE sql VOLATILE SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM naruv_finance.events WHERE org_id=p_org AND bill_id=p_bill AND action='credit')
$$;
CREATE FUNCTION naruv_finance.credit_sum(p_org text,p_bill text) RETURNS bigint
 LANGUAGE sql VOLATILE SET search_path=pg_catalog AS $$
 SELECT coalesce(sum(amount),0)::bigint FROM naruv_finance.events WHERE org_id=p_org AND bill_id=p_bill AND action='credit'
$$;
CREATE FUNCTION naruv_finance.returned_qty(p_org text,p_bill text) RETURNS bigint
 LANGUAGE sql VOLATILE SET search_path=pg_catalog AS $$
 SELECT coalesce(sum((payload->>'quantity')::bigint),0)::bigint FROM naruv_finance.events WHERE org_id=p_org AND bill_id=p_bill AND action='credit'
$$;
-- Exact cumulative half-up allocation; the last unit drains the original amount.
CREATE FUNCTION naruv_finance.allocation(p_amount numeric,p_total bigint,p_previous bigint,p_qty bigint)
 RETURNS numeric LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT div(2*p_amount*(p_previous+p_qty)+p_total,2*p_total)-div(2*p_amount*p_previous+p_total,2*p_total)
$$;
CREATE FUNCTION naruv_finance.snapshot(b naruv_finance.bills,p_paid bigint) RETURNS jsonb
 LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('bill_id',($1).bill_id,'doc_id',($1).doc_id,'fulfillment_id',($1).fulfillment_id,
 'kind',($1).kind,'quantity',($1).quantity,'subtotal',($1).subtotal,'vat',($1).vat,'total',($1).total,
 'paid',$2,'outstanding',($1).total-$2,'state',CASE WHEN ($1).total=$2 THEN 'SETTLED' WHEN $2=0 THEN 'OPEN' ELSE 'PARTIAL' END,
 'production_authorized',false)
$$;
CREATE FUNCTION naruv_finance.adjusted_snapshot(b naruv_finance.bills,p_paid bigint) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
DECLARE c bigint; q bigint; due bigint; result jsonb;
BEGIN
 c:=naruv_finance.credit_sum(b.org_id,b.bill_id);q:=naruv_finance.returned_qty(b.org_id,b.bill_id);
 due:=b.total-p_paid-c;
 IF q<0 OR q>b.quantity OR c<0 OR c>b.total OR p_paid<0 OR due<0 OR (q=b.quantity AND c<>b.total)
 THEN RAISE EXCEPTION 'FIN_INTEGRITY'; END IF;
 result:=naruv_finance.snapshot(b,p_paid);
 IF q=0 THEN RETURN result; END IF;
 RETURN result||jsonb_build_object('credited',c,'returned_quantity',q,'outstanding',due,
 'state',CASE WHEN q=b.quantity THEN 'CREDITED' WHEN due=0 THEN 'SETTLED' WHEN p_paid=0 THEN 'OPEN' ELSE 'PARTIAL' END);
END $$;
CREATE FUNCTION naruv_finance.command(p_bill text,p_request text,p_action text,p_payload jsonb,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; b naruv_finance.bills; e naruv_finance.events; original naruv_finance.events;
 d naruv_trade.documents; f naruv_trade.events; doc text; fid text; prev bigint; n bigint; done_qty bigint;
 sub bigint; tax bigint; paid_amt bigint; amt bigint:=0; pref text; rev text; result jsonb;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_bill IS NULL OR p_bill !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_action IS NULL OR p_action NOT IN ('bill','pay','reverse')
 OR p_confirm IS DISTINCT FROM true OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
 OR octet_length(p_payload::text)>4096 THEN RAISE EXCEPTION 'FIN_INPUT'; END IF;
 -- Same lock as fulfillment/cancellation; no settlement from uncommitted stock.
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO e FROM naruv_finance.events x WHERE x.org_id=a.org_id AND x.request_id=p_request;
 IF FOUND THEN
  IF (e.bill_id,e.actor_id,e.action,e.payload) IS DISTINCT FROM (p_bill,a.actor_id,p_action,p_payload)
  THEN RAISE EXCEPTION 'FIN_CONFLICT'; END IF;
  RETURN e.receipt;
 END IF;
 IF p_action='bill' THEN
  IF p_payload-'doc_id'-'fulfillment_id'<>'{}'::jsonb
  OR jsonb_typeof(p_payload->'doc_id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(p_payload->'fulfillment_id') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'FIN_INPUT'; END IF;
  doc:=p_payload->>'doc_id'; fid:=p_payload->>'fulfillment_id';
  SELECT * INTO d FROM naruv_trade.documents x WHERE x.org_id=a.org_id AND x.doc_id=doc FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'FIN_NOT_FOUND'; END IF;
  SELECT * INTO f FROM naruv_trade.events x WHERE x.org_id=a.org_id AND x.doc_id=doc AND x.request_id=fid AND x.action='fulfill';
  IF NOT FOUND THEN RAISE EXCEPTION 'FIN_NOT_FOUND'; END IF;
  -- Bind the actual inventory movement, not any client-supplied amount.
  SELECT m.quantity INTO n FROM naruv_inventory.movements m WHERE m.org_id=a.org_id AND m.request_id=f.movement_id
   AND m.source_id=d.source_id AND m.normalized_id=d.item_id
   AND m.from_warehouse IS NOT DISTINCT FROM (CASE WHEN d.kind='sale' THEN d.warehouse_id ELSE NULL END)
   AND m.to_warehouse IS NOT DISTINCT FROM (CASE WHEN d.kind='purchase' THEN d.warehouse_id ELSE NULL END);
  IF NOT FOUND OR n IS DISTINCT FROM (f.payload->>'quantity')::bigint THEN RAISE EXCEPTION 'FIN_INTEGRITY'; END IF;
  done_qty:=(f.receipt->>'fulfilled')::bigint;
  SELECT coalesce(sum(x.quantity),0)::bigint INTO prev FROM naruv_finance.bills x WHERE x.org_id=a.org_id AND x.doc_id=doc;
  IF done_qty IS NULL OR done_qty> d.fulfilled OR done_qty-n<>prev OR n<1 THEN RAISE EXCEPTION 'FIN_SEQUENCE'; END IF;
  sub:=n*d.unit_price;
  -- Cumulative half-up VAT delta, no penny drift across partial billings.
  tax:=CASE WHEN d.vat_mode='taxable' THEN (done_qty*d.unit_price+5)/10-(prev*d.unit_price+5)/10 ELSE 0 END;
  INSERT INTO naruv_finance.bills(org_id,bill_id,doc_id,fulfillment_id,kind,actor_id,quantity,subtotal,vat,created_at)
   VALUES(a.org_id,p_bill,doc,fid,d.kind,a.actor_id,n,sub,tax,clock_timestamp()) RETURNING * INTO b;
  paid_amt:=0;
 ELSE
  SELECT * INTO b FROM naruv_finance.bills x WHERE x.org_id=a.org_id AND x.bill_id=p_bill FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'FIN_NOT_FOUND'; END IF;
  paid_amt:=naruv_finance.paid(a.org_id,p_bill);
  IF paid_amt<0 OR paid_amt>b.total-naruv_finance.credit_sum(a.org_id,p_bill) THEN RAISE EXCEPTION 'FIN_INTEGRITY'; END IF;
  IF naruv_finance.returned_qty(a.org_id,p_bill)=b.quantity THEN RAISE EXCEPTION 'FIN_CONFLICT'; END IF;
  IF p_action='pay' THEN
   IF p_payload-'amount'-'reference'<>'{}'::jsonb
   OR jsonb_typeof(p_payload->'amount') IS DISTINCT FROM 'number' OR (p_payload->>'amount') !~ '^[0-9]{1,15}$'
   OR jsonb_typeof(p_payload->'reference') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'FIN_INPUT'; END IF;
   amt:=(p_payload->>'amount')::bigint; pref:=p_payload->>'reference';
   IF pref !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR amt<1 THEN RAISE EXCEPTION 'FIN_INPUT'; END IF;
   IF amt>b.total-paid_amt-naruv_finance.credit_sum(a.org_id,p_bill) THEN RAISE EXCEPTION 'FIN_OVERPAY'; END IF;
   paid_amt:=paid_amt+amt;
  ELSE
   IF p_payload-'payment_request_id'<>'{}'::jsonb OR jsonb_typeof(p_payload->'payment_request_id') IS DISTINCT FROM 'string'
   THEN RAISE EXCEPTION 'FIN_INPUT'; END IF;
   rev:=p_payload->>'payment_request_id';
   SELECT * INTO original FROM naruv_finance.events x WHERE x.org_id=a.org_id AND x.bill_id=p_bill AND x.request_id=rev AND x.action='pay';
   IF NOT FOUND THEN RAISE EXCEPTION 'FIN_NOT_FOUND'; END IF;
   IF EXISTS(SELECT 1 FROM naruv_finance.events x WHERE x.org_id=a.org_id AND x.reversal_of=rev) THEN RAISE EXCEPTION 'FIN_CONFLICT'; END IF;
   amt:=original.amount;
   IF amt>paid_amt THEN RAISE EXCEPTION 'FIN_INTEGRITY'; END IF;
   paid_amt:=paid_amt-amt;
  END IF;
 END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 result:=naruv_finance.adjusted_snapshot(b,paid_amt)||jsonb_build_object('request_id',p_request,'action',p_action,'amount',amt);
 INSERT INTO naruv_finance.events VALUES(a.org_id,p_request,p_bill,a.actor_id,p_action,p_payload,amt,pref,rev,result,clock_timestamp());
 RETURN result;
END $$;
CREATE FUNCTION naruv_finance.inspect(p_bill text,p_csrf text) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; b naruv_finance.bills; paid_amt bigint;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO b FROM naruv_finance.bills x WHERE x.org_id=a.org_id AND x.bill_id=p_bill;
 IF NOT FOUND THEN RAISE EXCEPTION 'FIN_NOT_FOUND'; END IF;
 paid_amt:=naruv_finance.paid(a.org_id,p_bill);
 RETURN naruv_finance.adjusted_snapshot(b,paid_amt);
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA naruv_finance FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_finance.command(text,text,text,jsonb,boolean,text),naruv_finance.inspect(text,text) TO jw_app_dev;
RESET ROLE;
