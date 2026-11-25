-- Disposable PG17 moving-average cost review. No statutory GL postings.
DO $$ BEGIN
 IF current_database()<>'postgres' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user<>'postgres' OR current_setting('naruv.valuation_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'COST_DISPOSABLE_ONLY'; END IF;
 IF EXISTS(SELECT 1 FROM naruv_inventory.movements) OR EXISTS(SELECT 1 FROM naruv_inventory.balances)
 THEN RAISE EXCEPTION 'COST_NONEMPTY_BASELINE'; END IF;
END $$;
CREATE SCHEMA naruv_valuation AUTHORIZATION naruv_native_owner;
REVOKE ALL ON SCHEMA naruv_valuation FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT USAGE ON SCHEMA naruv_valuation TO jw_app_dev;
SET ROLE naruv_native_owner;
CREATE TABLE naruv_valuation.balances(
 org_id text NOT NULL,source_id text NOT NULL,item_id text NOT NULL,warehouse_id text NOT NULL,
 quantity bigint NOT NULL CHECK(quantity BETWEEN 0 AND 1000000000000),
 value_krw numeric(24,0) NOT NULL CHECK(value_krw BETWEEN 0 AND 1000000000000000000000),
 PRIMARY KEY(org_id,source_id,item_id,warehouse_id),
 FOREIGN KEY(org_id,source_id,item_id,warehouse_id) REFERENCES naruv_inventory.balances,
 CHECK(quantity<>0 OR value_krw=0)
);
CREATE TABLE naruv_valuation.entries(
 org_id text NOT NULL,movement_id text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('opening','purchase','sale','transfer','adjustment_issue','material','output')),
 source_event_id text,amount_krw numeric(24,0) NOT NULL CHECK(amount_krw BETWEEN 0 AND 1000000000000000000000),
 from_value numeric(24,0),to_value numeric(24,0),
 PRIMARY KEY(org_id,movement_id),FOREIGN KEY(org_id,movement_id) REFERENCES naruv_inventory.movements,
 CHECK(from_value BETWEEN 0 AND 1000000000000000000000),CHECK(to_value BETWEEN 0 AND 1000000000000000000000),
 CHECK((kind IN ('purchase','sale','material','output'))=(source_event_id IS NOT NULL))
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['balances','entries'] LOOP
  EXECUTE format('ALTER TABLE naruv_valuation.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE naruv_valuation.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY valuation_scope ON naruv_valuation.%I TO naruv_native_owner USING (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin'')) WITH CHECK (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin''))',t);
  EXECUTE format('REVOKE ALL ON naruv_valuation.%I FROM PUBLIC,jw_app_dev,naruv_native_stage',t);
 END LOOP;
END $$;
CREATE TRIGGER cost_entries_immutable BEFORE UPDATE OR DELETE ON naruv_valuation.entries
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE FUNCTION naruv_valuation.apply(p_org text,p_mid text,p_kind text,p_event text,p_incoming numeric)
 RETURNS numeric LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
DECLARE m naruv_inventory.movements; b naruv_valuation.balances; amount numeric; fv numeric; tv numeric;
BEGIN
 SELECT * INTO m FROM naruv_inventory.movements z WHERE z.org_id=p_org AND z.request_id=p_mid;
 IF NOT FOUND THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 IF (p_kind IN ('opening','purchase','output') AND (m.from_warehouse IS NOT NULL OR m.to_warehouse IS NULL OR p_incoming IS NULL))
 OR (p_kind IN ('sale','material','adjustment_issue') AND (m.from_warehouse IS NULL OR m.to_warehouse IS NOT NULL OR p_incoming IS NOT NULL))
 OR (p_kind='transfer' AND (m.from_warehouse IS NULL OR m.to_warehouse IS NULL OR p_incoming IS NOT NULL))
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 amount:=p_incoming;
 IF m.from_warehouse IS NOT NULL THEN
  SELECT * INTO b FROM naruv_valuation.balances z WHERE (z.org_id,z.source_id,z.item_id,z.warehouse_id)=(p_org,m.source_id,m.normalized_id,m.from_warehouse) FOR UPDATE;
  IF NOT FOUND OR b.quantity<>m.from_after+m.quantity THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  -- Whole KRW moving-average amount, final issue drains the exact remainder.
  amount:=CASE WHEN b.quantity=m.quantity THEN b.value_krw ELSE div(2*b.value_krw*m.quantity+b.quantity,2*b.quantity) END;
  fv:=b.value_krw-amount;
  UPDATE naruv_valuation.balances z SET quantity=m.from_after,value_krw=fv
   WHERE (z.org_id,z.source_id,z.item_id,z.warehouse_id)=(p_org,m.source_id,m.normalized_id,m.from_warehouse);
 END IF;
 IF amount IS NULL OR amount<0 OR amount<>trunc(amount) OR amount>1000000000000000000000 THEN RAISE EXCEPTION 'COST_CAPACITY'; END IF;
 IF m.to_warehouse IS NOT NULL THEN
  INSERT INTO naruv_valuation.balances VALUES(p_org,m.source_id,m.normalized_id,m.to_warehouse,0,0) ON CONFLICT DO NOTHING;
  SELECT * INTO STRICT b FROM naruv_valuation.balances z WHERE (z.org_id,z.source_id,z.item_id,z.warehouse_id)=(p_org,m.source_id,m.normalized_id,m.to_warehouse) FOR UPDATE;
  IF b.quantity<>m.to_after-m.quantity THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  tv:=b.value_krw+amount;
  IF tv>1000000000000000000000 THEN RAISE EXCEPTION 'COST_CAPACITY'; END IF;
  UPDATE naruv_valuation.balances z SET quantity=m.to_after,value_krw=tv
   WHERE (z.org_id,z.source_id,z.item_id,z.warehouse_id)=(p_org,m.source_id,m.normalized_id,m.to_warehouse);
 END IF;
 INSERT INTO naruv_valuation.entries VALUES(p_org,p_mid,p_kind,p_event,amount,fv,tv);
 RETURN amount;
END $$;
CREATE FUNCTION naruv_valuation.check_movement() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE wh text; e naruv_valuation.entries;
BEGIN
 SELECT * INTO e FROM naruv_valuation.entries z WHERE z.org_id=NEW.org_id AND z.movement_id=NEW.request_id;
 IF NOT FOUND OR (e.from_value IS NULL)<>(NEW.from_warehouse IS NULL) OR (e.to_value IS NULL)<>(NEW.to_warehouse IS NULL)
 THEN RAISE EXCEPTION 'COST_UNPOSTED'; END IF;
 FOR wh IN SELECT x FROM unnest(ARRAY[NEW.from_warehouse,NEW.to_warehouse]) x WHERE x IS NOT NULL LOOP
  IF NOT EXISTS(SELECT 1 FROM naruv_inventory.balances b JOIN naruv_valuation.balances v
   ON (b.org_id,b.source_id,b.normalized_id,b.warehouse_id)=(v.org_id,v.source_id,v.item_id,v.warehouse_id)
   WHERE (b.org_id,b.source_id,b.normalized_id,b.warehouse_id)=(NEW.org_id,NEW.source_id,NEW.normalized_id,wh)
   AND b.quantity=v.quantity) THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 END LOOP;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER valuation_required AFTER INSERT ON naruv_inventory.movements
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION naruv_valuation.check_movement();
CREATE FUNCTION naruv_valuation.trade_post() RETURNS trigger LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
DECLARE d naruv_trade.documents; m naruv_inventory.movements;
BEGIN
 IF NEW.action<>'fulfill' THEN RETURN NEW; END IF;
 SELECT * INTO STRICT d FROM naruv_trade.documents z WHERE z.org_id=NEW.org_id AND z.doc_id=NEW.doc_id;
 SELECT * INTO STRICT m FROM naruv_inventory.movements z WHERE z.org_id=NEW.org_id AND z.request_id=NEW.movement_id;
 IF (m.source_id,m.normalized_id,m.actor_id,m.quantity) IS DISTINCT FROM (d.source_id,d.item_id,NEW.actor_id,(NEW.payload->>'quantity')::bigint)
 OR m.from_warehouse IS DISTINCT FROM (CASE WHEN d.kind='sale' THEN d.warehouse_id ELSE NULL END)
 OR m.to_warehouse IS DISTINCT FROM (CASE WHEN d.kind='purchase' THEN d.warehouse_id ELSE NULL END)
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 PERFORM naruv_valuation.apply(NEW.org_id,m.request_id,d.kind,NEW.request_id,
  CASE WHEN d.kind='purchase' THEN m.quantity::numeric*d.unit_price ELSE NULL END);
 RETURN NEW;
END $$;
CREATE TRIGGER valuation_trade AFTER INSERT ON naruv_trade.events FOR EACH ROW EXECUTE FUNCTION naruv_valuation.trade_post();
CREATE FUNCTION naruv_valuation.production_post() RETURNS trigger LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
DECLARE o naruv_production.orders; b naruv_production.boms; c naruv_production.components; m naruv_inventory.movements;
 mid text; amount numeric:=0; q bigint;
BEGIN
 IF NEW.action<>'complete' THEN RETURN NEW; END IF;
 SELECT * INTO STRICT o FROM naruv_production.orders z WHERE z.org_id=NEW.org_id AND z.order_id=NEW.order_id;
 SELECT * INTO STRICT b FROM naruv_production.boms z WHERE z.org_id=NEW.org_id AND z.bom_id=o.bom_id;
 q:=(NEW.payload->>'quantity')::bigint;
 FOR c IN SELECT * FROM naruv_production.components z WHERE z.org_id=NEW.org_id AND z.bom_id=o.bom_id ORDER BY z.material_id LOOP
  mid:='doc:'||encode(sha256(convert_to(jsonb_build_array('production',NEW.request_id,'material',c.material_id)::text,'UTF8')),'hex');
  SELECT * INTO STRICT m FROM naruv_inventory.movements z WHERE z.org_id=NEW.org_id AND z.request_id=mid;
  IF (m.source_id,m.normalized_id,m.actor_id,m.quantity,m.from_warehouse,m.to_warehouse)
   IS DISTINCT FROM (c.source_id,c.material_id,NEW.actor_id,c.per_unit*q,o.warehouse_id,NULL::text)
  THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
  amount:=amount+naruv_valuation.apply(NEW.org_id,mid,'material',NEW.request_id,NULL);
 END LOOP;
 mid:='doc:'||encode(sha256(convert_to(jsonb_build_array('production',NEW.request_id,'output',b.product_id)::text,'UTF8')),'hex');
 SELECT * INTO STRICT m FROM naruv_inventory.movements z WHERE z.org_id=NEW.org_id AND z.request_id=mid;
 IF (m.source_id,m.normalized_id,m.actor_id,m.quantity,m.from_warehouse,m.to_warehouse)
  IS DISTINCT FROM (b.source_id,b.product_id,NEW.actor_id,q,NULL::text,o.warehouse_id)
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 PERFORM naruv_valuation.apply(NEW.org_id,mid,'output',NEW.request_id,amount);
 RETURN NEW;
END $$;
CREATE TRIGGER valuation_production AFTER INSERT ON naruv_production.events FOR EACH ROW EXECUTE FUNCTION naruv_valuation.production_post();
-- Ordinary transfers/issues still work. Unpriced external receipts fail closed.
CREATE OR REPLACE FUNCTION naruv_inventory.post_movement(p_source text,p_item text,p_request text,p_from text,p_to text,p_qty bigint,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; r jsonb;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF left(p_request,4)='doc:' OR p_from IS NULL THEN RAISE EXCEPTION 'INV_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 r:=naruv_inventory.post_movement_internal(p_source,p_item,p_request,p_from,p_to,p_qty,p_csrf);
 IF NOT EXISTS(SELECT 1 FROM naruv_valuation.entries z WHERE z.org_id=a.org_id AND z.movement_id=p_request) THEN
  PERFORM naruv_valuation.apply(a.org_id,p_request,CASE WHEN p_to IS NULL THEN 'adjustment_issue' ELSE 'transfer' END,NULL,NULL);
 END IF;
 RETURN r;
END $$;
CREATE FUNCTION naruv_valuation.receive(p_item text,p_request text,p_payload jsonb,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; m naruv_inventory.movements; e naruv_valuation.entries; r jsonb; src text; wh text; mid text; q bigint; price numeric; amount numeric;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF NOT naruv_production.ident(p_item) OR NOT naruv_production.ident(p_request)
 OR p_confirm IS DISTINCT FROM true OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
 OR p_payload-'source_id'-'warehouse_id'-'quantity'-'unit_cost'<>'{}'::jsonb
 OR jsonb_typeof(p_payload->'source_id') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p_payload->'warehouse_id') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p_payload->'unit_cost') IS DISTINCT FROM 'number' OR (p_payload->>'unit_cost') !~ '^[0-9]{1,10}$'
 THEN RAISE EXCEPTION 'COST_INPUT'; END IF;
 src:=p_payload->>'source_id';wh:=p_payload->>'warehouse_id';
 IF jsonb_typeof(p_payload->'quantity') IS DISTINCT FROM 'number' OR (p_payload->>'quantity') !~ '^[0-9]{1,10}$' THEN RAISE EXCEPTION 'COST_INPUT'; END IF;
 q:=(p_payload->>'quantity')::bigint;
 IF q NOT BETWEEN 1 AND 1000000000 THEN RAISE EXCEPTION 'COST_INPUT'; END IF;
 price:=(p_payload->>'unit_cost')::numeric;
 IF NOT naruv_production.ident(src) OR NOT naruv_production.ident(wh) OR price>1000000000 THEN RAISE EXCEPTION 'COST_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 mid:='doc:'||encode(sha256(convert_to(jsonb_build_array('cost-opening',p_request)::text,'UTF8')),'hex');
 SELECT * INTO e FROM naruv_valuation.entries z WHERE z.org_id=a.org_id AND z.movement_id=mid;
 IF FOUND THEN
  SELECT * INTO STRICT m FROM naruv_inventory.movements z WHERE z.org_id=a.org_id AND z.request_id=mid;
  IF (m.actor_id,m.source_id,m.normalized_id,m.to_warehouse,m.quantity,e.kind,e.amount_krw)
   IS DISTINCT FROM (a.actor_id,src,lower(p_item COLLATE "C"),wh,q,'opening'::text,q*price)
  THEN RAISE EXCEPTION 'COST_CONFLICT'; END IF;
  r:=naruv_inventory.receipt(m);amount:=e.amount_krw;
 ELSE
  r:=naruv_inventory.post_movement_internal(src,p_item,mid,NULL,wh,q,p_csrf);
  amount:=naruv_valuation.apply(a.org_id,mid,'opening',NULL,q*price);
 END IF;
 RETURN r||jsonb_build_object('cost_krw',amount::text,'opening_request_id',p_request);
END $$;
CREATE FUNCTION naruv_valuation.inspect(p_src text,p_item text,p_wh text,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; r jsonb; v naruv_valuation.balances; q bigint;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 r:=naruv_inventory.read_stock(p_src,p_item,p_wh,p_csrf);q:=(r->>'quantity')::bigint;
 SELECT * INTO v FROM naruv_valuation.balances z WHERE (z.org_id,z.source_id,z.item_id,z.warehouse_id)=(a.org_id,p_src,lower(p_item COLLATE "C"),p_wh);
 IF q<>coalesce(v.quantity,0) THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 RETURN r||jsonb_build_object('value_krw',coalesce(v.value_krw,0)::text,'method','WAREHOUSE_MOVING_AVERAGE','statutory_posted',false);
END $$;
-- Read-only reconciliation: no GL posting, no client-supplied amounts.
CREATE FUNCTION naruv_valuation.reconcile_bill(p_bill text,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; b naruv_finance.bills; f naruv_trade.events;
 d naruv_trade.documents; m naruv_inventory.movements; e naruv_valuation.entries;
 j jsonb; clearing numeric; sales numeric;
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
 j:=naruv_accounting.inspect_bill(p_bill,p_csrf);
 SELECT coalesce(sum(l.debit::numeric-l.credit) FILTER(WHERE l.account='PURCHASE_CLEARING'),0),
 coalesce(sum(l.credit::numeric-l.debit) FILTER(WHERE l.account='SALES'),0)
 INTO clearing,sales FROM naruv_accounting.lines l JOIN naruv_accounting.journals h USING(org_id,event_id)
 WHERE h.org_id=a.org_id AND h.bill_id=p_bill;
 IF clearing<>(CASE WHEN b.kind='purchase' THEN b.subtotal ELSE 0 END)
 OR sales<>(CASE WHEN b.kind='sale' THEN b.subtotal ELSE 0 END)
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 RETURN jsonb_build_object('bill_id',p_bill,'fulfillment_id',b.fulfillment_id,'kind',b.kind,
 'net_krw',b.subtotal::text,'inventory_cost_krw',e.amount_krw::text,
 'purchase_clearing_difference_krw',CASE WHEN b.kind='purchase' THEN (clearing-e.amount_krw)::text ELSE NULL END,
 'sales_margin_krw',CASE WHEN b.kind='sale' THEN (sales-e.amount_krw)::text ELSE NULL END,
 'outstanding_krw',j->>'outstanding','statutory_posted',false,'production_authorized',false);
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA naruv_valuation FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_valuation.receive(text,text,jsonb,boolean,text),naruv_valuation.inspect(text,text,text,text),naruv_valuation.reconcile_bill(text,text) TO jw_app_dev;
RESET ROLE;
