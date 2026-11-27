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
 kind text NOT NULL CHECK(kind IN ('opening','purchase','sale','transfer','adjustment_issue','material','output','sale_return','purchase_return')),
 source_event_id text,amount_krw numeric(24,0) NOT NULL CHECK(amount_krw BETWEEN 0 AND 1000000000000000000000),
 from_value numeric(24,0),to_value numeric(24,0),
 PRIMARY KEY(org_id,movement_id),FOREIGN KEY(org_id,movement_id) REFERENCES naruv_inventory.movements,
 CHECK(from_value BETWEEN 0 AND 1000000000000000000000),CHECK(to_value BETWEEN 0 AND 1000000000000000000000),
 CHECK((kind IN ('purchase','sale','material','output','sale_return','purchase_return'))=(source_event_id IS NOT NULL))
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
-- Internal double-entry cost journal; each nonzero posting is one balanced pair.
CREATE TABLE naruv_valuation.cost_journals(
 org_id text NOT NULL,movement_id text NOT NULL,period_start date NOT NULL,
 debit_account text,credit_account text,amount_krw numeric(24,0) NOT NULL
 CHECK(amount_krw BETWEEN 0 AND 1000000000000000000000),
 PRIMARY KEY(org_id,movement_id),FOREIGN KEY(org_id,movement_id) REFERENCES naruv_valuation.entries,
 FOREIGN KEY(org_id,period_start) REFERENCES naruv_accounting.periods,
 CHECK((amount_krw=0 AND debit_account IS NULL AND credit_account IS NULL)
 OR (amount_krw>0 AND debit_account IS NOT NULL AND credit_account IS NOT NULL AND debit_account<>credit_account)),
 CHECK(debit_account IN ('INVENTORY','COGS','WIP','ADJUSTMENT_EXPENSE','PURCHASE_CLEARING')),
 CHECK(credit_account IN ('INVENTORY','PURCHASE_CLEARING','WIP','OPENING_EQUITY','COGS'))
);
ALTER TABLE naruv_valuation.cost_journals ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_valuation.cost_journals FORCE ROW LEVEL SECURITY;
CREATE POLICY valuation_scope ON naruv_valuation.cost_journals TO naruv_native_owner
 USING (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))
 WITH CHECK (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
REVOKE ALL ON naruv_valuation.cost_journals FROM PUBLIC,jw_app_dev,naruv_native_stage;
CREATE TRIGGER cost_journals_immutable BEFORE UPDATE OR DELETE ON naruv_valuation.cost_journals
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE FUNCTION naruv_valuation.expected_posting(p_kind text,p_amount numeric,
 OUT dr text,OUT cr text,OUT amount numeric)
 LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
BEGIN
 amount:=CASE WHEN p_kind='transfer' THEN 0 ELSE p_amount END;
 IF amount=0 THEN RETURN; END IF;
 dr:=CASE p_kind WHEN 'opening' THEN 'INVENTORY' WHEN 'purchase' THEN 'INVENTORY'
 WHEN 'sale' THEN 'COGS' WHEN 'adjustment_issue' THEN 'ADJUSTMENT_EXPENSE'
 WHEN 'material' THEN 'WIP' WHEN 'output' THEN 'INVENTORY' WHEN 'sale_return' THEN 'INVENTORY' WHEN 'purchase_return' THEN 'PURCHASE_CLEARING' END;
 cr:=CASE p_kind WHEN 'opening' THEN 'OPENING_EQUITY' WHEN 'purchase' THEN 'PURCHASE_CLEARING'
 WHEN 'sale' THEN 'INVENTORY' WHEN 'adjustment_issue' THEN 'INVENTORY'
 WHEN 'material' THEN 'INVENTORY' WHEN 'output' THEN 'WIP' WHEN 'sale_return' THEN 'COGS' WHEN 'purchase_return' THEN 'INVENTORY' END;
 IF dr IS NULL OR cr IS NULL THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
END $$;
CREATE FUNCTION naruv_valuation.post_cost_journal() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
DECLARE m naruv_inventory.movements; p naruv_accounting.periods; mon date; expected record;
BEGIN
 SELECT * INTO STRICT m FROM naruv_inventory.movements z WHERE z.org_id=NEW.org_id AND z.request_id=NEW.movement_id;
 mon:=date_trunc('month',m.created_at AT TIME ZONE 'Asia/Seoul')::date;
 SELECT * INTO p FROM naruv_accounting.periods z WHERE z.org_id=NEW.org_id AND z.period_start=mon FOR UPDATE;
 IF NOT FOUND OR p.closed_at IS NOT NULL THEN RAISE EXCEPTION 'COST_PERIOD_CLOSED'; END IF;
 SELECT * INTO expected FROM naruv_valuation.expected_posting(NEW.kind,NEW.amount_krw);
 INSERT INTO naruv_valuation.cost_journals VALUES(NEW.org_id,NEW.movement_id,mon,expected.dr,expected.cr,expected.amount);
 RETURN NEW;
END $$;
CREATE TRIGGER cost_journal_post AFTER INSERT ON naruv_valuation.entries
 FOR EACH ROW EXECUTE FUNCTION naruv_valuation.post_cost_journal();
CREATE FUNCTION naruv_valuation.validate_cost_journal() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE e naruv_valuation.entries; j naruv_valuation.cost_journals; m naruv_inventory.movements; expected record;
BEGIN
 SELECT * INTO STRICT e FROM naruv_valuation.entries z WHERE z.org_id=NEW.org_id AND z.movement_id=NEW.movement_id;
 SELECT * INTO j FROM naruv_valuation.cost_journals z WHERE z.org_id=NEW.org_id AND z.movement_id=NEW.movement_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'COST_JOURNAL_MISSING'; END IF;
 SELECT * INTO STRICT m FROM naruv_inventory.movements z WHERE z.org_id=e.org_id AND z.request_id=e.movement_id;
 SELECT * INTO expected FROM naruv_valuation.expected_posting(e.kind,e.amount_krw);
 IF (j.debit_account,j.credit_account,j.amount_krw,j.period_start) IS DISTINCT FROM
 (expected.dr,expected.cr,expected.amount,date_trunc('month',m.created_at AT TIME ZONE 'Asia/Seoul')::date)
 THEN RAISE EXCEPTION 'COST_JOURNAL_MISMATCH'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER cost_entry_journal_required AFTER INSERT ON naruv_valuation.entries
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION naruv_valuation.validate_cost_journal();
CREATE CONSTRAINT TRIGGER cost_journal_check AFTER INSERT ON naruv_valuation.cost_journals
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION naruv_valuation.validate_cost_journal();
CREATE FUNCTION naruv_valuation.apply(p_org text,p_mid text,p_kind text,p_event text,p_incoming numeric)
 RETURNS numeric LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
DECLARE m naruv_inventory.movements; b naruv_valuation.balances; amount numeric; fv numeric; tv numeric;
BEGIN
 SELECT * INTO m FROM naruv_inventory.movements z WHERE z.org_id=p_org AND z.request_id=p_mid;
 IF NOT FOUND THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 IF (p_kind IN ('opening','purchase','output','sale_return') AND (m.from_warehouse IS NOT NULL OR m.to_warehouse IS NULL OR p_incoming IS NULL))
 OR (p_kind IN ('sale','material','adjustment_issue','purchase_return') AND (m.from_warehouse IS NULL OR m.to_warehouse IS NOT NULL OR p_incoming IS NOT NULL))
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
-- Original billed fulfillment return: legacy exact-cost/no-refund or explicit adjusted review.
CREATE FUNCTION naruv_valuation.return_adjusted(p_bill text,p_request text,p_qty bigint,p_advanced boolean,p_ref text,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; b naruv_finance.bills; f naruv_trade.events; m naruv_inventory.movements;
 e naruv_valuation.entries; prior naruv_finance.events; mid text; amt numeric; r jsonb; q bigint; prev bigint; net bigint; tax bigint; cost numeric; paid bigint; credit bigint; refund bigint; refund_id text; variance numeric;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF NOT naruv_production.ident(p_bill) OR NOT naruv_production.ident(p_request) OR p_confirm IS DISTINCT FROM true OR (p_qty IS NOT NULL AND p_qty NOT BETWEEN 1 AND 100000)
 OR p_advanced IS NULL OR (p_ref IS NOT NULL AND NOT naruv_production.ident(p_ref))
 THEN RAISE EXCEPTION 'COST_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM
 (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO prior FROM naruv_finance.events z WHERE z.org_id=a.org_id AND z.request_id=p_request;
 IF FOUND THEN
  IF (prior.action,prior.bill_id,prior.actor_id,(prior.payload->>'requested_quantity')::bigint,coalesce((prior.payload->>'advanced')::boolean,false),prior.payload->>'refund_reference') IS DISTINCT FROM ('credit'::text,p_bill,a.actor_id,p_qty,p_advanced,p_ref)
  THEN RAISE EXCEPTION 'COST_CONFLICT'; END IF;
  RETURN prior.receipt;
 END IF;
 SELECT * INTO b FROM naruv_finance.bills z WHERE z.org_id=a.org_id AND z.bill_id=p_bill FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'INV_NOT_FOUND'; END IF;
 prev:=naruv_finance.returned_qty(a.org_id,p_bill);q:=coalesce(p_qty,b.quantity);
 paid:=naruv_finance.paid(a.org_id,p_bill);credit:=naruv_finance.credit_sum(a.org_id,p_bill);
 IF q<1 OR prev+q>b.quantity THEN RAISE EXCEPTION 'COST_RETURN_CONFLICT'; END IF;
 net:=naruv_finance.allocation(b.subtotal,b.quantity,prev,q)::bigint;
 tax:=naruv_finance.allocation(b.vat,b.quantity,prev,q)::bigint;
 refund:=greatest(0,paid+credit+net+tax-b.total);
 IF (refund>0 AND (NOT p_advanced OR p_ref IS NULL)) OR (refund=0 AND p_ref IS NOT NULL)
 THEN RAISE EXCEPTION 'COST_RETURN_CONFLICT'; END IF;
 PERFORM naruv_valuation.reconcile_bill(p_bill,p_csrf);
 SELECT * INTO STRICT f FROM naruv_trade.events z WHERE z.org_id=a.org_id AND z.request_id=b.fulfillment_id;
 SELECT * INTO STRICT m FROM naruv_inventory.movements z WHERE z.org_id=a.org_id AND z.request_id=f.movement_id;
 SELECT * INTO STRICT e FROM naruv_valuation.entries z WHERE z.org_id=a.org_id AND z.movement_id=m.request_id;
 mid:='doc:'||encode(sha256(convert_to(jsonb_build_array('cost-return',p_request)::text,'UTF8')),'hex');
 cost:=naruv_finance.allocation(e.amount_krw,b.quantity,prev,q);
 PERFORM naruv_inventory.post_movement_internal(m.source_id,m.normalized_id,mid,m.to_warehouse,m.from_warehouse,q,p_csrf);
 amt:=naruv_valuation.apply(a.org_id,mid,b.kind||'_return',p_request,CASE WHEN b.kind='sale' THEN cost ELSE NULL END);
 variance:=cost-amt;
 IF variance<>0 AND (NOT p_advanced OR b.kind<>'purchase' OR abs(variance)>110000000000000)
 THEN RAISE EXCEPTION 'COST_RETURN_CONFLICT'; END IF;
 IF refund>0 THEN
  refund_id:='refund:'||encode(sha256(convert_to(jsonb_build_array(p_request)::text,'UTF8')),'hex');
  IF refund_id=p_request OR EXISTS(SELECT 1 FROM naruv_finance.events z WHERE z.org_id=a.org_id AND (z.request_id=refund_id OR z.payment_ref=p_ref))
  THEN RAISE EXCEPTION 'COST_CONFLICT'; END IF;
  INSERT INTO naruv_finance.events VALUES(a.org_id,refund_id,p_bill,a.actor_id,'refund',
    jsonb_build_object('credit_request_id',p_request,'reference',p_ref),refund,p_ref,NULL,
    jsonb_build_object('amount',refund,'production_authorized',false,'external_transfer_executed',false),clock_timestamp());
  paid:=paid-refund;
 END IF;
 r:=naruv_finance.snapshot(b,paid)||jsonb_build_object('credited',credit+net+tax,'outstanding',b.total-paid-credit-net-tax,
 'state',CASE WHEN prev+q=b.quantity THEN 'CREDITED' WHEN b.total-paid-credit-net-tax=0 THEN 'SETTLED' WHEN paid=0 THEN 'OPEN' ELSE 'PARTIAL' END,
 'request_id',p_request,'movement_id',mid,'returned_quantity',q,'cumulative_returned_quantity',prev+q,'returned_cost_krw',amt::text,'refund_recorded_krw',refund::text,'purchase_cost_variance_krw',variance::text,'external_transfer_executed',false,'statutory_posted',false);
 INSERT INTO naruv_finance.events VALUES(a.org_id,p_request,p_bill,a.actor_id,'credit',
 jsonb_build_object('movement_id',mid,'requested_quantity',p_qty,'prior_quantity',prev,'quantity',q,'net',net,'vat',tax,'variance',variance,'advanced',p_advanced,'refund_reference',p_ref,'refund_id',refund_id,'refund_amount',refund),
 net+tax,NULL,NULL,r,clock_timestamp());
 PERFORM naruv_valuation.reconcile_bill(p_bill,p_csrf);
 RETURN r;
END $$;
CREATE FUNCTION naruv_valuation.return_quantity(p_bill text,p_request text,p_qty bigint,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT naruv_valuation.return_adjusted(p_bill,p_request,p_qty,false,NULL::text,p_confirm,p_csrf)
$$;
CREATE FUNCTION naruv_valuation.return_bill(p_bill text,p_request text,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT naruv_valuation.return_quantity(p_bill,p_request,NULL::bigint,p_confirm,p_csrf)
$$;
-- Whole-tenant current-state audit. Bounded synchronous review, never a repair.
CREATE FUNCTION naruv_valuation.audit_ledger(p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; n bigint; bill record; stock_value numeric; journal_value numeric; wip numeric;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM
 (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT count(*) INTO n FROM naruv_finance.bills b WHERE b.org_id=a.org_id;
 IF n>1000 THEN RAISE EXCEPTION 'COST_CAPACITY'; END IF;
 IF EXISTS(SELECT 1 FROM naruv_inventory.balances b LEFT JOIN naruv_valuation.balances v
 ON (b.org_id,b.source_id,b.normalized_id,b.warehouse_id)=(v.org_id,v.source_id,v.item_id,v.warehouse_id)
 WHERE b.org_id=a.org_id AND b.quantity<>coalesce(v.quantity,0))
 OR EXISTS(SELECT 1 FROM naruv_inventory.movements m LEFT JOIN naruv_valuation.entries e
 ON (m.org_id,m.request_id)=(e.org_id,e.movement_id)
 LEFT JOIN naruv_valuation.cost_journals j ON (e.org_id,e.movement_id)=(j.org_id,j.movement_id)
 WHERE m.org_id=a.org_id AND (e.movement_id IS NULL OR j.movement_id IS NULL))
 OR EXISTS(SELECT 1 FROM naruv_valuation.entries e JOIN naruv_valuation.cost_journals j USING(org_id,movement_id)
 JOIN naruv_inventory.movements m ON (m.org_id,m.request_id)=(e.org_id,e.movement_id)
 CROSS JOIN LATERAL naruv_valuation.expected_posting(e.kind,e.amount_krw) x
 WHERE e.org_id=a.org_id AND (j.debit_account,j.credit_account,j.amount_krw,j.period_start)
 IS DISTINCT FROM (x.dr,x.cr,x.amount,date_trunc('month',m.created_at AT TIME ZONE 'Asia/Seoul')::date))
 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 -- Rebuild signed quantities and cost per warehouse from immutable movements.
 IF EXISTS(
  WITH signed AS (
   SELECT m.source_id,m.normalized_id,m.from_warehouse AS wh,-m.quantity::numeric AS q,-e.amount_krw AS v
    FROM naruv_inventory.movements m JOIN naruv_valuation.entries e ON (m.org_id,m.request_id)=(e.org_id,e.movement_id)
    WHERE m.org_id=a.org_id AND m.from_warehouse IS NOT NULL
   UNION ALL
   SELECT m.source_id,m.normalized_id,m.to_warehouse,m.quantity::numeric,e.amount_krw
    FROM naruv_inventory.movements m JOIN naruv_valuation.entries e ON (m.org_id,m.request_id)=(e.org_id,e.movement_id)
    WHERE m.org_id=a.org_id AND m.to_warehouse IS NOT NULL
  ), totals AS (SELECT source_id,normalized_id,wh,sum(q) AS q,sum(v) AS v FROM signed GROUP BY source_id,normalized_id,wh),
  balances AS (SELECT source_id,item_id,warehouse_id,quantity,value_krw FROM naruv_valuation.balances WHERE org_id=a.org_id)
  SELECT 1 FROM totals t FULL JOIN balances b ON (t.source_id,t.normalized_id,t.wh)=(b.source_id,b.item_id,b.warehouse_id)
  WHERE t.wh IS NULL OR b.warehouse_id IS NULL OR (t.q,t.v) IS DISTINCT FROM (b.quantity::numeric,b.value_krw)
 ) THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 SELECT coalesce(sum(value_krw),0) INTO stock_value FROM naruv_valuation.balances WHERE org_id=a.org_id;
 SELECT coalesce(sum(CASE WHEN debit_account='INVENTORY' THEN amount_krw WHEN credit_account='INVENTORY' THEN -amount_krw ELSE 0 END),0),
 coalesce(sum(CASE WHEN debit_account='WIP' THEN amount_krw WHEN credit_account='WIP' THEN -amount_krw ELSE 0 END),0)
 INTO journal_value,wip FROM naruv_valuation.cost_journals WHERE org_id=a.org_id;
 IF stock_value<>journal_value OR wip<>0 THEN RAISE EXCEPTION 'COST_INTEGRITY'; END IF;
 FOR bill IN SELECT bill_id FROM naruv_finance.bills WHERE org_id=a.org_id ORDER BY bill_id LOOP
  PERFORM naruv_valuation.reconcile_bill(bill.bill_id,p_csrf);
 END LOOP;
 RETURN jsonb_build_object('inventory_krw',stock_value::text,'journal_inventory_krw',journal_value::text,
 'wip_krw',wip::text,'bill_count',n,'status','RECONCILED','production_authorized',false,'statutory_posted',false);
END $$;
-- Read-only dashboard contract. Strict tenant identity; no client filters or writes.
CREATE FUNCTION naruv_valuation.overview(p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; proof jsonb; due_sale numeric; due_purchase numeric; paid_sale numeric; paid_purchase numeric; n_sale bigint; n_purchase bigint; n_open bigint; n_products bigint; n_wh bigint;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM
 (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 proof:=naruv_valuation.audit_ledger(p_csrf);
 SELECT count(*) FILTER(WHERE b.kind='sale'),count(*) FILTER(WHERE b.kind='purchase'),
 coalesce(sum(b.total-naruv_finance.paid(b.org_id,b.bill_id)-naruv_finance.credit_sum(b.org_id,b.bill_id)) FILTER(WHERE b.kind='sale'),0),
 coalesce(sum(b.total-naruv_finance.paid(b.org_id,b.bill_id)-naruv_finance.credit_sum(b.org_id,b.bill_id)) FILTER(WHERE b.kind='purchase'),0),
 coalesce(sum(naruv_finance.paid(b.org_id,b.bill_id)) FILTER(WHERE b.kind='sale'),0),
 coalesce(sum(naruv_finance.paid(b.org_id,b.bill_id)) FILTER(WHERE b.kind='purchase'),0)
 INTO n_sale,n_purchase,due_sale,due_purchase,paid_sale,paid_purchase
 FROM naruv_finance.bills b WHERE b.org_id=a.org_id;
 SELECT count(*) INTO n_open FROM naruv_trade.documents d WHERE d.org_id=a.org_id AND d.state IN ('OPEN','PARTIAL');
 SELECT count(*) INTO n_products FROM naruv_inventory.items i WHERE i.org_id=a.org_id;
 SELECT count(*) INTO n_wh FROM naruv_inventory.warehouses w WHERE w.org_id=a.org_id AND w.active;
 RETURN proof||jsonb_build_object('sales_bill_count',n_sale,'purchase_bill_count',n_purchase,
 'receivable_krw',due_sale::text,'payable_krw',due_purchase::text,'sale_paid_krw',paid_sale::text,'purchase_paid_krw',paid_purchase::text,
 'open_trade_count',n_open,'item_count',n_products,'active_warehouse_count',n_wh,'scope','ISOLATED_SYNTHETIC_ONLY');
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA naruv_valuation FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_valuation.receive(text,text,jsonb,boolean,text),naruv_valuation.inspect(text,text,text,text),naruv_valuation.reconcile_bill(text,text),naruv_valuation.return_bill(text,text,boolean,text),naruv_valuation.return_quantity(text,text,bigint,boolean,text),naruv_valuation.return_adjusted(text,text,bigint,boolean,text,boolean,text),naruv_valuation.audit_ledger(text),naruv_valuation.overview(text) TO jw_app_dev;
RESET ROLE;
