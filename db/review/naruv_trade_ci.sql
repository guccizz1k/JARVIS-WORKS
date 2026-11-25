-- Disposable PG17 trade-document proof; no persistent DB migration.
DO $$ BEGIN
 IF current_database()<>'postgres' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user<>'postgres' OR current_setting('naruv.trade_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'NARUV_TRADE_DISPOSABLE_ONLY'; END IF;
END $$;
GRANT SELECT ON jw_dev.customers,jw_dev.quotes,jw_dev.quote_items TO naruv_native_owner;
GRANT REFERENCES(id) ON jw_dev.quotes TO naruv_native_owner;
CREATE POLICY naruv_trade_quote_read ON jw_dev.quotes FOR SELECT TO naruv_native_owner
 USING(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
CREATE POLICY naruv_trade_quote_item_read ON jw_dev.quote_items FOR SELECT TO naruv_native_owner
 USING(EXISTS(SELECT 1 FROM jw_dev.quotes q WHERE q.id=quote_id AND q.org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin')));
CREATE POLICY naruv_trade_customer_read ON jw_dev.customers FOR SELECT TO naruv_native_owner
 USING(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
CREATE SCHEMA naruv_trade AUTHORIZATION naruv_native_owner;
REVOKE ALL ON SCHEMA naruv_trade FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT USAGE ON SCHEMA naruv_trade TO jw_app_dev;
SET ROLE naruv_native_owner;
CREATE TABLE naruv_trade.documents(
 org_id text NOT NULL,doc_id text NOT NULL,actor_id text NOT NULL,kind text NOT NULL CHECK(kind IN ('sale','purchase')),
 quote_id text REFERENCES jw_dev.quotes(id),counterparty_id text NOT NULL,
 source_id text NOT NULL,item_id text NOT NULL,warehouse_id text NOT NULL,
 quantity bigint NOT NULL CHECK(quantity BETWEEN 1 AND 100000),
 unit_price bigint NOT NULL CHECK(unit_price BETWEEN 0 AND 1000000000),
 vat_mode text NOT NULL CHECK(vat_mode IN ('taxable','exempt')),
 fulfilled bigint NOT NULL DEFAULT 0 CHECK(fulfilled>=0 AND fulfilled<=quantity),
 state text NOT NULL CHECK(state IN ('OPEN','PARTIAL','DONE','CANCELLED')),
 created_at timestamptz NOT NULL,
 PRIMARY KEY(org_id,doc_id),UNIQUE(org_id,quote_id),
 CHECK((kind='sale')=(quote_id IS NOT NULL)),
 CHECK((state='OPEN' AND fulfilled=0) OR (state='PARTIAL' AND fulfilled>0 AND fulfilled<quantity)
 OR (state='DONE' AND fulfilled=quantity) OR (state='CANCELLED' AND fulfilled<quantity)),
 FOREIGN KEY(org_id,counterparty_id) REFERENCES jw_dev.customers(org_id,id),
 FOREIGN KEY(org_id,source_id,item_id) REFERENCES naruv_inventory.items,
 FOREIGN KEY(org_id,warehouse_id) REFERENCES naruv_inventory.warehouses
);
CREATE TABLE naruv_trade.events(
 org_id text NOT NULL,request_id text NOT NULL,doc_id text NOT NULL,actor_id text NOT NULL,
 action text NOT NULL CHECK(action IN ('open','fulfill','cancel')),payload jsonb NOT NULL,
 movement_id text,receipt jsonb NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(org_id,request_id),
 FOREIGN KEY(org_id,doc_id) REFERENCES naruv_trade.documents,
 FOREIGN KEY(org_id,movement_id) REFERENCES naruv_inventory.movements,
 CHECK((action='fulfill')=(movement_id IS NOT NULL))
);
CREATE INDEX naruv_trade_reservation_lookup ON naruv_trade.documents(org_id,source_id,item_id,warehouse_id)
 WHERE kind='sale' AND state IN ('OPEN','PARTIAL');
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['documents','events'] LOOP
  EXECUTE format('ALTER TABLE naruv_trade.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE naruv_trade.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY trade_scope ON naruv_trade.%I TO naruv_native_owner USING (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin'')) WITH CHECK (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin''))',t);
  EXECUTE format('REVOKE ALL ON naruv_trade.%I FROM PUBLIC,jw_app_dev,naruv_native_stage',t);
 END LOOP;
END $$;
CREATE TRIGGER trade_events_immutable BEFORE UPDATE OR DELETE ON naruv_trade.events
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE FUNCTION naruv_trade.reserved(p_org text,p_source text,p_item text,p_wh text)
 RETURNS bigint LANGUAGE sql VOLATILE SET search_path=pg_catalog AS $$
 SELECT coalesce(sum(quantity-fulfilled),0)::bigint FROM naruv_trade.documents d
 WHERE d.org_id=p_org AND d.source_id=p_source AND d.item_id=p_item AND d.warehouse_id=p_wh
 AND d.kind='sale' AND d.state IN ('OPEN','PARTIAL')
$$;
-- Existing inventory calls retain their tested implementation; deny the private
-- document movement namespace at the external entrypoint.
ALTER FUNCTION naruv_inventory.post_movement(text,text,text,text,text,bigint,text) RENAME TO post_movement_internal;
REVOKE ALL ON FUNCTION naruv_inventory.post_movement_internal(text,text,text,text,text,bigint,text) FROM PUBLIC,jw_app_dev,naruv_native_stage;
CREATE FUNCTION naruv_inventory.post_movement(p_source text,p_item text,p_request text,p_from text,p_to text,p_qty bigint,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF left(p_request,4)='doc:' THEN RAISE EXCEPTION 'INV_INPUT'; END IF;
 RETURN naruv_inventory.post_movement_internal(p_source,p_item,p_request,p_from,p_to,p_qty,p_csrf);
END $$;
REVOKE ALL ON FUNCTION naruv_inventory.post_movement(text,text,text,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION naruv_inventory.post_movement(text,text,text,text,text,bigint,text) TO jw_app_dev;
-- Both manual movements and document fulfillment must leave all open sale
-- reservations covered. Existing movement transaction takes the tenant lock.
CREATE FUNCTION naruv_trade.balance_guard() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.quantity<naruv_trade.reserved(NEW.org_id,NEW.source_id,NEW.normalized_id,NEW.warehouse_id)
 THEN RAISE EXCEPTION 'INV_INSUFFICIENT'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER trade_balance_guard BEFORE UPDATE OF quantity ON naruv_inventory.balances
 FOR EACH ROW EXECUTE FUNCTION naruv_trade.balance_guard();
CREATE FUNCTION naruv_trade.snapshot(d naruv_trade.documents) RETURNS jsonb
 LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('doc_id',($1).doc_id,'kind',($1).kind,'quote_id',($1).quote_id,
 'counterparty_id',($1).counterparty_id,'source_id',($1).source_id,'item_id',($1).item_id,'warehouse_id',($1).warehouse_id,
 'quantity',($1).quantity,'unit_price',($1).unit_price,'vat_mode',($1).vat_mode,
 'fulfilled',($1).fulfilled,'remaining',CASE WHEN ($1).state='CANCELLED' THEN 0 ELSE ($1).quantity-($1).fulfilled END,
 'state',($1).state,'subtotal',($1).quantity*($1).unit_price,
 'vat',CASE WHEN ($1).vat_mode='taxable' THEN (($1).quantity*($1).unit_price+5)/10 ELSE 0 END,
 'production_authorized',false)
$$;
CREATE FUNCTION naruv_trade.command(p_doc text,p_request text,p_action text,p_payload jsonb,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; e naruv_trade.events; d naruv_trade.documents;
 kind text; qid text; cp text; src text; itm text; wh text; mode text; q bigint; price bigint;
 n bigint; stock bigint; moved jsonb; mid text; result jsonb; qt record;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_doc IS NULL OR p_doc !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_action IS NULL OR p_action NOT IN ('open','fulfill','cancel')
 OR p_confirm IS DISTINCT FROM true OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
 OR octet_length(p_payload::text)>4096 THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO e FROM naruv_trade.events x WHERE x.org_id=a.org_id AND x.request_id=p_request;
 IF FOUND THEN
  IF (e.doc_id,e.actor_id,e.action,e.payload) IS DISTINCT FROM (p_doc,a.actor_id,p_action,p_payload)
  THEN RAISE EXCEPTION 'TRADE_CONFLICT'; END IF;
  RETURN e.receipt;
 END IF;
 IF p_action='open' THEN
  kind:=p_payload->>'kind'; src:=p_payload->>'source_id'; itm:=lower((p_payload->>'item_id') COLLATE "C"); wh:=p_payload->>'warehouse_id';
  IF kind IS NULL OR kind NOT IN ('sale','purchase') OR src IS NULL OR src !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
  OR itm IS NULL OR itm !~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' OR wh IS NULL OR wh !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
  OR jsonb_typeof(p_payload->'kind') IS DISTINCT FROM 'string' OR jsonb_typeof(p_payload->'source_id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(p_payload->'item_id') IS DISTINCT FROM 'string' OR jsonb_typeof(p_payload->'warehouse_id') IS DISTINCT FROM 'string'
  THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
  PERFORM 1 FROM naruv_inventory.items i WHERE i.org_id=a.org_id AND i.source_id=src AND i.normalized_id=itm AND btrim(i.unit)<>'';
  IF NOT FOUND THEN RAISE EXCEPTION 'TRADE_NOT_FOUND'; END IF;
  PERFORM 1 FROM naruv_inventory.warehouses w WHERE w.org_id=a.org_id AND w.warehouse_id=wh AND w.active FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'TRADE_NOT_FOUND'; END IF;
  IF kind='sale' THEN
   IF p_payload-'kind'-'source_id'-'item_id'-'warehouse_id'-'quote_id'<>'{}'::jsonb
   OR jsonb_typeof(p_payload->'quote_id') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
   qid:=p_payload->>'quote_id';
   -- Only single-line V92 draft quotes in this lab; no mutation of the legacy quote.
   SELECT x.customer_id,x.vat_mode,x.status,li.name,li.quantity,li.unit_price INTO qt
   FROM jw_dev.quotes x JOIN jw_dev.quote_items li ON li.quote_id=x.id
   WHERE x.org_id=a.org_id AND x.id=qid;
   IF NOT FOUND THEN RAISE EXCEPTION 'TRADE_NOT_FOUND'; END IF;
   IF qt.status<>'draft' OR (SELECT count(*) FROM jw_dev.quote_items li WHERE li.quote_id=qid)<>1
   THEN RAISE EXCEPTION 'TRADE_QUOTE_SCOPE'; END IF;
   IF NOT EXISTS(SELECT 1 FROM naruv_inventory.items i WHERE i.org_id=a.org_id AND i.source_id=src AND i.normalized_id=itm AND i.name=qt.name)
   THEN RAISE EXCEPTION 'TRADE_QUOTE_SCOPE'; END IF;
   cp:=qt.customer_id; mode:=qt.vat_mode; q:=qt.quantity; price:=qt.unit_price;
   SELECT b.quantity INTO stock FROM naruv_inventory.balances b WHERE b.org_id=a.org_id AND b.source_id=src AND b.normalized_id=itm AND b.warehouse_id=wh;
   IF coalesce(stock,0)-naruv_trade.reserved(a.org_id,src,itm,wh)<q THEN RAISE EXCEPTION 'INV_INSUFFICIENT'; END IF;
  ELSE
   IF p_payload-'kind'-'source_id'-'item_id'-'warehouse_id'-'counterparty_id'-'quantity'-'unit_price'-'vat_mode'<>'{}'::jsonb
   OR jsonb_typeof(p_payload->'counterparty_id') IS DISTINCT FROM 'string'
   OR jsonb_typeof(p_payload->'quantity') IS DISTINCT FROM 'number' OR (p_payload->>'quantity') !~ '^[0-9]{1,6}$'
   OR jsonb_typeof(p_payload->'unit_price') IS DISTINCT FROM 'number' OR (p_payload->>'unit_price') !~ '^[0-9]{1,10}$'
   OR jsonb_typeof(p_payload->'vat_mode') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
   cp:=p_payload->>'counterparty_id'; q:=(p_payload->>'quantity')::bigint; price:=(p_payload->>'unit_price')::bigint; mode:=p_payload->>'vat_mode';
   -- Existing counterparty catalog only; supplier classification is outside this proof.
   PERFORM 1 FROM jw_dev.customers c WHERE c.org_id=a.org_id AND c.id=cp;
   IF NOT FOUND THEN RAISE EXCEPTION 'TRADE_NOT_FOUND'; END IF;
  END IF;
  IF q IS NULL OR q NOT BETWEEN 1 AND 100000 OR price IS NULL OR price NOT BETWEEN 0 AND 1000000000 OR mode IS NULL OR mode NOT IN ('taxable','exempt')
  THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
  INSERT INTO naruv_trade.documents VALUES(a.org_id,p_doc,a.actor_id,kind,qid,cp,src,itm,wh,q,price,mode,0,'OPEN',clock_timestamp()) RETURNING * INTO d;
 ELSE
  SELECT * INTO d FROM naruv_trade.documents x WHERE x.org_id=a.org_id AND x.doc_id=p_doc FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'TRADE_NOT_FOUND'; END IF;
  IF d.state NOT IN ('OPEN','PARTIAL') THEN RAISE EXCEPTION 'TRADE_TERMINAL'; END IF;
  IF p_action='cancel' THEN
   IF p_payload<>'{}'::jsonb THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
   UPDATE naruv_trade.documents x SET state='CANCELLED' WHERE x.org_id=a.org_id AND x.doc_id=p_doc RETURNING * INTO d;
  ELSE
   IF p_payload-'quantity'<>'{}'::jsonb OR jsonb_typeof(p_payload->'quantity') IS DISTINCT FROM 'number'
   OR (p_payload->>'quantity') !~ '^[0-9]{1,6}$' THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
   n:=(p_payload->>'quantity')::bigint;
   IF n<1 OR n>d.quantity-d.fulfilled THEN RAISE EXCEPTION 'TRADE_OVER_QUANTITY'; END IF;
   -- Release only the delivered portion before the stock update; same transaction.
   UPDATE naruv_trade.documents x SET fulfilled=x.fulfilled+n,state=CASE WHEN x.fulfilled+n=x.quantity THEN 'DONE' ELSE 'PARTIAL' END
    WHERE x.org_id=a.org_id AND x.doc_id=p_doc RETURNING * INTO d;
   mid:='doc:'||encode(sha256(convert_to(p_request,'UTF8')),'hex');
   moved:=naruv_inventory.post_movement_internal(d.source_id,d.item_id,mid,
     CASE WHEN d.kind='sale' THEN d.warehouse_id ELSE NULL END,
     CASE WHEN d.kind='purchase' THEN d.warehouse_id ELSE NULL END,n,p_csrf);
  END IF;
 END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 result:=naruv_trade.snapshot(d)||jsonb_build_object('request_id',p_request,'action',p_action,'movement',moved);
 INSERT INTO naruv_trade.events VALUES(a.org_id,p_request,p_doc,a.actor_id,p_action,p_payload,mid,result,clock_timestamp());
 RETURN result;
END $$;
CREATE FUNCTION naruv_trade.inspect(p_doc text,p_csrf text) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; d naruv_trade.documents;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 SELECT * INTO d FROM naruv_trade.documents x WHERE x.org_id=a.org_id AND x.doc_id=p_doc;
 IF NOT FOUND THEN RAISE EXCEPTION 'TRADE_NOT_FOUND'; END IF;
 RETURN naruv_trade.snapshot(d);
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA naruv_trade FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_trade.command(text,text,text,jsonb,boolean,text),naruv_trade.inspect(text,text) TO jw_app_dev;
RESET ROLE;
