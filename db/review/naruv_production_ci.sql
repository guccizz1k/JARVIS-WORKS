-- Disposable PG17 only: single-level BOM and atomic production quantity review.
DO $$ BEGIN
 IF current_database()<>'postgres' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user<>'postgres' OR current_setting('naruv.production_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'PROD_DISPOSABLE_ONLY'; END IF;
END $$;
CREATE SCHEMA naruv_production AUTHORIZATION naruv_native_owner;
REVOKE ALL ON SCHEMA naruv_production FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT USAGE ON SCHEMA naruv_production TO jw_app_dev;
SET ROLE naruv_native_owner;
CREATE TABLE naruv_production.boms(
 org_id text NOT NULL,bom_id text NOT NULL,source_id text NOT NULL,product_id text NOT NULL,actor_id text NOT NULL,
 created_at timestamptz NOT NULL,PRIMARY KEY(org_id,bom_id),
 UNIQUE(org_id,bom_id,source_id),FOREIGN KEY(org_id,source_id,product_id) REFERENCES naruv_inventory.items
);
CREATE TABLE naruv_production.components(
 org_id text NOT NULL,bom_id text NOT NULL,source_id text NOT NULL,material_id text NOT NULL,
 per_unit bigint NOT NULL CHECK(per_unit BETWEEN 1 AND 10000),
 PRIMARY KEY(org_id,bom_id,material_id),
 FOREIGN KEY(org_id,bom_id,source_id) REFERENCES naruv_production.boms(org_id,bom_id,source_id),
 FOREIGN KEY(org_id,source_id,material_id) REFERENCES naruv_inventory.items
);
CREATE TABLE naruv_production.orders(
 org_id text NOT NULL,order_id text NOT NULL,bom_id text NOT NULL,warehouse_id text NOT NULL,
 actor_id text NOT NULL,quantity bigint NOT NULL CHECK(quantity BETWEEN 1 AND 100000),
 completed bigint NOT NULL CHECK(completed BETWEEN 0 AND quantity),
 state text NOT NULL CHECK(state IN ('OPEN','PARTIAL','DONE','CANCELLED')),created_at timestamptz NOT NULL,
 PRIMARY KEY(org_id,order_id),FOREIGN KEY(org_id,bom_id) REFERENCES naruv_production.boms,
 FOREIGN KEY(org_id,warehouse_id) REFERENCES naruv_inventory.warehouses,
 CHECK((state='OPEN' AND completed=0) OR (state='PARTIAL' AND completed>0 AND completed<quantity)
 OR (state='DONE' AND completed=quantity) OR (state='CANCELLED' AND completed<quantity))
);
CREATE TABLE naruv_production.events(
 org_id text NOT NULL,request_id text NOT NULL,bom_id text NOT NULL,order_id text,actor_id text NOT NULL,
 action text NOT NULL CHECK(action IN ('define','open','complete','cancel')),payload jsonb NOT NULL,receipt jsonb NOT NULL,
 created_at timestamptz NOT NULL,PRIMARY KEY(org_id,request_id),
 FOREIGN KEY(org_id,bom_id) REFERENCES naruv_production.boms,
 FOREIGN KEY(org_id,order_id) REFERENCES naruv_production.orders,
 CHECK((action='define')=(order_id IS NULL))
);
CREATE INDEX production_open ON naruv_production.orders(org_id,bom_id,warehouse_id) WHERE state IN ('OPEN','PARTIAL');
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['boms','components','orders','events'] LOOP
  EXECUTE format('ALTER TABLE naruv_production.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE naruv_production.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY production_scope ON naruv_production.%I TO naruv_native_owner USING (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin'')) WITH CHECK (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin''))',t);
  EXECUTE format('REVOKE ALL ON naruv_production.%I FROM PUBLIC,jw_app_dev,naruv_native_stage',t);
  IF t<>'orders' THEN
   EXECUTE format('CREATE TRIGGER production_immutable BEFORE UPDATE OR DELETE ON naruv_production.%I FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable()',t);
  END IF;
 END LOOP;
END $$;
-- Both sales and production share the same reservation pool and tenant lock.
CREATE OR REPLACE FUNCTION naruv_trade.reserved(p_org text,p_source text,p_item text,p_wh text)
 RETURNS bigint LANGUAGE sql VOLATILE SET search_path=pg_catalog AS $$
 SELECT (
  coalesce((SELECT sum(quantity-fulfilled) FROM naruv_trade.documents d
   WHERE d.org_id=p_org AND d.source_id=p_source AND d.item_id=p_item AND d.warehouse_id=p_wh
   AND d.kind='sale' AND d.state IN ('OPEN','PARTIAL')),0)
  +coalesce((SELECT sum((o.quantity-o.completed)*c.per_unit)
   FROM naruv_production.orders o JOIN naruv_production.components c USING(org_id,bom_id)
   WHERE o.org_id=p_org AND c.source_id=p_source AND c.material_id=p_item AND o.warehouse_id=p_wh
   AND o.state IN ('OPEN','PARTIAL')),0))::bigint
$$;
CREATE FUNCTION naruv_production.ident(v text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT coalesce($1 ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$',false)
$$;
CREATE FUNCTION naruv_production.qty(v jsonb,p_max bigint) RETURNS bigint LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE q bigint;
BEGIN
 IF jsonb_typeof(v) IS DISTINCT FROM 'number' OR (v#>>'{}') !~ '^[0-9]{1,9}$' THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
 q:=(v#>>'{}')::bigint;
 IF q<1 OR q>p_max THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
 RETURN q;
END $$;
CREATE FUNCTION naruv_production.plan(p_org text,p_bom text,p_wh text,p_qty bigint) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
DECLARE b naruv_production.boms; rows jsonb;
BEGIN
 SELECT * INTO b FROM naruv_production.boms x WHERE x.org_id=p_org AND x.bom_id=p_bom;
 IF NOT FOUND THEN RAISE EXCEPTION 'PROD_NOT_FOUND'; END IF;
 PERFORM 1 FROM naruv_inventory.warehouses w WHERE w.org_id=p_org AND w.warehouse_id=p_wh AND w.active FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PROD_NOT_FOUND'; END IF;
 SELECT jsonb_agg(jsonb_build_object('material_id',c.material_id,'per_unit',c.per_unit,
 'required',c.per_unit*p_qty,'stock',coalesce(s.quantity,0),
 'reserved',naruv_trade.reserved(p_org,c.source_id,c.material_id,p_wh),
 'shortage',greatest(0,c.per_unit*p_qty-coalesce(s.quantity,0)+naruv_trade.reserved(p_org,c.source_id,c.material_id,p_wh))) ORDER BY c.material_id)
 INTO rows FROM naruv_production.components c LEFT JOIN naruv_inventory.balances s
 ON (s.org_id,s.source_id,s.normalized_id,s.warehouse_id)=(c.org_id,c.source_id,c.material_id,p_wh)
 WHERE c.org_id=p_org AND c.bom_id=p_bom;
 RETURN jsonb_build_object('bom_id',p_bom,'product_id',b.product_id,'warehouse_id',p_wh,'quantity',p_qty,
 'lines',rows,'production_authorized',false);
END $$;
CREATE FUNCTION naruv_production.requirements(p_bom text,p_payload jsonb,p_csrf text) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; q bigint; wh text;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF jsonb_typeof(p_payload) IS DISTINCT FROM 'object' OR p_payload-'warehouse_id'-'quantity'<>'{}'::jsonb
 OR jsonb_typeof(p_payload->'warehouse_id') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
 wh:=p_payload->>'warehouse_id';q:=naruv_production.qty(p_payload->'quantity',100000);
 IF NOT naruv_production.ident(p_bom) OR NOT naruv_production.ident(wh) THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 RETURN naruv_production.plan(a.org_id,p_bom,wh,q);
END $$;
CREATE FUNCTION naruv_production.snapshot(o naruv_production.orders) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('order_id',($1).order_id,'bom_id',($1).bom_id,'warehouse_id',($1).warehouse_id,
 'quantity',($1).quantity,'completed',($1).completed,'state',($1).state,
 'remaining',CASE WHEN ($1).state='CANCELLED' THEN 0 ELSE ($1).quantity-($1).completed END,'production_authorized',false)
$$;
CREATE FUNCTION naruv_production.command(p_key text,p_request text,p_action text,p_payload jsonb,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; b naruv_production.boms; o naruv_production.orders; e naruv_production.events;
 c naruv_production.components; x jsonb; src text; product text; material text; wh text; bid text;
 q bigint; per bigint; result jsonb; plan jsonb; movements jsonb:='[]'::jsonb; mid text;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF NOT naruv_production.ident(p_key) OR NOT naruv_production.ident(p_request)
 OR p_action IS NULL OR p_action NOT IN ('define','open','complete','cancel')
 OR p_confirm IS DISTINCT FROM true OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
 OR octet_length(p_payload::text)>16384 THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO e FROM naruv_production.events z WHERE z.org_id=a.org_id AND z.request_id=p_request;
 IF FOUND THEN
  IF (coalesce(e.order_id,e.bom_id),e.actor_id,e.action,e.payload) IS DISTINCT FROM (p_key,a.actor_id,p_action,p_payload)
  THEN RAISE EXCEPTION 'PROD_CONFLICT'; END IF;
  RETURN e.receipt;
 END IF;
 IF p_action='define' THEN
  IF p_payload-'source_id'-'product_id'-'lines'<>'{}'::jsonb
  OR jsonb_typeof(p_payload->'source_id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(p_payload->'product_id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(p_payload->'lines') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
  src:=p_payload->>'source_id';product:=lower((p_payload->>'product_id') COLLATE "C");bid:=p_key;
  IF NOT naruv_production.ident(src) OR NOT naruv_production.ident(product)
  OR jsonb_array_length(p_payload->'lines') NOT BETWEEN 1 AND 20 THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
  IF (SELECT count(*) FROM naruv_production.boms z WHERE z.org_id=a.org_id)>=128 THEN RAISE EXCEPTION 'PROD_CAPACITY'; END IF;
  PERFORM 1 FROM naruv_inventory.items i WHERE i.org_id=a.org_id AND i.source_id=src AND i.normalized_id=product AND btrim(i.unit)<>'';
  IF NOT FOUND THEN RAISE EXCEPTION 'PROD_NOT_FOUND'; END IF;
  INSERT INTO naruv_production.boms VALUES(a.org_id,bid,src,product,a.actor_id,clock_timestamp());
  FOR x IN SELECT value FROM jsonb_array_elements(p_payload->'lines') LOOP
   IF jsonb_typeof(x) IS DISTINCT FROM 'object' OR x-'material_id'-'per_unit'<>'{}'::jsonb
   OR jsonb_typeof(x->'material_id') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
   material:=lower((x->>'material_id') COLLATE "C");per:=naruv_production.qty(x->'per_unit',10000);
   IF NOT naruv_production.ident(material) THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
   PERFORM 1 FROM naruv_inventory.items i WHERE i.org_id=a.org_id AND i.source_id=src AND i.normalized_id=material AND btrim(i.unit)<>'';
   IF NOT FOUND THEN RAISE EXCEPTION 'PROD_NOT_FOUND'; END IF;
   IF EXISTS(WITH RECURSIVE reach(item) AS (
     SELECT material UNION SELECT z.material_id FROM reach r
     JOIN naruv_production.boms h ON h.org_id=a.org_id AND h.source_id=src AND h.product_id=r.item
     JOIN naruv_production.components z ON (z.org_id,z.bom_id)=(h.org_id,h.bom_id)
    ) SELECT 1 FROM reach WHERE item=product) THEN RAISE EXCEPTION 'PROD_CYCLE'; END IF;
   INSERT INTO naruv_production.components VALUES(a.org_id,bid,src,material,per);
  END LOOP;
  result:=jsonb_build_object('bom_id',bid,'product_id',product,'source_id',src,'lines',p_payload->'lines','production_authorized',false);
 ELSE
  IF p_action='open' THEN
   IF p_payload-'bom_id'-'warehouse_id'-'quantity'<>'{}'::jsonb
   OR jsonb_typeof(p_payload->'bom_id') IS DISTINCT FROM 'string'
   OR jsonb_typeof(p_payload->'warehouse_id') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
   bid:=p_payload->>'bom_id';wh:=p_payload->>'warehouse_id';q:=naruv_production.qty(p_payload->'quantity',100000);
   IF NOT naruv_production.ident(bid) OR NOT naruv_production.ident(wh) THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
   plan:=naruv_production.plan(a.org_id,bid,wh,q);
   IF EXISTS(SELECT 1 FROM jsonb_array_elements(plan->'lines') z WHERE (z->>'shortage')::bigint>0)
   THEN RAISE EXCEPTION 'INV_INSUFFICIENT'; END IF;
   INSERT INTO naruv_production.orders VALUES(a.org_id,p_key,bid,wh,a.actor_id,q,0,'OPEN',clock_timestamp()) RETURNING * INTO o;
  ELSE
   SELECT * INTO o FROM naruv_production.orders z WHERE z.org_id=a.org_id AND z.order_id=p_key FOR UPDATE;
   IF NOT FOUND THEN RAISE EXCEPTION 'PROD_NOT_FOUND'; END IF;
   IF o.state NOT IN ('OPEN','PARTIAL') THEN RAISE EXCEPTION 'PROD_TERMINAL'; END IF;
   bid:=o.bom_id;wh:=o.warehouse_id;
   IF p_action='cancel' THEN
    IF p_payload<>'{}'::jsonb THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
    UPDATE naruv_production.orders z SET state='CANCELLED' WHERE z.org_id=a.org_id AND z.order_id=p_key RETURNING * INTO o;
   ELSE
    IF p_payload-'quantity'<>'{}'::jsonb THEN RAISE EXCEPTION 'PROD_INPUT'; END IF;
    q:=naruv_production.qty(p_payload->'quantity',100000);
    IF q>o.quantity-o.completed THEN RAISE EXCEPTION 'PROD_OVER_QUANTITY'; END IF;
    SELECT * INTO STRICT b FROM naruv_production.boms z WHERE z.org_id=a.org_id AND z.bom_id=bid;
    -- Release only this completion's reservation; all material issues and output share one transaction.
    UPDATE naruv_production.orders z SET completed=z.completed+q,state=CASE WHEN z.completed+q=z.quantity THEN 'DONE' ELSE 'PARTIAL' END
     WHERE z.org_id=a.org_id AND z.order_id=p_key RETURNING * INTO o;
    FOR c IN SELECT * FROM naruv_production.components z WHERE z.org_id=a.org_id AND z.bom_id=bid ORDER BY z.material_id LOOP
     mid:='doc:'||encode(sha256(convert_to(jsonb_build_array('production',p_request,'material',c.material_id)::text,'UTF8')),'hex');
     movements:=movements||jsonb_build_array(naruv_inventory.post_movement_internal(c.source_id,c.material_id,mid,wh,NULL,c.per_unit*q,p_csrf));
    END LOOP;
    mid:='doc:'||encode(sha256(convert_to(jsonb_build_array('production',p_request,'output',b.product_id)::text,'UTF8')),'hex');
    movements:=movements||jsonb_build_array(naruv_inventory.post_movement_internal(b.source_id,b.product_id,mid,NULL,wh,q,p_csrf));
   END IF;
  END IF;
  result:=naruv_production.snapshot(o)||jsonb_build_object('movements',movements);
 END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 result:=result||jsonb_build_object('request_id',p_request,'action',p_action);
 INSERT INTO naruv_production.events VALUES(a.org_id,p_request,bid,CASE WHEN p_action='define' THEN NULL ELSE p_key END,a.actor_id,p_action,p_payload,result,clock_timestamp());
 RETURN result;
END $$;
CREATE FUNCTION naruv_production.inspect(p_order text,p_csrf text) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; o naruv_production.orders;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 SELECT * INTO o FROM naruv_production.orders z WHERE z.org_id=a.org_id AND z.order_id=p_order;
 IF NOT FOUND THEN RAISE EXCEPTION 'PROD_NOT_FOUND'; END IF;
 RETURN naruv_production.snapshot(o);
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA naruv_production FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_production.command(text,text,text,jsonb,boolean,text),naruv_production.requirements(text,jsonb,text),naruv_production.inspect(text,text) TO jw_app_dev;
RESET ROLE;
