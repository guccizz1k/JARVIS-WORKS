-- Disposable PG17 inventory proof. Requires native write and customer bridge fixtures.
DO $$ BEGIN
 IF current_database()<>'postgres' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user<>'postgres' OR current_setting('naruv.inventory_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'NARUV_INVENTORY_DISPOSABLE_ONLY'; END IF;
END $$;
CREATE SCHEMA naruv_inventory AUTHORIZATION naruv_native_owner;
REVOKE ALL ON SCHEMA naruv_inventory FROM PUBLIC,naruv_native_stage,jw_app_dev;
GRANT USAGE ON SCHEMA naruv_inventory TO jw_app_dev;
SET ROLE naruv_native_owner;
CREATE TABLE naruv_inventory.items(
 org_id text NOT NULL,source_id text NOT NULL,normalized_id text NOT NULL,
 entity text NOT NULL DEFAULT 'item' CHECK(entity='item'),
 source_item_id text NOT NULL,name text NOT NULL,unit text NOT NULL,
 PRIMARY KEY(org_id,source_id,normalized_id),
 CHECK(normalized_id=lower(source_item_id COLLATE "C")),
 FOREIGN KEY(org_id,source_id,entity,normalized_id)
 REFERENCES naruv_native_review.records(org_id,source_id,entity,normalized_id)
);
CREATE TABLE naruv_inventory.warehouses(
 org_id text NOT NULL,warehouse_id text NOT NULL CHECK(warehouse_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 name text NOT NULL,active boolean NOT NULL DEFAULT true,
 PRIMARY KEY(org_id,warehouse_id)
);
CREATE TABLE naruv_inventory.balances(
 org_id text NOT NULL,source_id text NOT NULL,normalized_id text NOT NULL,warehouse_id text NOT NULL,
 quantity bigint NOT NULL CHECK(quantity BETWEEN 0 AND 1000000000000),
 PRIMARY KEY(org_id,source_id,normalized_id,warehouse_id),
 FOREIGN KEY(org_id,source_id,normalized_id) REFERENCES naruv_inventory.items,
 FOREIGN KEY(org_id,warehouse_id) REFERENCES naruv_inventory.warehouses
);
CREATE TABLE naruv_inventory.movements(
 org_id text NOT NULL,request_id text NOT NULL,actor_id text NOT NULL,
 source_id text NOT NULL,normalized_id text NOT NULL,
 from_warehouse text,to_warehouse text,quantity bigint NOT NULL CHECK(quantity BETWEEN 1 AND 1000000000),
 from_after bigint,to_after bigint,created_at timestamptz NOT NULL,
 PRIMARY KEY(org_id,request_id),
 CHECK(from_warehouse IS DISTINCT FROM to_warehouse),
 CHECK((from_warehouse IS NULL)=(from_after IS NULL)),
 CHECK((to_warehouse IS NULL)=(to_after IS NULL)),
 CHECK(from_after BETWEEN 0 AND 1000000000000),CHECK(to_after BETWEEN 0 AND 1000000000000),
 FOREIGN KEY(org_id,source_id,normalized_id) REFERENCES naruv_inventory.items,
 FOREIGN KEY(org_id,from_warehouse) REFERENCES naruv_inventory.warehouses,
 FOREIGN KEY(org_id,to_warehouse) REFERENCES naruv_inventory.warehouses
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['items','warehouses','balances','movements'] LOOP
  EXECUTE format('ALTER TABLE naruv_inventory.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE naruv_inventory.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY inventory_scope ON naruv_inventory.%I TO naruv_native_owner USING (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin'')) WITH CHECK (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin''))',t);
  EXECUTE format('REVOKE ALL ON naruv_inventory.%I FROM PUBLIC,jw_app_dev,naruv_native_stage',t);
 END LOOP;
END $$;
CREATE TRIGGER immutable_movements BEFORE UPDATE OR DELETE ON naruv_inventory.movements
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE TRIGGER immutable_items BEFORE UPDATE OR DELETE ON naruv_inventory.items
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE FUNCTION naruv_inventory.import_item() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
BEGIN
 IF current_user IS DISTINCT FROM 'naruv_native_owner' OR NEW.entity IS DISTINCT FROM 'item'
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 INSERT INTO naruv_inventory.items(org_id,source_id,normalized_id,source_item_id,name,unit)
 VALUES(NEW.org_id,NEW.source_id,NEW.normalized_id,NEW.source_record_id,NEW.data->>'name',coalesce(NEW.data->>'unit',''));
 RETURN NEW;
END $$;
CREATE TRIGGER inventory_item_after_insert AFTER INSERT ON naruv_native_review.records
 FOR EACH ROW WHEN(NEW.entity='item') EXECUTE FUNCTION naruv_inventory.import_item();
CREATE FUNCTION naruv_inventory.receipt(r naruv_inventory.movements) RETURNS jsonb
 LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('status','REVIEW_MOVED','request_id',($1).request_id,'source_id',($1).source_id,
 'item_id',($1).normalized_id,'from_warehouse',($1).from_warehouse,'to_warehouse',($1).to_warehouse,
 'quantity',($1).quantity,'from_after',($1).from_after,'to_after',($1).to_after,'production_authorized',false)
$$;
CREATE FUNCTION naruv_inventory.post_movement(p_source text,p_item text,p_request text,p_from text,p_to text,p_qty bigint,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; m naruv_inventory.movements; item text; wh text; available bigint; f bigint; t bigint;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_source IS NULL OR p_source !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_item IS NULL OR p_item !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_from IS NOT DISTINCT FROM p_to OR p_qty IS NULL OR p_qty NOT BETWEEN 1 AND 1000000000
 OR (p_from IS NOT NULL AND p_from !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$')
 OR (p_to IS NOT NULL AND p_to !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$')
 THEN RAISE EXCEPTION 'INV_INPUT'; END IF;
 item:=lower(p_item COLLATE "C");
 -- Conservative fixture lock: serialize tenant movements, including across items.
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO m FROM naruv_inventory.movements x WHERE x.org_id=a.org_id AND x.request_id=p_request;
 IF FOUND THEN
  IF (m.actor_id,m.source_id,m.normalized_id,m.from_warehouse,m.to_warehouse,m.quantity)
  IS DISTINCT FROM (a.actor_id,p_source,item,p_from,p_to,p_qty) THEN RAISE EXCEPTION 'INV_CONFLICT'; END IF;
  RETURN naruv_inventory.receipt(m);
 END IF;
 PERFORM 1 FROM naruv_inventory.items i WHERE i.org_id=a.org_id AND i.source_id=p_source AND i.normalized_id=item;
 IF NOT FOUND THEN RAISE EXCEPTION 'INV_NOT_FOUND'; END IF;
 -- No fractional stock or implicit unit conversion. Unspecified units cannot move.
 IF EXISTS(SELECT 1 FROM naruv_inventory.items i WHERE i.org_id=a.org_id AND i.source_id=p_source AND i.normalized_id=item AND btrim(i.unit)='')
 THEN RAISE EXCEPTION 'INV_UNIT_REQUIRED'; END IF;
 FOR wh IN SELECT x FROM unnest(ARRAY[p_from,p_to]) x WHERE x IS NOT NULL ORDER BY x COLLATE "C" LOOP
  PERFORM 1 FROM naruv_inventory.warehouses w WHERE w.org_id=a.org_id AND w.warehouse_id=wh AND w.active FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'INV_NOT_FOUND'; END IF;
  INSERT INTO naruv_inventory.balances VALUES(a.org_id,p_source,item,wh,0) ON CONFLICT DO NOTHING;
  SELECT b.quantity INTO available FROM naruv_inventory.balances b
   WHERE b.org_id=a.org_id AND b.source_id=p_source AND b.normalized_id=item AND b.warehouse_id=wh FOR UPDATE;
  IF wh=p_from THEN
   IF available<p_qty THEN RAISE EXCEPTION 'INV_INSUFFICIENT'; END IF;
   f:=available-p_qty;
   UPDATE naruv_inventory.balances b SET quantity=f WHERE b.org_id=a.org_id AND b.source_id=p_source AND b.normalized_id=item AND b.warehouse_id=wh;
  ELSE
   IF available>1000000000000-p_qty THEN RAISE EXCEPTION 'INV_CAPACITY'; END IF;
   t:=available+p_qty;
   UPDATE naruv_inventory.balances b SET quantity=t WHERE b.org_id=a.org_id AND b.source_id=p_source AND b.normalized_id=item AND b.warehouse_id=wh;
  END IF;
 END LOOP;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 INSERT INTO naruv_inventory.movements VALUES(a.org_id,p_request,a.actor_id,p_source,item,p_from,p_to,p_qty,f,t,clock_timestamp()) RETURNING * INTO m;
 RETURN naruv_inventory.receipt(m);
END $$;
CREATE FUNCTION naruv_inventory.read_stock(p_source text,p_item text,p_warehouse text,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; i naruv_inventory.items; qty bigint;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 SELECT * INTO i FROM naruv_inventory.items x WHERE x.org_id=a.org_id AND x.source_id=p_source AND x.normalized_id=lower(p_item COLLATE "C");
 IF NOT FOUND THEN RAISE EXCEPTION 'INV_NOT_FOUND'; END IF;
 PERFORM 1 FROM naruv_inventory.warehouses w WHERE w.org_id=a.org_id AND w.warehouse_id=p_warehouse AND w.active;
 IF NOT FOUND THEN RAISE EXCEPTION 'INV_NOT_FOUND'; END IF;
 SELECT b.quantity INTO qty FROM naruv_inventory.balances b WHERE b.org_id=a.org_id AND b.source_id=p_source AND b.normalized_id=i.normalized_id AND b.warehouse_id=p_warehouse;
 RETURN jsonb_build_object('item_id',i.source_item_id,'name',i.name,'unit',i.unit,'warehouse_id',p_warehouse,'quantity',coalesce(qty,0),'production_authorized',false);
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA naruv_inventory FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_inventory.post_movement(text,text,text,text,text,bigint,text),naruv_inventory.read_stock(text,text,text,text) TO jw_app_dev;
RESET ROLE;
INSERT INTO naruv_inventory.warehouses VALUES ('ci-a','W1','Warehouse 1',true),('ci-a','W2','Warehouse 2',true),
 ('ci-b','W1','Warehouse 1',true),('ci-b','W2','Warehouse 2',true),('ci-a','CLOSED','Closed',false);
