-- Disposable PG17: one authoritative multi-line V92 quote -> one bundle.
DO $$ BEGIN
 IF current_database()<>'postgres' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user<>'postgres' OR current_setting('naruv.quote_bundle_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'QUOTE_BUNDLE_DISPOSABLE_ONLY'; END IF;
END $$;
CREATE ROLE naruv_quote_fence NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
CREATE SCHEMA naruv_quote_bundle AUTHORIZATION naruv_native_owner;
REVOKE ALL ON SCHEMA naruv_quote_bundle FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT USAGE ON SCHEMA naruv_quote_bundle TO jw_app_dev,naruv_quote_fence;
GRANT REFERENCES(id) ON jw_dev.quote_items TO naruv_native_owner;
SET ROLE naruv_native_owner;
ALTER TABLE naruv_trade.documents ADD COLUMN quote_line_id text REFERENCES jw_dev.quote_items(id);
ALTER TABLE naruv_trade.documents DROP CONSTRAINT documents_org_id_quote_id_key;
CREATE UNIQUE INDEX documents_single_quote ON naruv_trade.documents(org_id,quote_id) WHERE quote_line_id IS NULL;
CREATE UNIQUE INDEX documents_quote_line ON naruv_trade.documents(org_id,quote_line_id) WHERE quote_line_id IS NOT NULL;
ALTER TABLE naruv_trade.documents ADD CHECK(quote_line_id IS NULL OR (kind='sale' AND left(doc_id,7)='bundle:'));
CREATE TABLE naruv_quote_bundle.conversions(
 org_id text NOT NULL,quote_id text NOT NULL REFERENCES jw_dev.quotes(id),
 bundle_id text NOT NULL,actor_id text NOT NULL,snapshot_sha256 text NOT NULL CHECK(snapshot_sha256 ~ '^[a-f0-9]{64}$'),
 snapshot jsonb NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(org_id,quote_id),UNIQUE(quote_id),UNIQUE(org_id,bundle_id),
 FOREIGN KEY(org_id,bundle_id) REFERENCES naruv_bundle.headers
);
ALTER TABLE naruv_quote_bundle.conversions ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_quote_bundle.conversions FORCE ROW LEVEL SECURITY;
CREATE POLICY conversion_scope ON naruv_quote_bundle.conversions TO naruv_native_owner
 USING(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))
 WITH CHECK(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
CREATE POLICY conversion_fence_read ON naruv_quote_bundle.conversions FOR SELECT TO naruv_quote_fence USING(true);
REVOKE ALL ON naruv_quote_bundle.conversions FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT SELECT(quote_id) ON naruv_quote_bundle.conversions TO naruv_quote_fence;
CREATE TRIGGER conversion_immutable BEFORE UPDATE OR DELETE ON naruv_quote_bundle.conversions
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE FUNCTION naruv_quote_bundle.snapshot(p_org text,p_quote text) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
DECLARE q record; lines jsonb; n bigint; sub numeric; tax numeric;
BEGIN
 SELECT x.id,x.customer_id,x.status,x.vat_mode,x.updated_at,x.title,x.doc_no,x.customer_name_snapshot INTO q
 FROM jw_dev.quotes x WHERE x.org_id=p_org AND x.id=p_quote;
 IF NOT FOUND THEN RAISE EXCEPTION 'QB_NOT_FOUND'; END IF;
 IF q.status<>'draft' OR q.vat_mode NOT IN ('taxable','exempt') THEN RAISE EXCEPTION 'QB_SCOPE'; END IF;
 SELECT count(*),coalesce(sum(quantity::numeric*unit_price),0),
 jsonb_agg(jsonb_build_object('quote_line_id',id,'position',position,'name',name,'quantity',quantity,'unit_price',unit_price) ORDER BY position,id)
 INTO n,sub,lines FROM jw_dev.quote_items WHERE quote_id=p_quote;
 IF n NOT BETWEEN 2 AND 20 OR sub>2000000000000000 OR EXISTS(
 SELECT 1 FROM jw_dev.quote_items WHERE quote_id=p_quote AND (quantity NOT BETWEEN 1 AND 100000 OR unit_price NOT BETWEEN 0 AND 1000000000 OR btrim(name)=''))
 OR (SELECT count(DISTINCT position) FROM jw_dev.quote_items WHERE quote_id=p_quote)<>n
 THEN RAISE EXCEPTION 'QB_SCOPE'; END IF;
 tax:=CASE WHEN q.vat_mode='taxable' THEN floor((sub+5)/10) ELSE 0 END;
 RETURN to_jsonb(q)||jsonb_build_object('lines',lines,'subtotal',sub,'vat',tax,'total',sub+tax);
END $$;
CREATE FUNCTION naruv_quote_bundle.preview(p_quote text,p_csrf text) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; s jsonb;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-quote-v1:'||p_quote,0));
 s:=naruv_quote_bundle.snapshot(a.org_id,p_quote);
 RETURN jsonb_build_object('snapshot',s,'snapshot_sha256',encode(sha256(convert_to(s::text,'UTF8')),'hex'),'production_authorized',false);
END $$;
CREATE FUNCTION naruv_quote_bundle.convert(p_bundle text,p_request text,p_payload jsonb,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; e naruv_bundle.events; s jsonb; qid text; digest text; mappings jsonb;
 x jsonb; m jsonb; idx int; cid text; rid text; src text; itm text; wh text; qty bigint; price bigint;
 stock bigint; d naruv_trade.documents; result jsonb; out_rows jsonb:='[]'::jsonb;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_bundle IS NULL OR p_bundle !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_confirm IS DISTINCT FROM true OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
 OR p_payload-'quote_id'-'snapshot_sha256'-'lines'<>'{}'::jsonb OR octet_length(p_payload::text)>16384
 OR jsonb_typeof(p_payload->'quote_id') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p_payload->'snapshot_sha256') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p_payload->'lines') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'QB_INPUT'; END IF;
 qid:=p_payload->>'quote_id';digest:=p_payload->>'snapshot_sha256';mappings:=p_payload->'lines';
 IF qid !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR digest !~ '^[a-f0-9]{64}$' OR jsonb_array_length(mappings) NOT BETWEEN 2 AND 20
 THEN RAISE EXCEPTION 'QB_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-quote-v1:'||qid,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO e FROM naruv_bundle.events z WHERE z.org_id=a.org_id AND z.request_id=p_request;
 IF FOUND THEN
  IF (e.bundle_id,e.actor_id,e.action,e.payload) IS DISTINCT FROM (p_bundle,a.actor_id,'open'::text,p_payload)
  THEN RAISE EXCEPTION 'QB_CONFLICT'; END IF;
  RETURN e.receipt;
 END IF;
 s:=naruv_quote_bundle.snapshot(a.org_id,qid);
 IF digest<>encode(sha256(convert_to(s::text,'UTF8')),'hex') THEN RAISE EXCEPTION 'QB_STALE'; END IF;
 IF EXISTS(SELECT 1 FROM naruv_quote_bundle.conversions z WHERE z.org_id=a.org_id AND z.quote_id=qid)
 OR EXISTS(SELECT 1 FROM naruv_trade.documents z WHERE z.org_id=a.org_id AND z.quote_id=qid)
 OR EXISTS(SELECT 1 FROM naruv_bundle.headers z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle)
 THEN RAISE EXCEPTION 'QB_CONFLICT'; END IF;
 IF jsonb_array_length(mappings)<>jsonb_array_length(s->'lines')
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(mappings) z WHERE jsonb_typeof(z) IS DISTINCT FROM 'object'
 OR z-'quote_line_id'-'source_id'-'item_id'-'warehouse_id'<>'{}'::jsonb
 OR jsonb_typeof(z->'quote_line_id') IS DISTINCT FROM 'string' OR jsonb_typeof(z->'source_id') IS DISTINCT FROM 'string'
 OR jsonb_typeof(z->'item_id') IS DISTINCT FROM 'string' OR jsonb_typeof(z->'warehouse_id') IS DISTINCT FROM 'string')
 OR (SELECT count(DISTINCT z->>'quote_line_id') FROM jsonb_array_elements(mappings) z)<>jsonb_array_length(mappings)
 THEN RAISE EXCEPTION 'QB_INPUT'; END IF;
 INSERT INTO naruv_bundle.headers VALUES(a.org_id,p_bundle,a.actor_id,'sale',s->>'customer_id',s->>'vat_mode',clock_timestamp());
 FOR x,idx IN SELECT value,ordinality::int FROM jsonb_array_elements(s->'lines') WITH ORDINALITY LOOP
  SELECT z INTO m FROM jsonb_array_elements(mappings) z WHERE z->>'quote_line_id'=x->>'quote_line_id';
  IF NOT FOUND THEN RAISE EXCEPTION 'QB_INPUT'; END IF;
  src:=m->>'source_id';itm:=lower((m->>'item_id') COLLATE "C");wh:=m->>'warehouse_id';
  IF src !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR itm !~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' OR wh !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
  THEN RAISE EXCEPTION 'QB_INPUT'; END IF;
  IF NOT EXISTS(SELECT 1 FROM naruv_inventory.items i WHERE i.org_id=a.org_id AND i.source_id=src AND i.normalized_id=itm AND i.name=x->>'name' AND btrim(i.unit)<>'')
  THEN RAISE EXCEPTION 'QB_MAPPING'; END IF;
  PERFORM 1 FROM naruv_inventory.warehouses w WHERE w.org_id=a.org_id AND w.warehouse_id=wh AND w.active FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'QB_NOT_FOUND'; END IF;
  qty:=(x->>'quantity')::bigint;price:=(x->>'unit_price')::bigint;
  SELECT b.quantity INTO stock FROM naruv_inventory.balances b WHERE b.org_id=a.org_id AND b.source_id=src AND b.normalized_id=itm AND b.warehouse_id=wh;
  IF coalesce(stock,0)-naruv_trade.reserved(a.org_id,src,itm,wh)<qty THEN RAISE EXCEPTION 'INV_INSUFFICIENT'; END IF;
  cid:=naruv_bundle.child_id('document',p_bundle,idx);rid:=naruv_bundle.child_id('command',p_request,idx);
  INSERT INTO naruv_trade.documents(org_id,doc_id,actor_id,kind,quote_id,counterparty_id,source_id,item_id,warehouse_id,quantity,unit_price,vat_mode,fulfilled,state,created_at,quote_line_id)
  VALUES(a.org_id,cid,a.actor_id,'sale',qid,s->>'customer_id',src,itm,wh,qty,price,s->>'vat_mode',0,'OPEN',clock_timestamp(),x->>'quote_line_id') RETURNING * INTO d;
  result:=naruv_trade.snapshot(d)||jsonb_build_object('request_id',rid,'action','open','movement',NULL,'quote_line_id',x->>'quote_line_id');
  INSERT INTO naruv_trade.events(org_id,request_id,doc_id,actor_id,action,payload,movement_id,receipt,created_at) VALUES(a.org_id,rid,cid,a.actor_id,'open',m,NULL,result,clock_timestamp());
  INSERT INTO naruv_bundle.lines VALUES(a.org_id,p_bundle,idx,cid);
  out_rows:=out_rows||jsonb_build_array(jsonb_build_object('line_no',idx,'result',result));
 END LOOP;
 INSERT INTO naruv_quote_bundle.conversions VALUES(a.org_id,qid,p_bundle,a.actor_id,digest,s,clock_timestamp());
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 result:=jsonb_build_object('bundle_id',p_bundle,'request_id',p_request,'action','open','lines',out_rows,
 'quote_id',qid,'snapshot_sha256',digest,'subtotal',s->'subtotal','vat',s->'vat','total',s->'total','production_authorized',false);
 INSERT INTO naruv_bundle.events VALUES(a.org_id,p_request,p_bundle,a.actor_id,'open',p_payload,result,clock_timestamp());
 RETURN result;
END $$;
-- Cumulative VAT for all billed lines of a converted quote, in posting order.
-- Existing single-line/grouped purchase/sale behavior is untouched.
CREATE FUNCTION naruv_quote_bundle.allocate_vat() RETURNS trigger LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
DECLARE qid text; mode text; prev numeric;
BEGIN
 SELECT d.quote_id,d.vat_mode INTO qid,mode FROM naruv_trade.documents d
 WHERE d.org_id=NEW.org_id AND d.doc_id=NEW.doc_id AND d.quote_line_id IS NOT NULL;
 IF NOT FOUND THEN RETURN NEW; END IF;
 SELECT coalesce(sum(b.subtotal),0) INTO prev FROM naruv_finance.bills b JOIN naruv_trade.documents d ON (b.org_id,b.doc_id)=(d.org_id,d.doc_id)
 WHERE d.org_id=NEW.org_id AND d.quote_id=qid AND d.quote_line_id IS NOT NULL;
 NEW.vat:=CASE WHEN mode='taxable' THEN floor((prev+NEW.subtotal+5)/10)-floor((prev+5)/10) ELSE 0 END;
 RETURN NEW;
END $$;
CREATE TRIGGER quote_bundle_vat BEFORE INSERT ON naruv_finance.bills FOR EACH ROW EXECUTE FUNCTION naruv_quote_bundle.allocate_vat();
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA naruv_quote_bundle FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_quote_bundle.preview(text,text),naruv_quote_bundle.convert(text,text,jsonb,boolean,text) TO jw_app_dev;
RESET ROLE;
-- Narrow, non-login security-definer fence sees only consumed quote IDs.
-- Serialize ordinary source DML with conversion, even for non-admin writers.
CREATE SCHEMA naruv_quote_fence AUTHORIZATION naruv_quote_fence;
REVOKE ALL ON SCHEMA naruv_quote_fence FROM PUBLIC,jw_app_dev,naruv_native_stage;
SET ROLE naruv_quote_fence;
CREATE FUNCTION naruv_quote_fence.freeze() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old_id text; new_id text; qid text;
BEGIN
 IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'QB_SOURCE_FROZEN'; END IF;
 IF TG_TABLE_NAME='quotes' THEN
  IF TG_OP<>'INSERT' THEN old_id:=OLD.id; END IF;
  IF TG_OP<>'DELETE' THEN new_id:=NEW.id; END IF;
 ELSE
  IF TG_OP<>'INSERT' THEN old_id:=OLD.quote_id; END IF;
  IF TG_OP<>'DELETE' THEN new_id:=NEW.quote_id; END IF;
 END IF;
 FOR qid IN SELECT DISTINCT x FROM unnest(ARRAY[old_id,new_id]) x WHERE x IS NOT NULL ORDER BY x LOOP
  PERFORM pg_advisory_xact_lock(hashtextextended('naruv-quote-v1:'||qid,0));
  IF EXISTS(SELECT 1 FROM naruv_quote_bundle.conversions c WHERE c.quote_id=qid) THEN RAISE EXCEPTION 'QB_SOURCE_FROZEN'; END IF;
 END LOOP;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION naruv_quote_fence.freeze() FROM PUBLIC;
RESET ROLE;
CREATE TRIGGER quote_freeze BEFORE INSERT OR UPDATE OR DELETE ON jw_dev.quotes FOR EACH ROW EXECUTE FUNCTION naruv_quote_fence.freeze();
CREATE TRIGGER quote_line_freeze BEFORE INSERT OR UPDATE OR DELETE ON jw_dev.quote_items FOR EACH ROW EXECUTE FUNCTION naruv_quote_fence.freeze();
CREATE TRIGGER quote_truncate_freeze BEFORE TRUNCATE ON jw_dev.quotes FOR EACH STATEMENT EXECUTE FUNCTION naruv_quote_fence.freeze();
CREATE TRIGGER quote_line_truncate_freeze BEFORE TRUNCATE ON jw_dev.quote_items FOR EACH STATEMENT EXECUTE FUNCTION naruv_quote_fence.freeze();
