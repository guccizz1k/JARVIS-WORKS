-- Disposable PG17 batch review only. Reuses single-line trade and finance as child engines.
DO $$ BEGIN
 IF current_database()<>'postgres' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user<>'postgres' OR current_setting('naruv.bundle_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'BUNDLE_DISPOSABLE_ONLY'; END IF;
 IF EXISTS(SELECT 1 FROM naruv_trade.documents WHERE left(doc_id,7)='bundle:')
 OR EXISTS(SELECT 1 FROM naruv_trade.events WHERE left(request_id,7)='bundle:')
 OR EXISTS(SELECT 1 FROM naruv_finance.bills WHERE left(bill_id,7)='bundle:')
 OR EXISTS(SELECT 1 FROM naruv_finance.events WHERE left(request_id,7)='bundle:')
 THEN RAISE EXCEPTION 'BUNDLE_NAMESPACE_OCCUPIED'; END IF;
END $$;
CREATE SCHEMA naruv_bundle AUTHORIZATION naruv_native_owner;
REVOKE ALL ON SCHEMA naruv_bundle FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT USAGE ON SCHEMA naruv_bundle TO jw_app_dev;
SET ROLE naruv_native_owner;
CREATE TABLE naruv_bundle.headers(
 org_id text NOT NULL,bundle_id text NOT NULL,actor_id text NOT NULL,kind text NOT NULL CHECK(kind IN ('sale','purchase')),
 counterparty_id text NOT NULL,vat_mode text NOT NULL CHECK(vat_mode IN ('taxable','exempt')),created_at timestamptz NOT NULL,
 PRIMARY KEY(org_id,bundle_id)
);
CREATE TABLE naruv_bundle.lines(
 org_id text NOT NULL,bundle_id text NOT NULL,line_no int NOT NULL CHECK(line_no BETWEEN 1 AND 20),
 doc_id text NOT NULL,PRIMARY KEY(org_id,bundle_id,line_no),UNIQUE(org_id,doc_id),
 FOREIGN KEY(org_id,bundle_id) REFERENCES naruv_bundle.headers,
 FOREIGN KEY(org_id,doc_id) REFERENCES naruv_trade.documents
);
CREATE TABLE naruv_bundle.events(
 org_id text NOT NULL,request_id text NOT NULL,bundle_id text NOT NULL,actor_id text NOT NULL,
 action text NOT NULL CHECK(action IN ('open','fulfill','cancel','bill','pay','reverse')),
 payload jsonb NOT NULL,receipt jsonb NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(org_id,request_id),FOREIGN KEY(org_id,bundle_id) REFERENCES naruv_bundle.headers
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['headers','lines','events'] LOOP
  EXECUTE format('ALTER TABLE naruv_bundle.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE naruv_bundle.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY bundle_scope ON naruv_bundle.%I TO naruv_native_owner USING (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin'')) WITH CHECK (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin''))',t);
  EXECUTE format('REVOKE ALL ON naruv_bundle.%I FROM PUBLIC,jw_app_dev,naruv_native_stage',t);
  EXECUTE format('CREATE TRIGGER immutable_bundle BEFORE UPDATE OR DELETE ON naruv_bundle.%I FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable()',t);
 END LOOP;
END $$;
-- Preserve existing behavior for ordinary identifiers. Private IDs cannot be
-- mutated by standalone public APIs, even through direct SQL.
ALTER FUNCTION naruv_trade.command(text,text,text,jsonb,boolean,text) RENAME TO command_bundle_internal;
REVOKE ALL ON FUNCTION naruv_trade.command_bundle_internal(text,text,text,jsonb,boolean,text) FROM PUBLIC,jw_app_dev,naruv_native_stage;
CREATE FUNCTION naruv_trade.command(p_doc text,p_request text,p_action text,p_payload jsonb,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF left(p_doc,7)='bundle:' OR left(p_request,7)='bundle:' THEN RAISE EXCEPTION 'TRADE_INPUT'; END IF;
 RETURN naruv_trade.command_bundle_internal(p_doc,p_request,p_action,p_payload,p_confirm,p_csrf);
END $$;
REVOKE ALL ON FUNCTION naruv_trade.command(text,text,text,jsonb,boolean,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION naruv_trade.command(text,text,text,jsonb,boolean,text) TO jw_app_dev;
ALTER FUNCTION naruv_finance.command(text,text,text,jsonb,boolean,text) RENAME TO command_bundle_internal;
REVOKE ALL ON FUNCTION naruv_finance.command_bundle_internal(text,text,text,jsonb,boolean,text) FROM PUBLIC,jw_app_dev,naruv_native_stage;
CREATE FUNCTION naruv_finance.command(p_bill text,p_request text,p_action text,p_payload jsonb,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF left(p_bill,7)='bundle:' OR left(p_request,7)='bundle:'
 OR left(p_payload->>'doc_id',7)='bundle:' OR left(p_payload->>'fulfillment_id',7)='bundle:'
 OR left(p_payload->>'payment_request_id',7)='bundle:' THEN RAISE EXCEPTION 'FIN_INPUT'; END IF;
 RETURN naruv_finance.command_bundle_internal(p_bill,p_request,p_action,p_payload,p_confirm,p_csrf);
END $$;
REVOKE ALL ON FUNCTION naruv_finance.command(text,text,text,jsonb,boolean,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION naruv_finance.command(text,text,text,jsonb,boolean,text) TO jw_app_dev;
CREATE FUNCTION naruv_bundle.child_id(p_type text,p_key text,p_line int) RETURNS text
 LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT 'bundle:'||encode(sha256(convert_to(jsonb_build_array($1,$2,$3)::text,'UTF8')),'hex')
$$;
CREATE FUNCTION naruv_bundle.command(p_bundle text,p_request text,p_action text,p_payload jsonb,p_confirm boolean,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; h naruv_bundle.headers; e naruv_bundle.events; prior naruv_bundle.events;
 x jsonb; rows jsonb; r jsonb; out_rows jsonb:='[]'::jsonb; idx int; ln int; cid text; rid text; bid text;
 kind text; cp text; mode text; target text; expected_action text; current_bill text; n int;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_bundle IS NULL OR p_bundle !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR p_action IS NULL OR p_action NOT IN ('open','fulfill','cancel','bill','pay','reverse')
 OR p_confirm IS DISTINCT FROM true OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
 OR octet_length(p_payload::text)>16384 THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO e FROM naruv_bundle.events z WHERE z.org_id=a.org_id AND z.request_id=p_request;
 IF FOUND THEN
  IF (e.bundle_id,e.actor_id,e.action,e.payload) IS DISTINCT FROM (p_bundle,a.actor_id,p_action,p_payload)
  THEN RAISE EXCEPTION 'BUNDLE_CONFLICT'; END IF;
  RETURN e.receipt;
 END IF;
 IF p_action='open' THEN
  IF p_payload-'lines'<>'{}'::jsonb OR jsonb_typeof(p_payload->'lines') IS DISTINCT FROM 'array'
  THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
  rows:=p_payload->'lines'; n:=jsonb_array_length(rows);
  IF n NOT BETWEEN 2 AND 20 THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
  IF EXISTS(SELECT 1 FROM naruv_bundle.headers z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle)
  THEN RAISE EXCEPTION 'BUNDLE_CONFLICT'; END IF;
  FOR x,idx IN SELECT value,ordinality::int FROM jsonb_array_elements(rows) WITH ORDINALITY LOOP
   cid:=naruv_bundle.child_id('document',p_bundle,idx); rid:=naruv_bundle.child_id('command',p_request,idx);
   r:=naruv_trade.command_bundle_internal(cid,rid,'open',x,true,p_csrf);
   IF idx=1 THEN
    kind:=r->>'kind';cp:=r->>'counterparty_id';mode:=r->>'vat_mode';
    INSERT INTO naruv_bundle.headers VALUES(a.org_id,p_bundle,a.actor_id,kind,cp,mode,clock_timestamp());
   ELSIF (kind,cp,mode) IS DISTINCT FROM (r->>'kind',r->>'counterparty_id',r->>'vat_mode') THEN
    RAISE EXCEPTION 'BUNDLE_MIXED_SCOPE';
   END IF;
   INSERT INTO naruv_bundle.lines VALUES(a.org_id,p_bundle,idx,cid);
   out_rows:=out_rows||jsonb_build_array(jsonb_build_object('line_no',idx,'result',r));
  END LOOP;
 ELSE
  SELECT * INTO h FROM naruv_bundle.headers z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle;
  IF NOT FOUND THEN RAISE EXCEPTION 'BUNDLE_NOT_FOUND'; END IF;
  IF p_action='cancel' THEN
   IF p_payload<>'{}'::jsonb THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
   FOR ln,cid IN SELECT z.line_no,z.doc_id FROM naruv_bundle.lines z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle ORDER BY z.line_no LOOP
    r:=naruv_trade.inspect(cid,p_csrf);
    IF r->>'state' IN ('OPEN','PARTIAL') THEN
     r:=naruv_trade.command_bundle_internal(cid,naruv_bundle.child_id('command',p_request,ln),'cancel','{}'::jsonb,true,p_csrf);
     out_rows:=out_rows||jsonb_build_array(jsonb_build_object('line_no',ln,'result',r));
    END IF;
   END LOOP;
   IF jsonb_array_length(out_rows)=0 THEN RAISE EXCEPTION 'BUNDLE_TERMINAL'; END IF;
  ELSIF p_action IN ('bill','reverse') THEN
   IF p_payload-'source_request_id'<>'{}'::jsonb OR jsonb_typeof(p_payload->'source_request_id') IS DISTINCT FROM 'string'
   THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
   target:=p_payload->>'source_request_id';
   expected_action:=CASE WHEN p_action='bill' THEN 'fulfill' ELSE 'pay' END;
   SELECT * INTO prior FROM naruv_bundle.events z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle AND z.request_id=target AND z.action=expected_action;
   IF NOT FOUND THEN RAISE EXCEPTION 'BUNDLE_NOT_FOUND'; END IF;
   FOR x IN SELECT value FROM jsonb_array_elements(prior.receipt->'lines') LOOP
    ln:=(x->>'line_no')::int;rid:=naruv_bundle.child_id('command',p_request,ln);
    IF p_action='bill' THEN
     SELECT z.doc_id INTO STRICT cid FROM naruv_bundle.lines z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle AND z.line_no=ln;
     bid:=naruv_bundle.child_id('bill',p_request,ln);
     r:=naruv_finance.command_bundle_internal(bid,rid,'bill',jsonb_build_object('doc_id',cid,'fulfillment_id',naruv_bundle.child_id('command',target,ln)),true,p_csrf);
    ELSE
     bid:=x->'result'->>'bill_id';
     r:=naruv_finance.command_bundle_internal(bid,rid,'reverse',jsonb_build_object('payment_request_id',naruv_bundle.child_id('command',target,ln)),true,p_csrf);
    END IF;
    out_rows:=out_rows||jsonb_build_array(jsonb_build_object('line_no',ln,'result',r));
   END LOOP;
  ELSE
   IF jsonb_typeof(p_payload->'lines') IS DISTINCT FROM 'array'
   OR (p_action='fulfill' AND p_payload-'lines'<>'{}'::jsonb)
   OR (p_action='pay' AND (p_payload-'lines'-'bill_request_id'<>'{}'::jsonb OR jsonb_typeof(p_payload->'bill_request_id') IS DISTINCT FROM 'string'))
   THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
   rows:=p_payload->'lines';n:=jsonb_array_length(rows);
   IF n NOT BETWEEN 1 AND 20 THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
   IF EXISTS(SELECT 1 FROM jsonb_array_elements(rows) z WHERE jsonb_typeof(z) IS DISTINCT FROM 'object'
    OR jsonb_typeof(z->'line_no') IS DISTINCT FROM 'number' OR (z->>'line_no') !~ '^([1-9]|1[0-9]|20)$')
   THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
   IF (SELECT count(DISTINCT z->>'line_no') FROM jsonb_array_elements(rows) z)<>n THEN RAISE EXCEPTION 'BUNDLE_INPUT'; END IF;
   IF p_action='pay' THEN
    target:=p_payload->>'bill_request_id';
    SELECT * INTO prior FROM naruv_bundle.events z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle AND z.request_id=target AND z.action='bill';
    IF NOT FOUND THEN RAISE EXCEPTION 'BUNDLE_NOT_FOUND'; END IF;
   END IF;
   FOR x IN SELECT value FROM jsonb_array_elements(rows) ORDER BY (value->>'line_no')::int LOOP
    ln:=(x->>'line_no')::int;rid:=naruv_bundle.child_id('command',p_request,ln);
    SELECT z.doc_id INTO cid FROM naruv_bundle.lines z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle AND z.line_no=ln;
    IF NOT FOUND THEN RAISE EXCEPTION 'BUNDLE_NOT_FOUND'; END IF;
    IF p_action='fulfill' THEN
     r:=naruv_trade.command_bundle_internal(cid,rid,'fulfill',x-'line_no',true,p_csrf);
    ELSE
     SELECT z->'result'->>'bill_id' INTO current_bill FROM jsonb_array_elements(prior.receipt->'lines') z WHERE (z->>'line_no')::int=ln;
     IF NOT FOUND THEN RAISE EXCEPTION 'BUNDLE_NOT_FOUND'; END IF;
     r:=naruv_finance.command_bundle_internal(current_bill,rid,'pay',x-'line_no',true,p_csrf);
    END IF;
    out_rows:=out_rows||jsonb_build_array(jsonb_build_object('line_no',ln,'result',r));
   END LOOP;
  END IF;
 END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 r:=jsonb_build_object('bundle_id',p_bundle,'request_id',p_request,'action',p_action,'lines',out_rows,'production_authorized',false);
 INSERT INTO naruv_bundle.events VALUES(a.org_id,p_request,p_bundle,a.actor_id,p_action,p_payload,r,clock_timestamp());
 RETURN r;
END $$;
CREATE FUNCTION naruv_bundle.inspect(p_bundle text,p_csrf text) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; h naruv_bundle.headers; rows jsonb;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO h FROM naruv_bundle.headers z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle;
 IF NOT FOUND THEN RAISE EXCEPTION 'BUNDLE_NOT_FOUND'; END IF;
 SELECT jsonb_agg(jsonb_build_object('line_no',z.line_no,'result',naruv_trade.inspect(z.doc_id,p_csrf)) ORDER BY z.line_no)
 INTO rows FROM naruv_bundle.lines z WHERE z.org_id=a.org_id AND z.bundle_id=p_bundle;
 RETURN jsonb_build_object('bundle_id',p_bundle,'kind',h.kind,'counterparty_id',h.counterparty_id,'lines',rows,'production_authorized',false);
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA naruv_bundle FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_bundle.command(text,text,text,jsonb,boolean,text),naruv_bundle.inspect(text,text) TO jw_app_dev;
RESET ROLE;
