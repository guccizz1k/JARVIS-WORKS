-- Fresh disposable PG17 only. Requires native file preview CI source registry.
-- Native session role separation; no live ERP tables or production activation.
DO $$ BEGIN
 IF current_database() <> 'postgres' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user <> 'postgres' OR current_setting('naruv.native_write_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'NARUV_WRITE_DISPOSABLE_ONLY'; END IF;
END $$;
CREATE ROLE naruv_native_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
CREATE ROLE naruv_native_stage NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
CREATE SCHEMA naruv_native_review AUTHORIZATION naruv_native_owner;
REVOKE ALL ON SCHEMA naruv_native_review FROM PUBLIC;
GRANT USAGE ON SCHEMA naruv_native_review TO jw_app_dev,naruv_native_stage;
GRANT USAGE ON SCHEMA jw_dev TO naruv_native_owner,naruv_native_stage;
GRANT EXECUTE ON FUNCTION jw_dev.stage_identity_v84() TO naruv_native_owner,naruv_native_stage;
GRANT EXECUTE ON FUNCTION jw_dev.current_org_from_session() TO naruv_native_owner;
GRANT SELECT,UPDATE(revision,existing_ids) ON jw_dev.naruv_review_sources TO naruv_native_owner;
CREATE POLICY naruv_native_owner_source ON jw_dev.naruv_review_sources TO naruv_native_owner
 USING(org_id=jw_dev.current_org_from_session() AND EXISTS(
   SELECT 1 FROM jw_dev.stage_identity_v84() i WHERE i.org_id=naruv_review_sources.org_id AND i.actor_role='admin'))
 WITH CHECK(org_id=jw_dev.current_org_from_session() AND EXISTS(
   SELECT 1 FROM jw_dev.stage_identity_v84() i WHERE i.org_id=naruv_review_sources.org_id AND i.actor_role='admin'));
-- Disposable auth fence; not a migration for any persistent database.
CREATE ROLE naruv_auth_fence_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
CREATE SCHEMA naruv_auth_fence AUTHORIZATION naruv_auth_fence_owner;
REVOKE ALL ON SCHEMA naruv_auth_fence FROM PUBLIC;
GRANT USAGE ON SCHEMA naruv_auth_fence TO naruv_native_owner;
SET ROLE naruv_auth_fence_owner;
CREATE TABLE naruv_auth_fence.epochs(actor_id text PRIMARY KEY, epoch bigint NOT NULL CHECK(epoch>=0));
ALTER TABLE naruv_auth_fence.epochs ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_auth_fence.epochs FORCE ROW LEVEL SECURITY;
CREATE POLICY fence_internal ON naruv_auth_fence.epochs TO naruv_auth_fence_owner USING(true) WITH CHECK(true);
REVOKE ALL ON naruv_auth_fence.epochs FROM PUBLIC;
CREATE FUNCTION naruv_auth_fence.lock_actor(p_actor text)
 RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE generation bigint;
BEGIN
 IF p_actor IS NULL OR p_actor='' OR current_setting('transaction_isolation') <> 'read committed'
 THEN RAISE EXCEPTION 'NARUV_AUTH_FENCE_UNSAFE' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-native-auth-v1:'||p_actor,0));
 SELECT e.epoch INTO generation FROM naruv_auth_fence.epochs e WHERE e.actor_id=p_actor;
 RETURN coalesce(generation,0);
END $$;
CREATE FUNCTION naruv_auth_fence.auth_change()
 RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old_actor text; new_actor text; actor text; bump boolean:=true;
BEGIN
 IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'NARUV_AUTH_TRUNCATE_DENIED'; END IF;
 IF TG_TABLE_NAME='users' THEN
  IF TG_OP<>'INSERT' THEN old_actor:=OLD.id; END IF;
  IF TG_OP<>'DELETE' THEN new_actor:=NEW.id; END IF;
  IF TG_OP='UPDATE' THEN
   IF (OLD.id,OLD.org_id,OLD.role) IS NOT DISTINCT FROM (NEW.id,NEW.org_id,NEW.role)
   THEN RETURN NEW; END IF;
  END IF;
 ELSE
  IF TG_OP<>'INSERT' THEN old_actor:=OLD.user_id; END IF;
  IF TG_OP<>'DELETE' THEN new_actor:=NEW.user_id; END IF;
  IF TG_TABLE_NAME='sessions' THEN
   IF TG_OP='INSERT' THEN bump:=false; END IF;
   IF TG_OP='UPDATE' THEN
    IF (OLD.id,OLD.user_id,OLD.token_hash,OLD.csrf_token,OLD.expires_at)
       IS NOT DISTINCT FROM (NEW.id,NEW.user_id,NEW.token_hash,NEW.csrf_token,NEW.expires_at)
    THEN RETURN NEW; END IF;
   END IF;
  END IF;
 END IF;
 FOR actor IN SELECT DISTINCT x FROM unnest(ARRAY[old_actor,new_actor]) x WHERE x IS NOT NULL ORDER BY x LOOP
  PERFORM naruv_auth_fence.lock_actor(actor);
  IF bump THEN
   INSERT INTO naruv_auth_fence.epochs AS e VALUES(actor,1)
   ON CONFLICT(actor_id) DO UPDATE SET epoch=e.epoch+1;
  END IF;
 END LOOP;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA naruv_auth_fence FROM PUBLIC;
GRANT EXECUTE ON FUNCTION naruv_auth_fence.lock_actor(text) TO naruv_native_owner;
RESET ROLE;
CREATE TRIGGER naruv_fence_users BEFORE INSERT OR UPDATE OR DELETE ON jw_dev.users
 FOR EACH ROW EXECUTE FUNCTION naruv_auth_fence.auth_change();
CREATE TRIGGER naruv_fence_sessions BEFORE INSERT OR UPDATE OR DELETE ON jw_dev.sessions
 FOR EACH ROW EXECUTE FUNCTION naruv_auth_fence.auth_change();
CREATE TRIGGER naruv_fence_disabled BEFORE INSERT OR UPDATE OR DELETE ON jw_dev.staff_disabled
 FOR EACH ROW EXECUTE FUNCTION naruv_auth_fence.auth_change();
CREATE TRIGGER naruv_fence_users_truncate BEFORE TRUNCATE ON jw_dev.users
 FOR EACH STATEMENT EXECUTE FUNCTION naruv_auth_fence.auth_change();
CREATE TRIGGER naruv_fence_sessions_truncate BEFORE TRUNCATE ON jw_dev.sessions
 FOR EACH STATEMENT EXECUTE FUNCTION naruv_auth_fence.auth_change();
CREATE TRIGGER naruv_fence_disabled_truncate BEFORE TRUNCATE ON jw_dev.staff_disabled
 FOR EACH STATEMENT EXECUTE FUNCTION naruv_auth_fence.auth_change();
SET ROLE naruv_native_owner;
CREATE TABLE naruv_native_review.stages(
 org_id text NOT NULL, stage_id text NOT NULL CHECK(stage_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 actor_id text NOT NULL, session_binding_sha256 text NOT NULL CHECK(session_binding_sha256 ~ '^[a-f0-9]{64}$'),
 auth_epoch bigint NOT NULL CHECK(auth_epoch>=0),
 source_id text NOT NULL, entity text NOT NULL CHECK(entity IN ('item','customer')),
 file_format text NOT NULL CHECK(file_format IN ('csv','xlsx')),
 raw_sha256 text NOT NULL CHECK(raw_sha256 ~ '^[a-f0-9]{64}$'),
 byte_count integer NOT NULL CHECK(byte_count BETWEEN 1 AND 1048576),
 stage_sha256 text NOT NULL CHECK(stage_sha256 ~ '^[a-f0-9]{64}$'),
 canonical_sha256 text NOT NULL CHECK(canonical_sha256 ~ '^[a-f0-9]{64}$'),
 rows_sha256 text NOT NULL CHECK(rows_sha256 ~ '^[a-f0-9]{64}$'),
 snapshot_sha256 text NOT NULL CHECK(snapshot_sha256 ~ '^[a-f0-9]{64}$'),
 expected_revision text NOT NULL, expected_ids text[] NOT NULL CHECK(cardinality(expected_ids)<=10000),
 rows_canonical text NOT NULL CHECK(octet_length(rows_canonical)<=2097152 AND canonical_sha256=encode(sha256(convert_to(rows_canonical,'UTF8')),'hex') AND jsonb_typeof(rows_canonical::jsonb)='array' AND jsonb_array_length(rows_canonical::jsonb) BETWEEN 1 AND 1000),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 PRIMARY KEY(org_id,stage_id)
);
CREATE TABLE naruv_native_review.approvals(
 org_id text NOT NULL, stage_id text NOT NULL, actor_id text NOT NULL,
 stage_sha256 text NOT NULL CHECK(stage_sha256 ~ '^[a-f0-9]{64}$'),
 canonical_sha256 text NOT NULL CHECK(canonical_sha256 ~ '^[a-f0-9]{64}$'),
 snapshot_sha256 text NOT NULL CHECK(snapshot_sha256 ~ '^[a-f0-9]{64}$'),
 status text NOT NULL CHECK(status IN ('APPROVED','REVOKED','COMMITTED')),
 approved_at timestamptz NOT NULL, expires_at timestamptz NOT NULL CHECK(expires_at>approved_at),
 PRIMARY KEY(org_id,stage_id),
 FOREIGN KEY(org_id,stage_id) REFERENCES naruv_native_review.stages(org_id,stage_id)
);
CREATE TABLE naruv_native_review.records(
 org_id text NOT NULL, source_id text NOT NULL, entity text NOT NULL CHECK(entity IN ('item','customer')),
 source_record_id text NOT NULL CHECK(source_record_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 normalized_id text GENERATED ALWAYS AS(lower(source_record_id COLLATE "C")) STORED,
 stage_id text NOT NULL, data jsonb NOT NULL CHECK(jsonb_typeof(data)='object'),
 PRIMARY KEY(org_id,source_id,entity,normalized_id),
 FOREIGN KEY(org_id,stage_id) REFERENCES naruv_native_review.stages(org_id,stage_id)
);
CREATE TABLE naruv_native_review.receipts(
 org_id text NOT NULL, stage_id text NOT NULL, actor_id text NOT NULL,
 reservation_id text NOT NULL CHECK(reservation_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 stage_sha256 text NOT NULL CHECK(stage_sha256 ~ '^[a-f0-9]{64}$'),
 canonical_sha256 text NOT NULL CHECK(canonical_sha256 ~ '^[a-f0-9]{64}$'),
 snapshot_sha256 text NOT NULL CHECK(snapshot_sha256 ~ '^[a-f0-9]{64}$'),
 raw_sha256 text NOT NULL CHECK(raw_sha256 ~ '^[a-f0-9]{64}$'),
 rows_sha256 text NOT NULL CHECK(rows_sha256 ~ '^[a-f0-9]{64}$'),
 row_count integer NOT NULL CHECK(row_count BETWEEN 1 AND 1000),
 completed_at timestamptz NOT NULL,
 PRIMARY KEY(org_id,stage_id), UNIQUE(org_id,reservation_id),
 FOREIGN KEY(org_id,stage_id) REFERENCES naruv_native_review.approvals(org_id,stage_id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['stages','approvals','records','receipts'] LOOP
  EXECUTE format('ALTER TABLE naruv_native_review.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE naruv_native_review.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY native_owner_scope ON naruv_native_review.%I TO naruv_native_owner USING (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin'')) WITH CHECK (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin''))',t);
  EXECUTE format('REVOKE ALL ON naruv_native_review.%I FROM PUBLIC,jw_app_dev,naruv_native_stage',t);
 END LOOP;
END $$;
CREATE FUNCTION naruv_native_review.guard(p_csrf text,p_kind text)
 RETURNS TABLE(actor_id text,org_id text,session_binding_sha256 text,auth_epoch bigint)
 LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
DECLARE a record; fresh record; generation bigint; h text; login record; business boolean; stage boolean;
BEGIN
 h:=current_setting('jw.session_hash',true);
 SELECT r.rolsuper,r.rolbypassrls,r.rolcreaterole,r.rolcreatedb INTO login FROM pg_catalog.pg_roles r WHERE r.rolname=session_user;
 IF NOT FOUND OR login.rolsuper OR login.rolbypassrls OR login.rolcreaterole OR login.rolcreatedb
 OR session_user IN ('postgres','supabase_admin','service_role','naruv_native_owner','naruv_native_stage','jw_app_dev','jw_auth_stage_v85')
 OR pg_has_role(session_user,'naruv_native_owner','MEMBER') OR pg_has_role(session_user,'jw_auth_stage_v85','MEMBER')
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 business:=pg_has_role(session_user,'jw_app_dev','MEMBER');
 stage:=pg_has_role(session_user,'naruv_native_stage','MEMBER');
 IF p_kind IS NULL OR p_kind NOT IN ('stage','business')
 OR (p_kind='stage' AND (NOT stage OR business)) OR (p_kind='business' AND (NOT business OR stage))
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT i.actor_id,i.org_id,i.actor_role,i.csrf_token INTO a FROM jw_dev.stage_identity_v84() i;
 IF NOT FOUND OR a.actor_id IS NULL OR a.org_id IS NULL OR a.actor_role IS DISTINCT FROM 'admin'
 OR h IS NULL OR h !~ '^[a-f0-9]{64}$'
 OR p_csrf IS NULL OR length(p_csrf) NOT BETWEEN 1 AND 512 OR p_csrf IS DISTINCT FROM a.csrf_token
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 generation:=naruv_auth_fence.lock_actor(a.actor_id);
 SELECT i.actor_id,i.org_id,i.actor_role,i.csrf_token INTO fresh FROM jw_dev.stage_identity_v84() i;
 IF NOT FOUND OR (fresh.actor_id,fresh.org_id,fresh.actor_role,fresh.csrf_token)
 IS DISTINCT FROM (a.actor_id,a.org_id,a.actor_role,a.csrf_token)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT a.actor_id,a.org_id,encode(sha256(convert_to('naruv-native-session-v1:'||h,'UTF8')),'hex'),generation;
END $$;
CREATE FUNCTION naruv_native_review.immutable()
 RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'NARUV_IMMUTABLE'; END $$;
CREATE TRIGGER stage_immutable BEFORE UPDATE OR DELETE ON naruv_native_review.stages
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE TRIGGER receipt_immutable BEFORE UPDATE OR DELETE ON naruv_native_review.receipts
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE FUNCTION naruv_native_review.validated_ids(p_entity text,p_rows jsonb,p_existing text[])
 RETURNS text[] LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE v jsonb; id_key text; opt_key text; code text; seen text[]:=ARRAY[]::text[]; added text[]:=ARRAY[]::text[];
BEGIN
 IF p_entity NOT IN ('item','customer') OR p_entity IS NULL OR p_existing IS NULL OR cardinality(p_existing)>10000
 OR array_position(p_existing,NULL) IS NOT NULL OR jsonb_typeof(p_rows) IS DISTINCT FROM 'array'
 THEN RAISE EXCEPTION 'NARUV_ROWS_INVALID'; END IF;
 IF jsonb_array_length(p_rows) NOT BETWEEN 1 AND 1000 OR octet_length(p_rows::text)>2097152
 THEN RAISE EXCEPTION 'NARUV_ROWS_INVALID'; END IF;
 IF cardinality(p_existing)+jsonb_array_length(p_rows)>10000 THEN RAISE EXCEPTION 'NARUV_CAPACITY'; END IF;
 FOREACH code IN ARRAY p_existing LOOP
  IF code !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR lower(code COLLATE "C")=ANY(seen)
  THEN RAISE EXCEPTION 'NARUV_TARGET_INVALID'; END IF;
  seen:=array_append(seen,lower(code COLLATE "C"));
 END LOOP;
 id_key:=CASE WHEN p_entity='item' THEN 'source_item_id' ELSE 'source_customer_id' END;
 opt_key:=CASE WHEN p_entity='item' THEN 'unit' ELSE 'business_number' END;
 FOR v IN SELECT value FROM jsonb_array_elements(p_rows) LOOP
  IF jsonb_typeof(v) IS DISTINCT FROM 'object' OR jsonb_typeof(v->id_key) IS DISTINCT FROM 'string'
  OR jsonb_typeof(v->'name') IS DISTINCT FROM 'string' OR v-id_key-'name'-opt_key <> '{}'::jsonb
  OR (v ? opt_key AND jsonb_typeof(v->opt_key) IS DISTINCT FROM 'string')
  OR length(v->>'name') NOT BETWEEN 1 AND 120 OR v->>'name' <> btrim(v->>'name')
  OR left(v->>'name',1) IN ('=','+','-','@')
  OR (p_entity='item' AND length(v->>opt_key)>32)
  OR (p_entity='customer' AND v->>opt_key<>'' AND v->>opt_key !~ '^([0-9]{10}|[0-9]{3}-[0-9]{2}-[0-9]{5})$')
  THEN RAISE EXCEPTION 'NARUV_ROWS_INVALID'; END IF;
  code:=v->>id_key;
  IF code !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR lower(code COLLATE "C")=ANY(seen)
  THEN RAISE EXCEPTION 'NARUV_DUPLICATE_ID'; END IF;
  seen:=array_append(seen,lower(code COLLATE "C")); added:=array_append(added,code);
 END LOOP;
 RETURN added;
END $$;
-- Match Python make_target_snapshot canonical UTF-8 encoding for bounded ASCII IDs.
CREATE FUNCTION naruv_native_review.target_digest(p_org text,p_source text,p_entity text,p_rev text,p_ids text[])
 RETURNS text LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT encode(sha256(convert_to('{"entity":'||to_json(p_entity)::text||',"existing_source_ids":'||array_to_json(p_ids)::text||
 ',"organization_id":'||to_json(p_org)::text||',"revision":'||to_json(p_rev)::text||
 ',"source_id":'||to_json(p_source)::text||',"version":1}','UTF8')),'hex')
$$;
CREATE FUNCTION naruv_native_review.read_source(p_source text,p_entity text,p_csrf text)
 RETURNS TABLE(revision text,existing_ids text[])
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'stage');
 RETURN QUERY SELECT s.revision,ARRAY(SELECT x FROM unnest(s.existing_ids) x ORDER BY x COLLATE "C")
 FROM jw_dev.naruv_review_sources s WHERE s.org_id=a.org_id AND s.source_id=p_source AND s.entity=p_entity AND s.active;
END $$;
CREATE FUNCTION naruv_native_review.store_stage(p_id text,p_source text,p_entity text,p_format text,
 p_raw text,p_bytes integer,p_digest text,p_canonical text,p_rows_sha text,p_snapshot text,p_revision text,
 p_expected text[],p_rows_text text,p_csrf text)
 RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; target record; old naruv_native_review.stages; stamp timestamptz;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'stage');
 IF p_id IS NULL OR p_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR p_format IS NULL OR p_format NOT IN ('csv','xlsx')
 OR p_raw IS NULL OR p_raw !~ '^[a-f0-9]{64}$' OR p_digest IS NULL OR p_digest !~ '^[a-f0-9]{64}$'
 OR p_canonical IS NULL OR p_canonical !~ '^[a-f0-9]{64}$'
 OR p_rows_text IS NULL OR octet_length(p_rows_text)>2097152 OR p_canonical IS DISTINCT FROM encode(sha256(convert_to(p_rows_text,'UTF8')),'hex')
 OR p_rows_sha IS NULL OR p_rows_sha !~ '^[a-f0-9]{64}$' OR p_snapshot IS NULL OR p_snapshot !~ '^[a-f0-9]{64}$'
 OR p_bytes IS NULL OR p_bytes NOT BETWEEN 1 AND 1048576
 THEN RAISE EXCEPTION 'NARUV_STAGE_INPUT'; END IF;
 -- Tenant quota lock precedes the source lock.
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-native-quota-v1:'||a.org_id,0));
 -- Serialize all writes for a tenant/source/entity. Target is never browser authority.
 SELECT s.revision,s.existing_ids INTO target FROM jw_dev.naruv_review_sources s
 WHERE s.org_id=a.org_id AND s.source_id=p_source AND s.entity=p_entity AND s.active FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_SOURCE_NOT_FOUND'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'stage');
 IF (a.actor_id,a.org_id,a.session_binding_sha256,a.auth_epoch) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.session_binding_sha256,a2.auth_epoch) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED'; END IF;
 IF target.revision IS DISTINCT FROM p_revision OR
 ARRAY(SELECT x FROM unnest(target.existing_ids) x ORDER BY x COLLATE "C") IS DISTINCT FROM p_expected
 THEN RAISE EXCEPTION 'NARUV_TARGET_CHANGED'; END IF;
 IF p_snapshot IS DISTINCT FROM naruv_native_review.target_digest(a.org_id,p_source,p_entity,p_revision,p_expected) THEN RAISE EXCEPTION 'NARUV_TARGET_CHANGED'; END IF;
 PERFORM naruv_native_review.validated_ids(p_entity,p_rows_text::jsonb,p_expected);
 SELECT * INTO old FROM naruv_native_review.stages s WHERE s.org_id=a.org_id AND s.stage_id=p_id;
 stamp:=clock_timestamp();
 IF FOUND THEN
  IF (old.actor_id,old.session_binding_sha256,old.auth_epoch,old.source_id,old.entity,old.file_format,old.raw_sha256,old.byte_count,old.stage_sha256,old.canonical_sha256,old.rows_sha256,
      old.snapshot_sha256,old.expected_revision,old.expected_ids,old.rows_canonical)
  IS DISTINCT FROM (a.actor_id,a.session_binding_sha256,a.auth_epoch,p_source,p_entity,p_format,p_raw,p_bytes,p_digest,p_canonical,p_rows_sha,p_snapshot,p_revision,p_expected,p_rows_text)
  THEN RAISE EXCEPTION 'NARUV_STAGE_CONFLICT'; END IF;
  IF stamp<old.created_at OR stamp>=old.expires_at THEN RAISE EXCEPTION 'NARUV_STAGE_EXPIRED'; END IF;
  RETURN 'ALREADY_STAGED';
 END IF;
 -- Logical UTF-8 payload budget, not physical disk usage. No automatic purge.
 IF (SELECT count(*) FROM naruv_native_review.stages s WHERE s.org_id=a.org_id)>=128
 OR (SELECT coalesce(sum(octet_length(s.rows_canonical)::bigint+octet_length(array_to_json(s.expected_ids)::text)),0)
     FROM naruv_native_review.stages s WHERE s.org_id=a.org_id)
      +octet_length(p_rows_text)+octet_length(array_to_json(p_expected)::text)>16777216
 THEN RAISE EXCEPTION 'NARUV_CAPACITY'; END IF;
 INSERT INTO naruv_native_review.stages VALUES(a.org_id,p_id,a.actor_id,a.session_binding_sha256,a.auth_epoch,p_source,p_entity,p_format,p_raw,p_bytes,p_digest,p_canonical,p_rows_sha,
  p_snapshot,p_revision,p_expected,p_rows_text,stamp,stamp+interval '15 minutes');
 RETURN 'STAGED';
END $$;
CREATE FUNCTION naruv_native_review.approve(p_id text,p_digest text,p_canonical text,p_snapshot text,p_confirmed boolean,p_csrf text)
 RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; s naruv_native_review.stages; old naruv_native_review.approvals; target record; stamp timestamptz;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_confirmed IS DISTINCT FROM true THEN RAISE EXCEPTION 'NARUV_CONFIRM_REQUIRED'; END IF;
 SELECT * INTO s FROM naruv_native_review.stages t WHERE t.org_id=a.org_id AND t.stage_id=p_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_STAGE_MISSING'; END IF;
 IF (s.actor_id,s.session_binding_sha256,s.auth_epoch,s.stage_sha256,s.canonical_sha256,s.snapshot_sha256) IS DISTINCT FROM (a.actor_id,a.session_binding_sha256,a.auth_epoch,p_digest,p_canonical,p_snapshot) THEN RAISE EXCEPTION 'NARUV_BINDING_CHANGED'; END IF;
 SELECT t.revision,t.existing_ids INTO target FROM jw_dev.naruv_review_sources t
 WHERE t.org_id=a.org_id AND t.source_id=s.source_id AND t.entity=s.entity AND t.active FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_SOURCE_NOT_FOUND'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.session_binding_sha256,a.auth_epoch) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.session_binding_sha256,a2.auth_epoch) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED'; END IF;
 IF target.revision IS DISTINCT FROM s.expected_revision OR ARRAY(SELECT x FROM unnest(target.existing_ids) x ORDER BY x COLLATE "C") IS DISTINCT FROM s.expected_ids
 THEN RAISE EXCEPTION 'NARUV_TARGET_CHANGED'; END IF;
 stamp:=clock_timestamp();
 IF stamp<s.created_at OR stamp>=s.expires_at THEN RAISE EXCEPTION 'NARUV_STAGE_EXPIRED'; END IF;
 SELECT * INTO old FROM naruv_native_review.approvals t WHERE t.org_id=a.org_id AND t.stage_id=p_id FOR UPDATE;
 IF FOUND THEN
  IF old.status<>'APPROVED' OR stamp<old.approved_at OR stamp>=old.expires_at THEN RAISE EXCEPTION 'NARUV_APPROVAL_TERMINAL'; END IF;
  IF (old.actor_id,old.stage_sha256,old.canonical_sha256,old.snapshot_sha256) IS DISTINCT FROM (a.actor_id,p_digest,p_canonical,p_snapshot) THEN RAISE EXCEPTION 'NARUV_BINDING_CHANGED'; END IF;
  RETURN 'ALREADY_APPROVED';
 END IF;
 INSERT INTO naruv_native_review.approvals VALUES(a.org_id,p_id,a.actor_id,p_digest,p_canonical,p_snapshot,'APPROVED',stamp,s.expires_at);
 RETURN 'APPROVED';
END $$;
CREATE FUNCTION naruv_native_review.revoke(p_id text,p_digest text,p_canonical text,p_snapshot text,p_csrf text)
 RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; old naruv_native_review.approvals;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 SELECT * INTO old FROM naruv_native_review.approvals t WHERE t.org_id=a.org_id AND t.stage_id=p_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_STAGE_MISSING'; END IF;
 IF (old.actor_id,old.stage_sha256,old.canonical_sha256,old.snapshot_sha256) IS DISTINCT FROM (a.actor_id,p_digest,p_canonical,p_snapshot) THEN RAISE EXCEPTION 'NARUV_BINDING_CHANGED'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.session_binding_sha256,a.auth_epoch) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.session_binding_sha256,a2.auth_epoch) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED'; END IF;
 IF old.status='REVOKED' THEN RETURN 'ALREADY_REVOKED'; END IF;
 IF old.status<>'APPROVED' THEN RAISE EXCEPTION 'NARUV_APPROVAL_TERMINAL'; END IF;
 UPDATE naruv_native_review.approvals t SET status='REVOKED' WHERE t.org_id=a.org_id AND t.stage_id=p_id;
 RETURN 'REVOKED';
END $$;
CREATE FUNCTION naruv_native_review.receipt_json(r naruv_native_review.receipts)
 RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('status','REVIEW_COMMITTED','stage_id',($1).stage_id,'reservation_id',($1).reservation_id,
 'stage_sha256',($1).stage_sha256,'canonical_rows_sha256',($1).canonical_sha256,'target_snapshot_sha256',($1).snapshot_sha256,'raw_sha256',($1).raw_sha256,'rows_sha256',($1).rows_sha256,'row_count',($1).row_count,
 'row_import_authorized',false)
$$;
CREATE FUNCTION naruv_native_review.commit_stage(p_id text,p_digest text,p_canonical text,p_snapshot text,p_reservation text,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; s naruv_native_review.stages; ap naruv_native_review.approvals;
 r naruv_native_review.receipts; target record; new_ids text[]; v jsonb; id_key text; new_revision text;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_reservation IS NULL OR p_reservation !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' THEN RAISE EXCEPTION 'NARUV_STAGE_INPUT'; END IF;
 SELECT * INTO s FROM naruv_native_review.stages t WHERE t.org_id=a.org_id AND t.stage_id=p_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_STAGE_MISSING'; END IF;
 IF (s.actor_id,s.session_binding_sha256,s.auth_epoch,s.stage_sha256,s.canonical_sha256,s.snapshot_sha256) IS DISTINCT FROM (a.actor_id,a.session_binding_sha256,a.auth_epoch,p_digest,p_canonical,p_snapshot) THEN RAISE EXCEPTION 'NARUV_BINDING_CHANGED'; END IF;
 -- A committed receipt can be recovered even though the target revision advanced.
 SELECT * INTO r FROM naruv_native_review.receipts t WHERE t.org_id=a.org_id AND t.stage_id=p_id;
 IF FOUND THEN
  IF (r.reservation_id,r.actor_id,r.stage_sha256) IS DISTINCT FROM (p_reservation,a.actor_id,p_digest)
  THEN RAISE EXCEPTION 'NARUV_RESERVATION_CONFLICT'; END IF;
  RETURN naruv_native_review.receipt_json(r);
 END IF;
 SELECT t.revision,t.existing_ids,t.active INTO target FROM jw_dev.naruv_review_sources t
 WHERE t.org_id=a.org_id AND t.source_id=s.source_id AND t.entity=s.entity FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_SOURCE_NOT_FOUND'; END IF;
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.session_binding_sha256,a.auth_epoch) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.session_binding_sha256,a2.auth_epoch) THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED'; END IF;
 -- Check receipt again after serialization for concurrent same-request retry.
 SELECT * INTO r FROM naruv_native_review.receipts t WHERE t.org_id=a.org_id AND t.stage_id=p_id;
 IF FOUND THEN
  IF (r.reservation_id,r.actor_id,r.stage_sha256) IS DISTINCT FROM (p_reservation,a.actor_id,p_digest)
  THEN RAISE EXCEPTION 'NARUV_RESERVATION_CONFLICT'; END IF;
  RETURN naruv_native_review.receipt_json(r);
 END IF;
 IF NOT target.active THEN RAISE EXCEPTION 'NARUV_SOURCE_NOT_FOUND'; END IF;
 SELECT * INTO ap FROM naruv_native_review.approvals t WHERE t.org_id=a.org_id AND t.stage_id=p_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_APPROVAL_REQUIRED'; END IF;
 IF (ap.actor_id,ap.stage_sha256,ap.canonical_sha256,ap.snapshot_sha256) IS DISTINCT FROM (a.actor_id,p_digest,p_canonical,p_snapshot) THEN RAISE EXCEPTION 'NARUV_BINDING_CHANGED'; END IF;
 IF ap.status<>'APPROVED' OR clock_timestamp()<ap.approved_at OR clock_timestamp()<s.created_at OR clock_timestamp()>=ap.expires_at OR clock_timestamp()>=s.expires_at
 THEN RAISE EXCEPTION 'NARUV_APPROVAL_TERMINAL'; END IF;
 IF target.revision IS DISTINCT FROM s.expected_revision OR ARRAY(SELECT x FROM unnest(target.existing_ids) x ORDER BY x COLLATE "C") IS DISTINCT FROM s.expected_ids
 THEN RAISE EXCEPTION 'NARUV_TARGET_CHANGED'; END IF;
 new_ids:=naruv_native_review.validated_ids(s.entity,s.rows_canonical::jsonb,s.expected_ids);
 id_key:=CASE WHEN s.entity='item' THEN 'source_item_id' ELSE 'source_customer_id' END;
 FOR v IN SELECT value FROM jsonb_array_elements(s.rows_canonical::jsonb) LOOP
  INSERT INTO naruv_native_review.records(org_id,source_id,entity,source_record_id,stage_id,data)
  VALUES(a.org_id,s.source_id,s.entity,v->>id_key,p_id,v);
 END LOOP;
 new_revision:='rev-'||encode(sha256(convert_to(s.expected_revision||':'||s.stage_sha256,'UTF8')),'hex');
 UPDATE jw_dev.naruv_review_sources t SET revision=new_revision,
 existing_ids=ARRAY(SELECT x FROM unnest(s.expected_ids||new_ids) x ORDER BY x COLLATE "C")
 WHERE t.org_id=a.org_id AND t.source_id=s.source_id AND t.entity=s.entity;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_TARGET_CHANGED'; END IF;
 -- Recheck after all record writes and target update, before durable receipt.
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.session_binding_sha256,a.auth_epoch)
 IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.session_binding_sha256,a2.auth_epoch)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 IF clock_timestamp()<ap.approved_at OR clock_timestamp()<s.created_at
 OR clock_timestamp()>=ap.expires_at OR clock_timestamp()>=s.expires_at
 THEN RAISE EXCEPTION 'NARUV_APPROVAL_TERMINAL'; END IF;
 INSERT INTO naruv_native_review.receipts VALUES(a.org_id,p_id,a.actor_id,p_reservation,p_digest,p_canonical,p_snapshot,s.raw_sha256,s.rows_sha256,
 cardinality(new_ids),clock_timestamp()) RETURNING * INTO r;
 UPDATE naruv_native_review.approvals t SET status='COMMITTED' WHERE t.org_id=a.org_id AND t.stage_id=p_id;
 RETURN naruv_native_review.receipt_json(r);
END $$;
CREATE FUNCTION naruv_native_review.inspect(p_id text,p_reservation text,p_csrf text)
 RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; r naruv_native_review.receipts;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 SELECT * INTO r FROM naruv_native_review.receipts t WHERE t.org_id=a.org_id AND t.stage_id=p_id AND t.actor_id=a.actor_id AND t.reservation_id=p_reservation;
 IF NOT FOUND THEN RAISE EXCEPTION 'NARUV_STAGE_MISSING'; END IF;
 RETURN naruv_native_review.receipt_json(r);
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA naruv_native_review FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_native_review.read_source(text,text,text),
 naruv_native_review.store_stage(text,text,text,text,text,integer,text,text,text,text,text,text[],text,text) TO naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_native_review.approve(text,text,text,text,boolean,text),naruv_native_review.revoke(text,text,text,text,text),
 naruv_native_review.commit_stage(text,text,text,text,text,text),naruv_native_review.inspect(text,text,text) TO jw_app_dev;
RESET ROLE;
