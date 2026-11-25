-- CI-only WORKS customer integration: existing V92 fixture tables, no live migration.
DO $$ BEGIN
 IF current_database() <> 'postgres' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user <> 'postgres' OR current_setting('naruv.customer_bridge_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'NARUV_CUSTOMER_BRIDGE_DISPOSABLE_ONLY'; END IF;
END $$;
-- Conservative review policy: no automatic merge or update. Exact normalized
-- business number or name collisions reject the entire import. These indexes
-- intentionally cover existing manual writers in the disposable fixture.
CREATE UNIQUE INDEX naruv_ci_customer_name_key ON jw_dev.customers(org_id,lower(btrim(name) COLLATE "C"));
CREATE UNIQUE INDEX naruv_ci_customer_business_key ON jw_dev.customers(org_id,replace(btrim(business_number),'-',''))
 WHERE btrim(business_number)<>'';
CREATE UNIQUE INDEX naruv_ci_customer_tenant_id ON jw_dev.customers(org_id,id);
GRANT INSERT(id,org_id,name,business_number,contact_name,email,phone,created_at),REFERENCES(org_id,id)
 ON jw_dev.customers TO naruv_native_owner;
GRANT INSERT(id,org_id,actor_id,entity_type,entity_id,action,detail,created_at)
 ON jw_dev.audit_logs TO naruv_native_owner;
CREATE POLICY naruv_ci_customer_insert ON jw_dev.customers FOR INSERT TO naruv_native_owner
 WITH CHECK(org_id=jw_dev.current_org_from_session() AND EXISTS(
 SELECT 1 FROM jw_dev.stage_identity_v84() i WHERE i.org_id=customers.org_id AND i.actor_role='admin'));
CREATE POLICY naruv_ci_customer_audit ON jw_dev.audit_logs FOR INSERT TO naruv_native_owner
 WITH CHECK(org_id=jw_dev.current_org_from_session() AND EXISTS(
 SELECT 1 FROM jw_dev.stage_identity_v84() i
 WHERE i.org_id=audit_logs.org_id AND i.actor_id=audit_logs.actor_id AND i.actor_role='admin'));
CREATE SCHEMA naruv_customer_bridge AUTHORIZATION naruv_native_owner;
REVOKE ALL ON SCHEMA naruv_customer_bridge FROM PUBLIC,jw_app_dev,naruv_native_stage;
SET ROLE naruv_native_owner;
CREATE TABLE naruv_customer_bridge.crosswalk(
 org_id text NOT NULL,source_id text NOT NULL,
 entity text NOT NULL CHECK(entity='customer'),
 normalized_id text NOT NULL,
 source_customer_id text NOT NULL,
 customer_id text NOT NULL CHECK(customer_id ~ '^[a-f0-9]{32}$'),
 stage_id text NOT NULL,
 PRIMARY KEY(org_id,source_id,normalized_id),
 UNIQUE(org_id,customer_id),
 CHECK(normalized_id=lower(source_customer_id COLLATE "C")),
 FOREIGN KEY(org_id,source_id,entity,normalized_id) REFERENCES naruv_native_review.records(org_id,source_id,entity,normalized_id),
 FOREIGN KEY(org_id,stage_id) REFERENCES naruv_native_review.stages(org_id,stage_id),
 FOREIGN KEY(org_id,customer_id) REFERENCES jw_dev.customers(org_id,id)
);
ALTER TABLE naruv_customer_bridge.crosswalk ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_customer_bridge.crosswalk FORCE ROW LEVEL SECURITY;
CREATE POLICY crosswalk_owner_scope ON naruv_customer_bridge.crosswalk TO naruv_native_owner
 USING(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'))
 WITH CHECK(org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role='admin'));
REVOKE ALL ON naruv_customer_bridge.crosswalk FROM PUBLIC,jw_app_dev,naruv_native_stage;
CREATE TRIGGER crosswalk_immutable BEFORE UPDATE OR DELETE ON naruv_customer_bridge.crosswalk
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE FUNCTION naruv_customer_bridge.apply_customer()
 RETURNS trigger LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
DECLARE a record; s naruv_native_review.stages; cid text; stamp text;
BEGIN
 IF current_user IS DISTINCT FROM 'naruv_native_owner' OR NEW.entity IS DISTINCT FROM 'customer'
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT i.actor_id,i.org_id,i.actor_role INTO a FROM jw_dev.stage_identity_v84() i;
 IF NOT FOUND OR a.org_id IS DISTINCT FROM NEW.org_id OR a.actor_role IS DISTINCT FROM 'admin'
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO s FROM naruv_native_review.stages t
 WHERE t.org_id=NEW.org_id AND t.stage_id=NEW.stage_id;
 IF NOT FOUND OR (s.actor_id,s.source_id,s.entity) IS DISTINCT FROM (a.actor_id,NEW.source_id,NEW.entity)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 -- PostgreSQL derives a stable 32-hex ID from a delimiter-safe tuple; never
 -- reuse an unrelated existing customer even if a truncated digest collides.
 cid:=left(encode(sha256(convert_to(jsonb_build_array(NEW.org_id,NEW.source_id,NEW.normalized_id)::text,'UTF8')),'hex'),32);
 stamp:=to_char(clock_timestamp() AT TIME ZONE 'Asia/Seoul','YYYY-MM-DD"T"HH24:MI:SS')||'+09:00';
 INSERT INTO jw_dev.customers(id,org_id,name,business_number,contact_name,email,phone,created_at)
 VALUES(cid,NEW.org_id,NEW.data->>'name',coalesce(NEW.data->>'business_number',''),'','','',stamp);
 INSERT INTO naruv_customer_bridge.crosswalk(org_id,source_id,entity,normalized_id,source_customer_id,customer_id,stage_id)
 VALUES(NEW.org_id,NEW.source_id,NEW.entity,NEW.normalized_id,NEW.source_record_id,cid,NEW.stage_id);
 INSERT INTO jw_dev.audit_logs(id,org_id,actor_id,entity_type,entity_id,action,detail,created_at)
 VALUES(replace(gen_random_uuid()::text,'-',''),NEW.org_id,a.actor_id,'customer',cid,'create',
 jsonb_build_object('source','naruv_customer_bridge_ci','stage_id',NEW.stage_id,
 'source_id',NEW.source_id,'source_customer_id',NEW.source_record_id)::text,stamp);
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION naruv_customer_bridge.apply_customer() FROM PUBLIC,jw_app_dev,naruv_native_stage;
CREATE TRIGGER bridge_customer_after_insert AFTER INSERT ON naruv_native_review.records
 FOR EACH ROW WHEN (NEW.entity='customer') EXECUTE FUNCTION naruv_customer_bridge.apply_customer();
RESET ROLE;
