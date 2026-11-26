-- Disposable PG17 CI lab only; requires naruv_approval_pg17_lab.sql.
-- No production schema, real ERP records, or authorization to import.
DO $$ BEGIN
 IF current_database() <> 'naruv_approval_ci' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user <> 'postgres' OR current_setting('naruv.file_tx_server_addr',true) IS NULL
 OR host(inet_server_addr()) IS DISTINCT FROM current_setting('naruv.file_tx_server_addr',true)
 THEN RAISE EXCEPTION 'TX_DISPOSABLE_PG17_REQUIRED'; END IF;
END $$;
SET ROLE naruv_lab_owner;
CREATE TABLE naruv_approval_lab.file_revisions (
 organization_id text NOT NULL, source_id text NOT NULL, entity text NOT NULL,
 revision bigint NOT NULL CHECK(revision>=0),
 PRIMARY KEY(organization_id,source_id,entity),
 FOREIGN KEY(organization_id,source_id,entity) REFERENCES naruv_approval_lab.targets(organization_id,source_id,entity)
);
CREATE TABLE naruv_approval_lab.file_stages (
 organization_id text NOT NULL, stage_id text NOT NULL CHECK(stage_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 source_id text NOT NULL, entity text NOT NULL CHECK(entity IN ('item','customer')),
 file_format text NOT NULL CHECK(file_format IN ('csv','xlsx')),
 raw bytea NOT NULL, raw_sha256 text NOT NULL CHECK(raw_sha256=encode(sha256(raw),'hex')),
 byte_count integer NOT NULL CHECK(byte_count=octet_length(raw) AND byte_count BETWEEN 1 AND 1048576),
 stage_sha256 text NOT NULL CHECK(stage_sha256 ~ '^[a-f0-9]{64}$'),
 preflight_sha256 text NOT NULL CHECK(preflight_sha256 ~ '^[a-f0-9]{64}$'),
 rows_sha256 text NOT NULL CHECK(rows_sha256 ~ '^[a-f0-9]{64}$'),
 snapshot_sha256 text NOT NULL CHECK(snapshot_sha256 ~ '^[a-f0-9]{64}$'),
 next_snapshot_sha256 text NOT NULL CHECK(next_snapshot_sha256 ~ '^[a-f0-9]{64}$' AND next_snapshot_sha256<>snapshot_sha256),
 expected_ids text[] NOT NULL CHECK(cardinality(expected_ids)<=10000),
 next_revision bigint NOT NULL CHECK(next_revision>0),
 rows_json jsonb NOT NULL CHECK(jsonb_typeof(rows_json)='array' AND jsonb_array_length(rows_json) BETWEEN 1 AND 1000),
 PRIMARY KEY(organization_id,stage_id),
 UNIQUE(organization_id,source_id,entity,stage_sha256),
 FOREIGN KEY(organization_id,source_id,entity) REFERENCES naruv_approval_lab.file_revisions(organization_id,source_id,entity)
);
CREATE TABLE naruv_approval_lab.file_records (
 organization_id text NOT NULL, source_id text NOT NULL, entity text NOT NULL CHECK(entity IN ('item','customer')),
 source_record_id text NOT NULL CHECK(source_record_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 normalized_id text GENERATED ALWAYS AS (lower(source_record_id COLLATE "C")) STORED,
 data jsonb NOT NULL CHECK(jsonb_typeof(data)='object'),
 PRIMARY KEY(organization_id,source_id,entity,normalized_id),
 FOREIGN KEY(organization_id,source_id,entity) REFERENCES naruv_approval_lab.file_revisions(organization_id,source_id,entity)
);
CREATE TABLE naruv_approval_lab.file_bindings (
 organization_id text NOT NULL, stage_id text NOT NULL, stage_sha256 text NOT NULL,
 PRIMARY KEY(organization_id,stage_id),
 FOREIGN KEY(organization_id,stage_id) REFERENCES naruv_approval_lab.file_stages(organization_id,stage_id),
 FOREIGN KEY(organization_id,stage_id) REFERENCES naruv_approval_lab.approvals(organization_id,approval_id)
);
CREATE TABLE naruv_approval_lab.file_receipts (
 organization_id text NOT NULL, stage_id text NOT NULL, reservation_id text NOT NULL,
 stage_sha256 text NOT NULL, raw_sha256 text NOT NULL, rows_sha256 text NOT NULL,
 row_count integer NOT NULL CHECK(row_count BETWEEN 1 AND 1000),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 row_import_authorized boolean NOT NULL DEFAULT false CHECK(row_import_authorized=false),
 PRIMARY KEY(organization_id,stage_id), UNIQUE(organization_id,reservation_id),
 FOREIGN KEY(organization_id,stage_id) REFERENCES naruv_approval_lab.file_bindings(organization_id,stage_id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['file_revisions','file_stages','file_records','file_bindings','file_receipts'] LOOP
 EXECUTE format('ALTER TABLE naruv_approval_lab.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE naruv_approval_lab.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant_scope ON naruv_approval_lab.%I USING (organization_id=(SELECT organization_id FROM naruv_approval_lab.actors WHERE login_role=session_user)) WITH CHECK (organization_id=(SELECT organization_id FROM naruv_approval_lab.actors WHERE login_role=session_user))',t);
 EXECUTE format('REVOKE ALL ON TABLE naruv_approval_lab.%I FROM PUBLIC,naruv_lab_a,naruv_lab_b',t);
 END LOOP;
END $$;
-- Ordinary update/delete of a staged file is forbidden even for the lab custodian.
CREATE FUNCTION naruv_approval_lab.reject_stage_mutation() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'TX_STAGE_IMMUTABLE'; END $$;
REVOKE ALL ON FUNCTION naruv_approval_lab.reject_stage_mutation() FROM PUBLIC;
CREATE TRIGGER immutable_stage BEFORE UPDATE OR DELETE ON naruv_approval_lab.file_stages
 FOR EACH ROW EXECUTE FUNCTION naruv_approval_lab.reject_stage_mutation();
-- Old entry points cannot bypass the new staged-file approval contract.
REVOKE EXECUTE ON FUNCTION naruv_approval_lab.issue(text,text,text,text,text,text,text,boolean,integer),
 naruv_approval_lab.reserve(text,text,text,text,text,text,text,text) FROM naruv_lab_a,naruv_lab_b,PUBLIC;
DO $$ BEGIN
 IF to_regprocedure('naruv_approval_lab.commit_fixture(text,text,text)') IS NOT NULL THEN
 EXECUTE 'REVOKE EXECUTE ON FUNCTION naruv_approval_lab.commit_fixture(text,text,text) FROM PUBLIC,naruv_lab_a,naruv_lab_b';
 END IF;
END $$;
CREATE FUNCTION naruv_approval_lab.approve_file(p_org text,p_stage text,p_digest text,p_confirmed boolean,p_ttl integer)
 RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a naruv_approval_lab.actors; s naruv_approval_lab.file_stages; outcome text; binding text;
BEGIN
 a:=naruv_approval_lab.lock_actor('approve');
 IF p_org IS DISTINCT FROM a.organization_id THEN RAISE EXCEPTION 'TX_SCOPE'; END IF;
 SELECT * INTO s FROM naruv_approval_lab.file_stages WHERE organization_id=p_org AND stage_id=p_stage FOR UPDATE;
 IF NOT FOUND OR s.stage_sha256 IS DISTINCT FROM p_digest THEN RAISE EXCEPTION 'TX_STAGE_CHANGED'; END IF;
 outcome:=naruv_approval_lab.issue(p_org,p_stage,s.source_id,s.entity,s.preflight_sha256,s.rows_sha256,s.snapshot_sha256,p_confirmed,p_ttl);
 IF outcome='APPROVED' THEN
 INSERT INTO naruv_approval_lab.file_bindings VALUES(p_org,p_stage,s.stage_sha256);
 ELSE
 SELECT stage_sha256 INTO binding FROM naruv_approval_lab.file_bindings WHERE organization_id=p_org AND stage_id=p_stage;
 IF NOT FOUND OR binding IS DISTINCT FROM s.stage_sha256 THEN RAISE EXCEPTION 'TX_BINDING_CHANGED'; END IF;
 END IF;
 RETURN outcome;
END $$;
CREATE FUNCTION naruv_approval_lab.commit_file(p_org text,p_stage text,p_reservation text)
 RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a naruv_approval_lab.actors; s naruv_approval_lab.file_stages; b text;
 actual_ids text[]; rev bigint; row_data jsonb; id_key text; opt_key text; code text; n integer:=0;
BEGIN
 a:=naruv_approval_lab.lock_actor('reserve');
 IF p_org IS DISTINCT FROM a.organization_id THEN RAISE EXCEPTION 'TX_SCOPE'; END IF;
 SELECT * INTO s FROM naruv_approval_lab.file_stages WHERE organization_id=p_org AND stage_id=p_stage FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'TX_STAGE_MISSING'; END IF;
 SELECT stage_sha256 INTO b FROM naruv_approval_lab.file_bindings WHERE organization_id=p_org AND stage_id=p_stage;
 IF NOT FOUND OR b IS DISTINCT FROM s.stage_sha256 THEN RAISE EXCEPTION 'TX_BINDING_CHANGED'; END IF;
 PERFORM naruv_approval_lab.check_target(p_org,s.source_id,s.entity,s.snapshot_sha256);
 SELECT revision INTO rev FROM naruv_approval_lab.file_revisions WHERE organization_id=p_org AND source_id=s.source_id AND entity=s.entity FOR UPDATE;
 IF NOT FOUND OR rev IS DISTINCT FROM s.next_revision-1 THEN RAISE EXCEPTION 'TX_REVISION_CHANGED'; END IF;
 SELECT coalesce(array_agg(source_record_id ORDER BY source_record_id COLLATE "C"),ARRAY[]::text[]) INTO actual_ids
 FROM naruv_approval_lab.file_records WHERE organization_id=p_org AND source_id=s.source_id AND entity=s.entity;
 IF actual_ids IS DISTINCT FROM s.expected_ids THEN RAISE EXCEPTION 'TX_TARGET_IDS_CHANGED'; END IF;
 PERFORM naruv_approval_lab.reserve(p_org,p_stage,p_reservation,s.source_id,s.entity,s.preflight_sha256,s.rows_sha256,s.snapshot_sha256);
 id_key:=CASE WHEN s.entity='item' THEN 'source_item_id' ELSE 'source_customer_id' END;
 opt_key:=CASE WHEN s.entity='item' THEN 'unit' ELSE 'business_number' END;
 FOR row_data IN SELECT value FROM jsonb_array_elements(s.rows_json) LOOP
 IF jsonb_typeof(row_data) IS DISTINCT FROM 'object' OR jsonb_typeof(row_data->id_key) IS DISTINCT FROM 'string'
 OR jsonb_typeof(row_data->'name') IS DISTINCT FROM 'string' OR row_data-id_key-'name'-opt_key <> '{}'::jsonb
 OR (row_data ? opt_key AND jsonb_typeof(row_data->opt_key) IS DISTINCT FROM 'string')
 OR length(row_data->>'name') NOT BETWEEN 1 AND 120
 OR (s.entity='item' AND length(row_data->>opt_key)>32)
 OR (s.entity='customer' AND row_data->>opt_key <> '' AND row_data->>opt_key !~ '^([0-9]{10}|[0-9]{3}-[0-9]{2}-[0-9]{5})$')
 THEN RAISE EXCEPTION 'TX_ROW_SHAPE'; END IF;
 code:=row_data->>id_key;
 INSERT INTO naruv_approval_lab.file_records(organization_id,source_id,entity,source_record_id,data) VALUES(p_org,s.source_id,s.entity,code,row_data);
 n:=n+1;
 END LOOP;
 IF cardinality(actual_ids)+n>10000 THEN RAISE EXCEPTION 'TX_TARGET_CAPACITY'; END IF;
 UPDATE naruv_approval_lab.file_revisions SET revision=s.next_revision WHERE organization_id=p_org AND source_id=s.source_id AND entity=s.entity;
 UPDATE naruv_approval_lab.targets SET snapshot_sha256=s.next_snapshot_sha256 WHERE organization_id=p_org AND source_id=s.source_id AND entity=s.entity;
 INSERT INTO naruv_approval_lab.file_receipts(organization_id,stage_id,reservation_id,stage_sha256,raw_sha256,rows_sha256,row_count)
 VALUES(p_org,p_stage,p_reservation,s.stage_sha256,s.raw_sha256,s.rows_sha256,n);
 RETURN 'FILE_COMMITTED';
END $$;
CREATE FUNCTION naruv_approval_lab.inspect_file(p_org text,p_stage text,p_reservation text)
 RETURNS TABLE(outcome text,row_count integer,stage_sha256 text,row_import_authorized boolean)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a naruv_approval_lab.actors;
BEGIN
 a:=naruv_approval_lab.lock_actor('inspect');
 IF p_org IS DISTINCT FROM a.organization_id THEN RAISE EXCEPTION 'TX_SCOPE'; END IF;
 RETURN QUERY SELECT 'FILE_COMMITTED'::text,r.row_count,r.stage_sha256,r.row_import_authorized FROM naruv_approval_lab.file_receipts r
 WHERE r.organization_id=p_org AND r.stage_id=p_stage AND r.reservation_id=p_reservation;
END $$;
REVOKE ALL ON FUNCTION naruv_approval_lab.approve_file(text,text,text,boolean,integer),
 naruv_approval_lab.commit_file(text,text,text),naruv_approval_lab.inspect_file(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION naruv_approval_lab.approve_file(text,text,text,boolean,integer),
 naruv_approval_lab.commit_file(text,text,text),naruv_approval_lab.inspect_file(text,text,text) TO naruv_lab_a,naruv_lab_b;
RESET ROLE;
