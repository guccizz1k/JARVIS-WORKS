-- Disposable synthetic ITEM data only. Requires naruv_approval_pg17_lab.sql.
-- Trusted fixture custodian stages data after independently running preflight.
-- No production import permission; never apply to a real ERP database.
SET ROLE naruv_lab_owner;
CREATE TABLE naruv_approval_lab.fixture_stage (
 organization_id text NOT NULL,
 approval_id text NOT NULL,
 source_id text NOT NULL,
 entity text NOT NULL CHECK(entity='item'),
 preflight_sha256 text NOT NULL CHECK(preflight_sha256 ~ '^[a-f0-9]{64}$'),
 rows_sha256 text NOT NULL CHECK(rows_sha256 ~ '^[a-f0-9]{64}$'),
 snapshot_sha256 text NOT NULL CHECK(snapshot_sha256 ~ '^[a-f0-9]{64}$'),
 next_snapshot_sha256 text NOT NULL CHECK(next_snapshot_sha256 ~ '^[a-f0-9]{64}$' AND next_snapshot_sha256<>snapshot_sha256),
 expected_ids text[] NOT NULL CHECK(cardinality(expected_ids)<=10000),
 fixture_rows jsonb NOT NULL CHECK(jsonb_typeof(fixture_rows)='array' AND jsonb_array_length(fixture_rows) BETWEEN 1 AND 1000),
 PRIMARY KEY(organization_id,approval_id),
 FOREIGN KEY(organization_id,approval_id) REFERENCES naruv_approval_lab.approvals(organization_id,approval_id)
);
CREATE TABLE naruv_approval_lab.fixture_items (
 organization_id text NOT NULL,
 source_id text NOT NULL,
 entity text NOT NULL CHECK(entity='item'),
 source_item_id text NOT NULL CHECK(source_item_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 normalized_id text GENERATED ALWAYS AS (lower(source_item_id COLLATE "C")) STORED,
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 120),
 PRIMARY KEY(organization_id,source_id,entity,normalized_id),
 FOREIGN KEY(organization_id,source_id,entity) REFERENCES naruv_approval_lab.targets(organization_id,source_id,entity)
);
CREATE TABLE naruv_approval_lab.fixture_receipts (
 organization_id text NOT NULL,
 approval_id text NOT NULL,
 reservation_id text NOT NULL,
 preflight_sha256 text NOT NULL,
 rows_sha256 text NOT NULL,
 next_snapshot_sha256 text NOT NULL,
 row_count integer NOT NULL CHECK(row_count BETWEEN 1 AND 1000),
 row_import_authorized boolean NOT NULL DEFAULT false CHECK(row_import_authorized=false),
 PRIMARY KEY(organization_id,approval_id),
 UNIQUE(organization_id,reservation_id),
 FOREIGN KEY(organization_id,approval_id) REFERENCES naruv_approval_lab.approvals(organization_id,approval_id)
);
ALTER TABLE naruv_approval_lab.fixture_stage ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_approval_lab.fixture_stage FORCE ROW LEVEL SECURITY;
ALTER TABLE naruv_approval_lab.fixture_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_approval_lab.fixture_items FORCE ROW LEVEL SECURITY;
ALTER TABLE naruv_approval_lab.fixture_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_approval_lab.fixture_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY fixture_stage_scope ON naruv_approval_lab.fixture_stage
 USING(organization_id=(SELECT a.organization_id FROM naruv_approval_lab.actors a WHERE a.login_role=session_user))
 WITH CHECK(organization_id=(SELECT a.organization_id FROM naruv_approval_lab.actors a WHERE a.login_role=session_user));
CREATE POLICY fixture_item_scope ON naruv_approval_lab.fixture_items
 USING(organization_id=(SELECT a.organization_id FROM naruv_approval_lab.actors a WHERE a.login_role=session_user))
 WITH CHECK(organization_id=(SELECT a.organization_id FROM naruv_approval_lab.actors a WHERE a.login_role=session_user));
CREATE POLICY fixture_receipt_scope ON naruv_approval_lab.fixture_receipts
 USING(organization_id=(SELECT a.organization_id FROM naruv_approval_lab.actors a WHERE a.login_role=session_user))
 WITH CHECK(organization_id=(SELECT a.organization_id FROM naruv_approval_lab.actors a WHERE a.login_role=session_user));
CREATE FUNCTION naruv_approval_lab.commit_fixture(p_org text,p_approval text,p_reservation text)
 RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a naruv_approval_lab.actors; s naruv_approval_lab.fixture_stage;
 old naruv_approval_lab.approvals; actual_ids text[]; item jsonb; n integer:=0;
BEGIN
 a:=naruv_approval_lab.lock_actor('reserve');
 IF p_org IS DISTINCT FROM a.organization_id THEN RAISE EXCEPTION 'FIXTURE_SCOPE'; END IF;
 SELECT * INTO s FROM naruv_approval_lab.fixture_stage
  WHERE organization_id=p_org AND approval_id=p_approval FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'FIXTURE_STAGE_MISSING'; END IF;
 -- Actor lock serializes tenant operations. Existing reserve locks target then approval.
 PERFORM naruv_approval_lab.check_target(p_org,s.source_id,s.entity,s.snapshot_sha256);
 SELECT * INTO old FROM naruv_approval_lab.approvals
  WHERE organization_id=p_org AND approval_id=p_approval FOR UPDATE;
 IF NOT FOUND OR (old.source_id,old.entity,old.preflight_sha256,old.rows_sha256,old.snapshot_sha256)
 IS DISTINCT FROM (s.source_id,s.entity,s.preflight_sha256,s.rows_sha256,s.snapshot_sha256)
 THEN RAISE EXCEPTION 'FIXTURE_BINDING_CHANGED'; END IF;
 SELECT coalesce(array_agg(source_item_id ORDER BY source_item_id COLLATE "C"),ARRAY[]::text[])
 INTO actual_ids FROM naruv_approval_lab.fixture_items
 WHERE organization_id=p_org AND source_id=s.source_id AND entity=s.entity;
 IF actual_ids IS DISTINCT FROM s.expected_ids THEN RAISE EXCEPTION 'FIXTURE_TARGET_IDS_CHANGED'; END IF;
 PERFORM naruv_approval_lab.reserve(p_org,p_approval,p_reservation,s.source_id,s.entity,
   s.preflight_sha256,s.rows_sha256,s.snapshot_sha256);
 -- Caller cannot submit rows, hashes or replacement snapshot to this function.
 -- Root staging is a trust boundary, not a public application interface.
 FOR item IN SELECT value FROM jsonb_array_elements(s.fixture_rows) LOOP
   IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR
      NOT (item ? 'source_item_id' AND item ? 'name') OR
      item - 'source_item_id' - 'name' <> '{}'::jsonb OR
      jsonb_typeof(item->'source_item_id') IS DISTINCT FROM 'string' OR
      jsonb_typeof(item->'name') IS DISTINCT FROM 'string'
   THEN RAISE EXCEPTION 'FIXTURE_ROW_SHAPE'; END IF;
   INSERT INTO naruv_approval_lab.fixture_items(organization_id,source_id,entity,source_item_id,name)
    VALUES(p_org,s.source_id,s.entity,item->>'source_item_id',item->>'name');
   n:=n+1;
 END LOOP;
 UPDATE naruv_approval_lab.targets SET snapshot_sha256=s.next_snapshot_sha256
  WHERE organization_id=p_org AND source_id=s.source_id AND entity=s.entity;
 INSERT INTO naruv_approval_lab.fixture_receipts(organization_id,approval_id,reservation_id,
   preflight_sha256,rows_sha256,next_snapshot_sha256,row_count)
 VALUES(p_org,p_approval,p_reservation,s.preflight_sha256,s.rows_sha256,s.next_snapshot_sha256,n);
 RETURN 'FIXTURE_COMMITTED';
END $$;
CREATE FUNCTION naruv_approval_lab.inspect_fixture(p_org text,p_approval text,p_reservation text)
 RETURNS TABLE(outcome text, row_count integer, row_import_authorized boolean)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a naruv_approval_lab.actors;
BEGIN
 a:=naruv_approval_lab.lock_actor('inspect');
 IF p_org IS DISTINCT FROM a.organization_id THEN RAISE EXCEPTION 'FIXTURE_SCOPE'; END IF;
 RETURN QUERY SELECT 'FIXTURE_COMMITTED'::text,t.row_count,t.row_import_authorized
 FROM naruv_approval_lab.fixture_receipts t
 WHERE t.organization_id=p_org AND t.approval_id=p_approval AND t.reservation_id=p_reservation;
END $$;
REVOKE ALL ON FUNCTION naruv_approval_lab.commit_fixture(text,text,text),
 naruv_approval_lab.inspect_fixture(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION naruv_approval_lab.commit_fixture(text,text,text),
 naruv_approval_lab.inspect_fixture(text,text,text) TO naruv_lab_a,naruv_lab_b;
RESET ROLE;
