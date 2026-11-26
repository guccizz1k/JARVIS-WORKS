-- Disposable PG17 fixture only. Apply after V90 + V92 fixture bootstrap.
-- This is a server-owned review registry, not the real ERP target.
DO $$ BEGIN
 IF current_database() <> 'postgres' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user <> 'postgres' OR current_setting('naruv.preview_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'NARUV_PREVIEW_DISPOSABLE_ONLY'; END IF;
END $$;
CREATE TABLE jw_dev.naruv_review_sources(
 org_id text NOT NULL REFERENCES jw_dev.organizations(id),
 source_id text NOT NULL CHECK(source_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 entity text NOT NULL CHECK(entity IN ('item','customer')),
 revision text NOT NULL CHECK(revision ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 existing_ids text[] NOT NULL CHECK(cardinality(existing_ids)<=10000 AND array_position(existing_ids,NULL) IS NULL),
 active boolean NOT NULL DEFAULT true,
 PRIMARY KEY(org_id,source_id,entity)
);
ALTER TABLE jw_dev.naruv_review_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.naruv_review_sources FORCE ROW LEVEL SECURITY;
REVOKE ALL ON jw_dev.naruv_review_sources FROM PUBLIC,anon,authenticated,service_role,jw_app_dev;
GRANT SELECT ON jw_dev.naruv_review_sources TO jw_app_dev;
CREATE POLICY naruv_review_source_tenant ON jw_dev.naruv_review_sources FOR SELECT TO jw_app_dev
 USING(org_id=jw_dev.current_org_from_session() AND EXISTS(
  SELECT 1 FROM jw_dev.stage_identity_v84() i WHERE i.org_id=naruv_review_sources.org_id AND i.actor_role='admin'
 ));
INSERT INTO jw_dev.naruv_review_sources VALUES
 ('ci-a','source-a','item','rev-a',ARRAY['EXISTING-A'],true),
 ('ci-a','source-a','customer','rev-a',ARRAY[]::text[],true),
 ('ci-b','source-b','item','rev-b',ARRAY['EXISTING-B'],true),
 ('ci-a','inactive','item','rev-a',ARRAY[]::text[],false);
