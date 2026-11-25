-- V20.0: READ-ONLY actual jarvis-works-dev cutover preflight.
-- NEVER modifies a role, policy, index, table, secret, or customer row.
-- Do not confuse "safety PASS" with "release-ready": all CUTOVER checks
-- must independently pass before anyone schedules a migration.
WITH facts AS (
 SELECT
  current_setting('server_version_num')::int / 10000 = 17 AS pg17,
  to_regclass('jw_dev.import_previews') IS NOT NULL AS preview_table,
  (SELECT c.relrowsecurity AND c.relforcerowsecurity
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='jw_dev' AND c.relname='import_previews' AND c.relkind='r') AS force_rls,
  (SELECT count(*) FROM information_schema.columns
   WHERE table_schema='jw_dev' AND table_name='import_previews')=12 AS exactly_12_columns,
  (SELECT count(*) FROM information_schema.columns
   WHERE table_schema='jw_dev' AND table_name='import_previews'
    AND column_name=ANY(ARRAY['id','org_id','uploaded_by','file_sha256',
    'filename','normalized_json','preview_digest','status','created_at',
    'confirmed_at','order_id','quote_id']))=12 AS named_columns,
  (SELECT count(*) FROM information_schema.columns
   WHERE table_schema='jw_dev' AND table_name='import_previews'
    AND column_name=ANY(ARRAY['id','org_id','uploaded_by','file_sha256',
    'filename','normalized_json','preview_digest','status','created_at'])
    AND is_nullable='NO')=9 AS required_nonnull,
  (SELECT count(*) FROM information_schema.columns
   WHERE table_schema='jw_dev' AND table_name='import_previews'
   AND column_name IN ('filename','created_at') AND column_default IS NULL)=2 AS no_implicit_defaults,
  (SELECT count(*) FROM pg_constraint c
    JOIN pg_class t ON c.conrelid=t.oid
    JOIN pg_namespace n ON t.relnamespace=n.oid
    WHERE n.nspname='jw_dev' AND t.relname='import_previews' AND c.contype='f')=4 AS four_fks,
  (SELECT count(*) FROM pg_constraint c
    JOIN pg_class t ON c.conrelid=t.oid
    JOIN pg_namespace n ON t.relnamespace=n.oid
    WHERE n.nspname='jw_dev' AND t.relname='import_previews'
      AND c.contype='c' AND pg_get_constraintdef(c.oid) LIKE '%pending%confirmed%')>=1 AS status_check,
  (SELECT count(*) FROM pg_indexes WHERE schemaname='jw_dev'
   AND tablename='import_previews' AND indexdef LIKE '%UNIQUE INDEX%'
   AND indexdef LIKE '%(org_id, file_sha256)%'
   AND indexdef LIKE '%confirmed%')>=1 AS confirmed_unique,
  (SELECT count(*) FROM jw_dev.import_previews)=0 AS no_existing_import_rows,
  NOT has_table_privilege('jw_app_dev','jw_dev.import_previews','INSERT') AS business_insert_denied,
  NOT has_table_privilege('jw_app_dev','jw_dev.import_previews','UPDATE') AS business_update_denied,
  NOT has_table_privilege('jw_app_dev','jw_dev.import_previews','DELETE') AS business_delete_denied,
  NOT has_table_privilege('anon','jw_dev.import_previews','INSERT') AS anon_insert_denied,
  NOT has_table_privilege('anon','jw_dev.import_previews','SELECT') AS anon_select_denied,
  NOT has_table_privilege('authenticated','jw_dev.import_previews','INSERT') AS auth_insert_denied,
  NOT has_table_privilege('authenticated','jw_dev.import_previews','SELECT') AS auth_select_denied,
  (SELECT count(*) FROM pg_policies
   WHERE schemaname='jw_dev' AND tablename='import_previews'
   AND cmd='INSERT' AND 'jw_app_dev'=ANY(roles))=0 AS no_business_insert_policy,
  (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='jw_dev' AND p.proname IN
      ('current_org_from_session','current_actor_from_session_v82')
      AND p.prosecdef AND 'search_path=pg_catalog'=ANY(p.proconfig))=2 AS session_helpers_pinned,
  EXISTS (SELECT 1 FROM pg_roles
    WHERE rolname='jw_dev_import_writer_v200'
      AND NOT rolbypassrls AND NOT rolsuper AND NOT rolinherit) AS writer_role_present,
  EXISTS (SELECT 1 FROM pg_roles
    WHERE rolname='jw_dev_import_approver_v200'
      AND NOT rolbypassrls AND NOT rolsuper AND NOT rolinherit) AS approver_role_present,
  EXISTS (SELECT 1 FROM pg_policies
    WHERE schemaname='jw_dev' AND tablename='import_previews'
      AND cmd='INSERT' AND 'jw_dev_import_writer_v200'=ANY(roles)) AS writer_insert_rls_present,
  EXISTS (SELECT 1 FROM pg_indexes
    WHERE schemaname='jw_dev' AND tablename='import_previews'
      AND indexdef LIKE '%UNIQUE INDEX%'
      AND indexdef LIKE '%(org_id, file_sha256)%'
      AND indexdef LIKE '%pending%') AS pending_duplicate_guard,
  to_regclass('jw_dev.v195_approval_receipts') IS NOT NULL AS approval_audit_table,
  to_regprocedure('jw_dev.v195_confirm_import(text,text,text,text,text,text,text)') IS NOT NULL AS signed_atomic_approval
), checks AS (
 SELECT * FROM facts,
 LATERAL (VALUES
  ('S01','safety',pg17),
  ('S02','safety',preview_table),
  ('S03','safety',force_rls),
  ('S04','safety',exactly_12_columns),
  ('S05','safety',named_columns),
  ('S06','safety',required_nonnull),
  ('S07','safety',no_implicit_defaults),
  ('S08','safety',four_fks),
  ('S09','safety',status_check),
  ('S10','safety',confirmed_unique),
  ('S11','safety',no_existing_import_rows),
  ('S12','safety',business_insert_denied),
  ('S13','safety',business_update_denied),
  ('S14','safety',business_delete_denied),
  ('S15','safety',anon_insert_denied),
  ('S16','safety',anon_select_denied),
  ('S17','safety',auth_insert_denied),
  ('S18','safety',auth_select_denied),
  ('S19','safety',no_business_insert_policy),
  ('S20','safety',session_helpers_pinned),
  ('C01','cutover',writer_role_present),
  ('C02','cutover',approver_role_present),
  ('C03','cutover',writer_insert_rls_present),
  ('C04','cutover',pending_duplicate_guard),
  ('C05','cutover',approval_audit_table),
  ('C06','cutover',signed_atomic_approval)
 ) AS c(check_id,category,ok)
)
SELECT check_id,category,CASE WHEN ok IS TRUE THEN 'PASS' ELSE 'BLOCKED' END AS state
FROM checks ORDER BY check_id;
