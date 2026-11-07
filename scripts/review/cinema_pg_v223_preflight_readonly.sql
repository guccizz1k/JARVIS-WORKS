-- V22.3 Track B (issue #140) -- READ-ONLY preflight for the jw_dev development schema.
--
-- WHAT IT IS: ONE SELECT statement that returns ONE jsonb document. No DDL, no DML, no temp objects, no
-- function that writes. It only reads the catalog, privilege-check functions and COUNT(*) of the schema's
-- tables. Nothing in the output is a row value, a DSN or a password: only object names, booleans and counts.
--
-- WHAT IT ANSWERS (before anyone applies the SQL proposals, with the approval the issue requires):
--   * is the quote two-person constraint present, validated, and does its text require a non-NULL approver?
--   * do the three order/invoice/payment side tables and their three functions exist, with FORCE RLS,
--     pinned search_path and no PUBLIC execute?
--   * does jw_backup_ro exist, and would the backup tool's least-privilege check (F2/F6) accept it?
--     (`violations` uses the same rule names as scripts/pg_backup_v223.py evaluate_source_privileges.)
--   * what does the CURRENT session role look like to that same check (run it as jw_backup_ro after it exists)?
--   * existing self-approved quotes (the rows the owner must review before VALIDATE CONSTRAINT)
--   * row counts per table, i.e. is the development data still empty?
--
-- HOW TO RUN (read-only by construction; the extra setting is a second lock, not the only one):
--   PGOPTIONS='-c default_transaction_read_only=on' psql "$DSN" -X -At -v ON_ERROR_STOP=1 \
--       -f scripts/review/cinema_pg_v223_preflight_readonly.sql > preflight.json
--   Keep $DSN out of shell history, chat and logs. The output file contains no secret.
--   Pasting this single statement into a SQL console works as well.
--
-- HONESTY RULES BAKED INTO THE OUTPUT:
--   * `data.row_visibility_complete` is true only for a superuser or a BYPASSRLS role that can also SELECT every
--     table. With FORCE ROW LEVEL SECURITY any other role sees a subset, so zero counts then prove nothing.
--   * BYPASSRLS does not grant table privileges. On the development project the `postgres` admin reads all 62
--     tables only because it inherits pg_read_all_data (it is merely an ADMIN member of jw_cinema_owner, with
--     INHERIT/SET false, so it holds no direct SELECT on that role's 17 tables). A role without that route has
--     those tables skipped: they are named in `data.unreadable_tables` and their counts are unknown, not zero.
--     After jw_backup_ro exists, running the preflight as that role gives the complete picture without
--     pg_read_all_data.
--   * This is evidence about one database at one moment. It is not an approval and not a PASS.
--
-- Counting every table is cheap on the development project (tens of tables, almost no rows). Do not run
-- it unchanged against a large database: COUNT(*) is a full scan per table.
WITH
cfg AS (SELECT 'jw_dev'::text AS s),
me AS (
  SELECT r.oid, r.rolname, r.rolsuper, r.rolbypassrls
    FROM pg_roles r WHERE r.rolname = current_user
),
sch AS (
  SELECT n.oid, n.nspname, pg_get_userbyid(n.nspowner) AS owner
    FROM pg_namespace n, cfg WHERE n.nspname = cfg.s
),
tbl AS (
  SELECT c.oid, c.relname, c.relrowsecurity, c.relforcerowsecurity, pg_get_userbyid(c.relowner) AS owner,
         (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) AS policies
    FROM pg_class c JOIN sch ON sch.oid = c.relnamespace
   WHERE c.relkind IN ('r','p')
),
seq AS (
  SELECT c.oid FROM pg_class c JOIN sch ON sch.oid = c.relnamespace WHERE c.relkind = 'S'
),
-- exact per-table row counts, only for tables this session may SELECT (no row value leaves the query)
cnt AS (
  SELECT t.relname,
         (xpath('/row/c/text()', query_to_xml(
              format('SELECT count(*) AS c FROM %I.%I', (SELECT s FROM cfg), t.relname), false, true, '')))[1]::text::bigint AS n
    FROM tbl t
   WHERE has_table_privilege(current_user, t.oid, 'SELECT')
),
-- the two roles judged by the backup tool's rules: the session role, and jw_backup_ro when it exists
subj AS (
  SELECT 'session'::text AS label, r.oid, r.rolname, true AS is_session FROM me r
  UNION ALL
  SELECT 'jw_backup_ro', r.oid, r.rolname, false FROM pg_roles r WHERE r.rolname = 'jw_backup_ro'
),
facts AS (
  SELECT sj.label, sj.oid, r.rolname, sj.is_session,
         r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls, r.rolcanlogin,
         r.rolconnlimit, r.rolvaliduntil,
         coalesce(r.rolconfig::text[] @> ARRAY['default_transaction_read_only=on'], false) AS default_read_only,
         (current_user = session_user) AS same_session_user,
         EXISTS (SELECT 1 FROM pg_roles r2 WHERE r2.oid <> r.oid AND pg_has_role(r.oid, r2.oid, 'SET')) AS settable_other_roles,
         (SELECT coalesce(bool_or(pg_has_role(r.oid, m, 'MEMBER')), false)
            FROM unnest(ARRAY['pg_write_all_data','pg_execute_server_program',
                              'pg_read_server_files','pg_write_server_files']) m) AS privileged_builtin_member,
         has_database_privilege(r.oid, current_database(), 'CREATE') AS database_create,
         has_schema_privilege(r.oid, (SELECT s FROM cfg), 'USAGE')  AS schema_usage,
         has_schema_privilege(r.oid, (SELECT s FROM cfg), 'CREATE') AS schema_create,
         (SELECT count(*) FROM tbl) AS tables,
         (SELECT count(*) FROM tbl t WHERE NOT has_table_privilege(r.oid, t.oid, 'SELECT')) AS tables_unreadable,
         (SELECT count(*) FROM tbl t WHERE has_table_privilege(r.oid, t.oid,
              'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')) AS tables_writable,
         (SELECT count(*) FROM tbl t WHERE t.relrowsecurity) AS rls_tables,
         (SELECT count(*) FROM seq q WHERE has_sequence_privilege(r.oid, q.oid, 'UPDATE')) AS sequences_writable,
         (SELECT coalesce(jsonb_agg(r2.rolname ORDER BY r2.rolname), '[]'::jsonb)
            FROM pg_auth_members am JOIN pg_roles r2 ON r2.oid = am.roleid WHERE am.member = r.oid) AS member_of
    FROM subj sj JOIN pg_roles r ON r.oid = sj.oid
),
verdict AS (
  SELECT f.*,
         array_remove(ARRAY[
           CASE WHEN f.rolsuper THEN 'superuser' END,
           CASE WHEN f.rolcreaterole THEN 'createrole' END,
           CASE WHEN f.rolcreatedb THEN 'createdb' END,
           CASE WHEN f.rolreplication THEN 'replication' END,
           CASE WHEN f.privileged_builtin_member THEN 'privileged_builtin_member' END,
           CASE WHEN f.database_create THEN 'database_create' END,
           CASE WHEN f.schema_create THEN 'schema_create' END,
           CASE WHEN f.is_session AND NOT f.same_session_user THEN 'role_switched' END,
           CASE WHEN f.settable_other_roles THEN 'settable_other_roles' END,
           CASE WHEN NOT f.schema_usage THEN 'schema_no_usage' END,
           CASE WHEN f.tables < 1 THEN 'no_tables_visible' END,
           CASE WHEN f.tables_unreadable <> 0 THEN 'tables_unreadable' END,
           CASE WHEN f.tables_writable <> 0 THEN 'tables_writable' END,
           CASE WHEN f.sequences_writable <> 0 THEN 'sequences_writable' END,
           CASE WHEN f.rls_tables > 0 AND NOT f.rolbypassrls THEN 'rls_rows_not_fully_readable' END
         ], NULL) AS violations
    FROM facts f
),
two AS (
  SELECT k.convalidated, pg_get_constraintdef(k.oid) AS def
    FROM pg_constraint k
   WHERE k.conrelid = to_regclass(format('%I.cinema_pg_quotes', (SELECT s FROM cfg)))
     AND k.conname = 'cinema_pg_quote_two_person'
),
conf AS (
  -- existing self-approved / approver-less quotes; only when the table and its three columns exist and are readable
  SELECT CASE WHEN q.ok THEN query_to_xml(
           'SELECT count(*) FILTER (WHERE status IN (''approved'',''ordered'')) AS total, '
        || 'count(*) FILTER (WHERE status IN (''approved'',''ordered'') AND (submitted_by IS NULL OR approved_by IS NULL '
        || 'OR approved_by IS NOT DISTINCT FROM submitted_by)) AS bad FROM jw_dev.cinema_pg_quotes', false, true, '') END AS x
    FROM (SELECT to_regclass('jw_dev.cinema_pg_quotes') IS NOT NULL
                 AND has_table_privilege(current_user, to_regclass('jw_dev.cinema_pg_quotes'), 'SELECT')
                 AND (SELECT count(*) FROM pg_attribute a
                       WHERE a.attrelid = to_regclass('jw_dev.cinema_pg_quotes') AND NOT a.attisdropped
                         AND a.attname IN ('status','submitted_by','approved_by')) = 3 AS ok) q
),
terms_tables AS (
  SELECT jsonb_object_agg(n, jsonb_build_object(
           'exists', t.oid IS NOT NULL, 'force_rls', coalesce(t.relforcerowsecurity, false),
           'policies', coalesce(t.policies, 0), 'owner', t.owner)) AS j
    FROM unnest(ARRAY['cinema_pg_order_terms','cinema_pg_invoice_terms','cinema_pg_payment_notes']) n
    LEFT JOIN tbl t ON t.relname = n
),
terms_funcs AS (
  SELECT jsonb_object_agg(n, jsonb_build_object(
           'exists', f.cnt > 0, 'security_definer', coalesce(f.secdef, false),
           'search_path_pinned', coalesce(f.pinned, false), 'public_execute', coalesce(f.pub, false))) AS j
    FROM unnest(ARRAY['cinema_pg_order_terms_set','cinema_pg_invoice_terms_set','cinema_pg_payment_note_set']) n
    LEFT JOIN LATERAL (
      SELECT count(*) AS cnt, bool_and(p.prosecdef) AS secdef,
             bool_and(coalesce(array_to_string(p.proconfig, ',') LIKE '%search_path=pg_catalog%', false)) AS pinned,
             bool_or(has_function_privilege('public', p.oid, 'EXECUTE')) AS pub
        FROM pg_proc p JOIN sch ON sch.oid = p.pronamespace WHERE p.proname = n) f ON true
),
api_privs AS (
  SELECT coalesce(jsonb_object_agg(g.label, g.n), '{}'::jsonb) AS j
    FROM (SELECT x.label, (SELECT count(*) FROM tbl t WHERE has_table_privilege(x.oid, t.oid,
                  'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')) AS n
            FROM (SELECT r.rolname AS label, r.oid FROM pg_roles r WHERE r.rolname IN ('anon','authenticated','service_role')) x) g
),
owner_link AS (
  SELECT coalesce(jsonb_agg(jsonb_build_object('grantor', pg_get_userbyid(am.grantor), 'admin', am.admin_option,
                                               'inherit', am.inherit_option, 'set', am.set_option)), '[]'::jsonb) AS j
    FROM pg_auth_members am JOIN pg_roles ro ON ro.oid = am.roleid JOIN me ON me.oid = am.member
   WHERE ro.rolname = 'jw_cinema_owner'
)
SELECT jsonb_pretty(jsonb_build_object(
  'tool', 'cinema_pg_v223_preflight_readonly', 'version', 1,
  'server', jsonb_build_object('version_num', current_setting('server_version_num')::int,
                               'database', current_database(), 'current_user', current_user,
                               'session_user', session_user),
  'session_role', (SELECT to_jsonb(v) - 'oid' - 'label' - 'is_session' FROM verdict v WHERE v.label = 'session'),
  'session_to_jw_cinema_owner', (SELECT j FROM owner_link),
  'schema', jsonb_build_object(
      'name', (SELECT s FROM cfg), 'exists', EXISTS (SELECT 1 FROM sch), 'owner', (SELECT owner FROM sch),
      'tables', (SELECT count(*) FROM tbl), 'sequences', (SELECT count(*) FROM seq),
      'force_rls_tables', (SELECT count(*) FROM tbl WHERE relforcerowsecurity),
      'rls_tables', (SELECT count(*) FROM tbl WHERE relrowsecurity),
      'rls_tables_without_policy', (SELECT coalesce(jsonb_agg(relname ORDER BY relname), '[]'::jsonb)
                                      FROM tbl WHERE relrowsecurity AND policies = 0),
      'tables_with_public_privileges', (SELECT count(*) FROM tbl t WHERE has_table_privilege('public', t.oid,
                  'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')),
      'tables_with_privileges_by_api_role', (SELECT j FROM api_privs)),
  'candidates', jsonb_build_object(
      'quote_two_person_constraint', jsonb_build_object(
          'present', EXISTS (SELECT 1 FROM two), 'validated', (SELECT convalidated FROM two),
          'requires_non_null_approver', (SELECT def LIKE '%approved_by IS NOT NULL%' FROM two)),
      'terms_tables', (SELECT j FROM terms_tables),
      'terms_functions', (SELECT j FROM terms_funcs),
      'backup_role', CASE WHEN EXISTS (SELECT 1 FROM verdict WHERE label = 'jw_backup_ro')
          THEN (SELECT jsonb_build_object('exists', true, 'can_login', can_login, 'bypassrls', rolbypassrls,
                  'superuser', rolsuper, 'createrole', rolcreaterole, 'createdb', rolcreatedb,
                  'replication', rolreplication, 'connection_limit', rolconnlimit,
                  'valid_until', rolvaliduntil, 'default_read_only', default_read_only,
                  'member_of', member_of, 'settable_other_roles', settable_other_roles,
                  'tables', tables, 'tables_unreadable', tables_unreadable, 'tables_writable', tables_writable,
                  'sequences_writable', sequences_writable, 'violations', to_jsonb(violations))
                  FROM (SELECT v.*, v.rolcanlogin AS can_login FROM verdict v WHERE v.label = 'jw_backup_ro') b)
          ELSE jsonb_build_object('exists', false) END,
      'other_login_bypassrls_roles', (SELECT coalesce(jsonb_agg(rolname ORDER BY rolname), '[]'::jsonb)
                                        FROM pg_roles WHERE rolcanlogin AND rolbypassrls AND NOT rolsuper)),
  'data', jsonb_build_object(
      'rls_bypassed', (SELECT rolsuper OR rolbypassrls FROM me),
      -- complete = no row hidden by RLS AND no table skipped for lack of SELECT; otherwise "unknown", never "zero"
      'row_visibility_complete', (SELECT rolsuper OR rolbypassrls FROM me)
                                 AND (SELECT count(*) FROM tbl) = (SELECT count(*) FROM cnt),
      'tables_counted', (SELECT count(*) FROM cnt),
      'tables_not_readable', (SELECT count(*) FROM tbl) - (SELECT count(*) FROM cnt),
      'unreadable_tables', (SELECT coalesce(jsonb_agg(t.relname ORDER BY t.relname), '[]'::jsonb)
                              FROM tbl t WHERE NOT has_table_privilege(current_user, t.oid, 'SELECT')),
      'tables_with_rows', (SELECT count(*) FROM cnt WHERE n > 0),
      'total_rows', (SELECT coalesce(sum(n), 0) FROM cnt),
      'row_counts', (SELECT coalesce(jsonb_object_agg(relname, n ORDER BY relname), '{}'::jsonb) FROM cnt),
      'quotes_approved_or_ordered', (SELECT (xpath('/row/total/text()', x))[1]::text::bigint FROM conf),
      'quotes_self_approved_or_approver_missing', (SELECT (xpath('/row/bad/text()', x))[1]::text::bigint FROM conf)),
  'limitations', (SELECT to_jsonb(array_remove(ARRAY[
      CASE WHEN NOT (SELECT rolsuper OR rolbypassrls FROM me)
           THEN 'session role does not bypass row level security: counts cover only the rows it may see, zero proves nothing' END,
      CASE WHEN (SELECT count(*) FROM tbl) - (SELECT count(*) FROM cnt) > 0
           THEN 'some tables are not readable by this session and were not counted (unknown, not zero): see data.unreadable_tables' END,
      CASE WHEN to_regclass('jw_dev.cinema_pg_quotes') IS NOT NULL AND (SELECT x FROM conf) IS NULL
           THEN 'cinema_pg_quotes cannot be counted by this session: the self-approval count is unavailable' END,
      CASE WHEN NOT EXISTS (SELECT 1 FROM sch)
           THEN 'schema jw_dev does not exist in this database' END,
      'facts about one database at one moment; not an approval and not a PASS'], NULL)))
)) AS preflight;
