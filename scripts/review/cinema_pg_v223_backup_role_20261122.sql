-- Owner-approved 2026-11-22 development B2/B3 only.
-- Approval recorded at 2026-11-22 15:50:58 KST; expires 20:50:58 KST.
-- No production access. Existing expired approval scripts remain unchanged.
\set ON_ERROR_STOP on
BEGIN;
SELECT format('DO $check$ BEGIN '
 'IF clock_timestamp() >= %2$L::timestamptz THEN '
 'RAISE EXCEPTION ''2026-11-22 approval expired''; END IF; '
 'IF %1$L::timestamptz <= clock_timestamp() '
 'OR %1$L::timestamptz > clock_timestamp() + interval ''5 hours'' '
 'OR %1$L::timestamptz > %2$L::timestamptz THEN '
 'RAISE EXCEPTION ''invalid backup expiry''; END IF; '
 'END $check$', :'valid_until', '2026-11-22 20:50:58+09') \gexec
DO $role$
BEGIN
 IF current_user <> 'postgres' OR current_database() <> 'postgres' THEN
   RAISE EXCEPTION 'unexpected source administrator or database';
 END IF;
 IF NOT EXISTS (
   SELECT 1 FROM pg_roles WHERE rolname='jw_backup_ro'
     AND NOT rolcanlogin AND rolbypassrls AND NOT rolsuper
     AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication
     AND rolconnlimit=2 AND rolvaliduntil <= clock_timestamp()
 ) THEN
   RAISE EXCEPTION 'backup role not disabled or least-privilege';
 END IF;
 IF EXISTS (SELECT 1 FROM pg_stat_activity WHERE usename='jw_backup_ro') THEN
   RAISE EXCEPTION 'backup role has sessions';
 END IF;
 IF EXISTS (
   SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON m.member=r.oid
   WHERE r.rolname='jw_backup_ro'
 ) THEN
   RAISE EXCEPTION 'backup role inherits membership';
 END IF;
 IF has_schema_privilege('jw_backup_ro','jw_dev','CREATE') THEN
   RAISE EXCEPTION 'backup role can create schema objects';
 END IF;
 IF EXISTS (
   SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p')
     AND (has_table_privilege('jw_backup_ro',c.oid,'INSERT')
       OR has_table_privilege('jw_backup_ro',c.oid,'UPDATE')
       OR has_table_privilege('jw_backup_ro',c.oid,'DELETE')
       OR has_table_privilege('jw_backup_ro',c.oid,'TRUNCATE')
       OR has_table_privilege('jw_backup_ro',c.oid,'TRIGGER')
       OR has_table_privilege('jw_backup_ro',c.oid,'REFERENCES'))
 ) THEN
   RAISE EXCEPTION 'unexpected write or administrative privilege';
 END IF;
 IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
     WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p')
       AND has_table_privilege('jw_backup_ro',c.oid,'SELECT')) <> 65 THEN
   RAISE EXCEPTION 'expected 65 readable tables';
 END IF;
END $role$;
ALTER ROLE jw_backup_ro VALID UNTIL :'valid_until' LOGIN;
COMMIT;
