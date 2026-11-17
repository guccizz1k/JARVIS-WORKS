-- JARVIS-WORKS V22.3: 2026-11-17 single-use owner-authorized backup login.
-- This NEW file does not alter, relax, or renew the EXPIRED 2026-11-11 authorization.
-- Must run only in owner Codespaces through the isolated B2/B3 launcher after
-- verified exact project/TLS/admin, encrypted key, and empty disposable PG17.
-- Renewed owner approval: 2026-11-17 16:00 through 2026-11-20 16:00 KST.
-- This approval is 72h to execute work, NOT 72h of continuous LOGIN.
-- Each activation is strictly bounded to under five hours; fail closed after deadline.
-- This file changes ONLY LOGIN and VALID UNTIL on the already-existing role.
\set ON_ERROR_STOP on
BEGIN;
SELECT format('DO $check$ BEGIN '
 'IF clock_timestamp() >= %2$L::timestamptz THEN '
 'RAISE EXCEPTION ''2026-11-17 owner approval has expired''; END IF; '
 'IF %1$L::timestamptz <= clock_timestamp() '
 'OR %1$L::timestamptz > clock_timestamp() + interval ''5 hours'' '
 'OR %1$L::timestamptz > %2$L::timestamptz THEN '
 'RAISE EXCEPTION ''invalid or over-five-hour backup expiry''; END IF; '
 'END $check$', :'valid_until', '2026-11-20 16:00:00+09') \gexec

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
   RAISE EXCEPTION 'backup role disabled/expired/least-privilege preconditions failed';
 END IF;
 IF EXISTS (SELECT 1 FROM pg_stat_activity WHERE usename='jw_backup_ro') THEN
   RAISE EXCEPTION 'backup role still has active sessions';
 END IF;
 IF EXISTS (
   SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON m.member=r.oid
   WHERE r.rolname='jw_backup_ro'
 ) THEN
   RAISE EXCEPTION 'backup role unexpectedly inherits membership';
 END IF;
 IF has_schema_privilege('jw_backup_ro','jw_dev','CREATE') THEN
   RAISE EXCEPTION 'backup role can create in source schema';
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
   RAISE EXCEPTION 'backup role has unexpected table write/admin privileges';
 END IF;
 IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p')
      AND has_table_privilege('jw_backup_ro',c.oid,'SELECT')) <> 65 THEN
   RAISE EXCEPTION 'backup role cannot read all expected 65 tables';
 END IF;
END $role$;
ALTER ROLE jw_backup_ro VALID UNTIL :'valid_until' LOGIN;
COMMIT;
