-- V22.3 Track B (issue #140, B1) -- IMMEDIATE REVOCATION of the read-only backup role jw_backup_ro.   NOT APPLIED.
--
-- Use when the DSN or password may have leaked, or when the backups are finished and the role is not yet dropped.
-- It does not drop the role (cinema_pg_v223_backup_role_rollback.sql does) and it does not touch any grant, so the
-- role can be re-enabled later with a separate approval: `ALTER ROLE jw_backup_ro LOGIN;` (the renew file does NOT
-- re-enable LOGIN on purpose).
-- Run as the project admin, one transaction, then the optional session cut:
--   psql "<admin DSN>" -X -v ON_ERROR_STOP=1 -f scripts/review/cinema_pg_v223_backup_role_revoke.sql
-- Ending sessions that are already open needs pg_signal_backend (the observed admin has it). If that privilege is
-- missing the last statement fails and the NOLOGIN above still stands.
BEGIN;
ALTER ROLE jw_backup_ro NOLOGIN;
COMMIT;
SELECT count(*) AS sessions_terminated
  FROM (SELECT pg_terminate_backend(pid) FROM pg_stat_activity
         WHERE usename = 'jw_backup_ro' AND pid <> pg_backend_pid()) t;
