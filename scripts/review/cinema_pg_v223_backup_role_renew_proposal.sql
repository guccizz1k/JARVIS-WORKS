-- V22.3 Track B (issue #140, B1) -- RENEW the EXPIRED read-only backup role jw_backup_ro.   NOT APPLIED.
--
-- Needs the owner's explicit, separate approval for the exact `valid_until` value. Nothing in this file has been run
-- against Supabase. It was run only on disposable PostgreSQL by scripts/ci_cinema_pg_v223_backup_role_renew_gate.py.
--
-- WHAT IT CHANGES: exactly ONE attribute, VALID UNTIL. No password (the existing verifier is kept), no GRANT/REVOKE,
-- no membership, no LOGIN/BYPASSRLS/CONNECTION LIMIT/default_transaction_read_only change, no object in jw_dev.
-- WHAT IT REFUSES (before any change, the whole transaction aborts):
--   * a window that is not in the future, or is more than 7 days ahead (the role reads every row; keep it short);
--   * a missing variable (psql then fails on the unexpanded :'valid_until');
--   * a database where jw_backup_ro does not exist (this file never creates the role; C does).
-- HOW TO RUN (owner's own terminal, admin DSN with sslmode=verify-full; the DSN never goes into chat or a log):
--   psql "<admin DSN>" -X -v ON_ERROR_STOP=1 -v valid_until='2026-11-10 12:00:00+09' \
--        -f scripts/review/cinema_pg_v223_backup_role_renew_proposal.sql
-- AFTER: run scripts/review/cinema_pg_v223_preflight_readonly.sql as jw_backup_ro; expect `violations: []`,
--   `tables_unreadable: 0`, `tables_writable: 0`. To end early: cinema_pg_v223_backup_role_revoke.sql.
BEGIN;
SELECT format('DO $g$ BEGIN '
              'IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ''jw_backup_ro'') THEN '
              'RAISE EXCEPTION ''jw_backup_ro does not exist: apply the backup-role proposal first''; END IF; '
              'IF %1$L::timestamptz <= now() OR %1$L::timestamptz > now() + interval ''7 days'' THEN '
              'RAISE EXCEPTION ''jw_backup_ro renewal window must be after now() and at most 7 days ahead''; END IF; '
              'END $g$', :'valid_until') \gexec
ALTER ROLE jw_backup_ro VALID UNTIL :'valid_until';
COMMIT;
