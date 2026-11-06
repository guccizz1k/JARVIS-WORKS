-- ROLLBACK for cinema_pg_v223_backup_role_proposal.sql. ONE transaction; touches no table data.
-- V22.3 gate finding: "DROP OWNED BY jw_backup_ro" is refused for a non-superuser CREATEROLE admin
-- (PG16+: it holds only ADMIN on the role it created). So: disable login first, revoke the grants
-- explicitly (the ones on jw_cinema_owner's tables need the same temporary grant right as the proposal),
-- then drop the role. Idempotent: does nothing when the role does not exist.
BEGIN;
DO $r$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='jw_backup_ro') THEN
    EXECUTE 'ALTER ROLE jw_backup_ro NOLOGIN';
    EXECUTE 'GRANT jw_cinema_owner TO CURRENT_USER WITH ADMIN FALSE, INHERIT TRUE, SET FALSE';
    EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA jw_dev FROM jw_backup_ro';
    EXECUTE 'REVOKE ALL ON ALL SEQUENCES IN SCHEMA jw_dev FROM jw_backup_ro';
    EXECUTE 'REVOKE ALL ON SCHEMA jw_dev FROM jw_backup_ro';
    EXECUTE 'REVOKE jw_cinema_owner FROM CURRENT_USER GRANTED BY CURRENT_USER';
    EXECUTE 'DROP ROLE jw_backup_ro';
  END IF;
END $r$;
COMMIT;
