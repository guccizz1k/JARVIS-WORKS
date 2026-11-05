-- P2 DRAFT: least-privilege LOGIN role for the CINEMA business-write path. NOT applied anywhere.
-- No password appears in this file. After approval the owner sets it out-of-band (psql \password jw_cinema_login
-- or the Supabase dashboard) and stores the connection string only in the server's secret store.
-- Until a password is set a password-auth login is impossible (rolpassword IS NULL).
DO $pre$
BEGIN
  IF (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
    RAISE EXCEPTION 'P2 refused: run as a non-superuser admin role';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jw_cinema_login') THEN
    RAISE EXCEPTION 'P2 refused: jw_cinema_login already exists';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jw_cinema_writer' AND NOT rolcanlogin AND NOT rolbypassrls AND NOT rolsuper) THEN
    RAISE EXCEPTION 'P2 refused: jw_cinema_writer missing or unsafe';
  END IF;
END $pre$;
CREATE ROLE jw_cinema_login LOGIN NOINHERIT NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION CONNECTION LIMIT 8;
ALTER ROLE jw_cinema_login SET statement_timeout = '15s';
ALTER ROLE jw_cinema_login SET lock_timeout = '5s';
ALTER ROLE jw_cinema_login SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE jw_cinema_login SET search_path = 'pg_catalog';
-- may only SET ROLE to the writer; inherits nothing; cannot administer anything
GRANT jw_cinema_writer TO jw_cinema_login WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;
DO $post$
BEGIN
  IF (SELECT count(*) FROM pg_auth_members WHERE member = 'jw_cinema_login'::regrole) <> 1 THEN
    RAISE EXCEPTION 'P2 post-check failed: unexpected memberships';
  END IF;
END $post$;
