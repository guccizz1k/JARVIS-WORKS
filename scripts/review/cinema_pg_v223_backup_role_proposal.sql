-- PROPOSAL (option B of docs/review/cinema-pg-v223-backup-role-proposal.md). NOT EXECUTED ON SUPABASE.
-- Needs a separate owner approval. Run by the project admin role (Supabase: postgres = CREATEROLE +
-- BYPASSRLS, ADMIN-only member of jw_cinema_owner). valid_until must be an explicitly approved future expiry no more than 5 hours ahead.
-- No password here: set it interactively with \password jw_backup_ro AFTER this commits.
-- ONE transaction (V22.3 gate finding): if any GRANT fails, the temporary INHERIT membership of the admin
-- in jw_cinema_owner must not survive. Run with psql -v ON_ERROR_STOP=1.
-- The original owner approval is expired. This file does not renew it.
-- PostgreSQL refuses expired or >5-hour role creation atomically.
BEGIN;
SELECT format('DO $g$ BEGIN '
              'IF %1$L::timestamptz <= now() OR %1$L::timestamptz > now() + interval ''5 hours'' THEN '
              'RAISE EXCEPTION ''jw_backup_ro creation requires an approved future expiry within 5 hours''; END IF; '
              'END $g$', :'valid_until') \gexec
CREATE ROLE jw_backup_ro LOGIN BYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
  CONNECTION LIMIT 2 VALID UNTIL :'valid_until';
ALTER ROLE jw_backup_ro SET default_transaction_read_only = on;
GRANT jw_cinema_owner TO CURRENT_USER WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
GRANT USAGE ON SCHEMA jw_dev TO jw_backup_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA jw_dev TO jw_backup_ro;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA jw_dev TO jw_backup_ro;
REVOKE jw_cinema_owner FROM CURRENT_USER GRANTED BY CURRENT_USER;
COMMIT;
