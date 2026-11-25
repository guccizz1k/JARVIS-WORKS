-- ROLLBACK for cinema_pg_v223_quote_two_person_proposal.sql (REVIEW CANDIDATE, not applied anywhere).
-- Removes only the CHECK constraint; no row is changed. Idempotent. After this, the two-person rule is
-- enforced by the application layer only (pg_cinema_compat_v1.quote_approval_guard) - say so if you run it.
BEGIN;
GRANT jw_cinema_owner TO CURRENT_USER WITH SET TRUE, INHERIT FALSE;
SET LOCAL ROLE jw_cinema_owner;
ALTER TABLE jw_dev.cinema_pg_quotes DROP CONSTRAINT IF EXISTS cinema_pg_quote_two_person;
RESET ROLE;
REVOKE jw_cinema_owner FROM CURRENT_USER;
COMMIT;
