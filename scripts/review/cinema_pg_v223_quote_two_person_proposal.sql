-- V22.3 PROPOSAL (NOT APPLIED to any Supabase project): database-level two-person rule for quotes.
--
-- Measured fact: cinema_pg_quote_transition requires an administrator to approve but never compares the
-- approver with the submitter, and the audited engine test script itself approves with the submitting
-- administrator in three places. So this is a SEPARATE migration, applied AFTER the engine and its
-- 222-case gate; the audited engine and its tests are not edited.
--
-- NOT VALID: new and updated rows are checked at once, rows that already exist are not.
-- IMPORTANT: approved_by is nullable in the real development database. IS DISTINCT FROM
-- treats (NULL, non-NULL) as DISTINCT and would silently accept missing approvers.
-- Require BOTH submitted_by and approved_by to be non-NULL before comparing identity. Existing rows
-- where one person submitted and approved must be reviewed by the owner first (query below), then:
--   ALTER TABLE jw_dev.cinema_pg_quotes VALIDATE CONSTRAINT cinema_pg_quote_two_person;
--
--   -- review query (counts only):
--   SELECT count(*) FROM jw_dev.cinema_pg_quotes
--    WHERE status IN ('approved','ordered') AND (submitted_by IS NULL OR approved_by IS NULL OR approved_by IS NOT DISTINCT FROM submitted_by);
BEGIN;
GRANT jw_cinema_owner TO CURRENT_USER WITH SET TRUE, INHERIT FALSE;
SET LOCAL ROLE jw_cinema_owner;
ALTER TABLE jw_dev.cinema_pg_quotes
  ADD CONSTRAINT cinema_pg_quote_two_person
  CHECK (status NOT IN ('approved','ordered')
         OR (submitted_by IS NOT NULL AND approved_by IS NOT NULL AND approved_by IS DISTINCT FROM submitted_by)) NOT VALID;
RESET ROLE;
REVOKE jw_cinema_owner FROM CURRENT_USER;
COMMIT;
