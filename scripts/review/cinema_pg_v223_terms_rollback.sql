-- HARD rollback of cinema_pg_v223_terms_proposal.sql (REVIEW CANDIDATE, not applied anywhere).
-- Drops the three functions and three side tables ONLY IF THEY HOLD NO ROWS. With any stored due date,
-- pay-by date or note it refuses (would destroy user data); use cinema_pg_v223_terms_disable.sql instead.
-- The emptiness check runs as jw_cinema_owner WITHOUT BYPASSRLS, so it would only see the current session's
-- tenant: it therefore counts with row security OFF, which fails closed (error) for a role that FORCE RLS
-- applies to. Run by the migration owner (BYPASSRLS / table owner context) after review.
BEGIN;
SET LOCAL row_security = off;
DO $chk$
DECLARE n bigint;
BEGIN
  SELECT (SELECT count(*) FROM jw_dev.cinema_pg_order_terms) + (SELECT count(*) FROM jw_dev.cinema_pg_invoice_terms)
       + (SELECT count(*) FROM jw_dev.cinema_pg_payment_notes) INTO n;
  IF n > 0 THEN
    RAISE EXCEPTION 'terms rollback refused: % stored row(s) would be destroyed; use cinema_pg_v223_terms_disable.sql', n
      USING ERRCODE = '55000';
  END IF;
END $chk$;
GRANT jw_cinema_owner TO CURRENT_USER WITH SET TRUE, INHERIT FALSE;
SET LOCAL ROLE jw_cinema_owner;
DROP FUNCTION jw_dev.cinema_pg_order_terms_set(text,text,date);
DROP FUNCTION jw_dev.cinema_pg_invoice_terms_set(text,text,date);
DROP FUNCTION jw_dev.cinema_pg_payment_note_set(text,text,text);
DROP TABLE jw_dev.cinema_pg_order_terms;
DROP TABLE jw_dev.cinema_pg_invoice_terms;
DROP TABLE jw_dev.cinema_pg_payment_notes;
RESET ROLE;
REVOKE jw_cinema_owner FROM CURRENT_USER;
COMMIT;
