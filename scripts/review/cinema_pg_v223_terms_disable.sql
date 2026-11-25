-- LOSSLESS rollback of cinema_pg_v223_terms_proposal.sql (REVIEW CANDIDATE, not applied anywhere).
-- Stops NEW order due dates / invoice pay-by dates / payment notes by revoking EXECUTE from the writer.
-- Tables, rows and SELECT stay: stored values remain visible, nothing is deleted. Re-enable with
-- cinema_pg_v223_terms_enable.sql. The legacy-contract router detects EXECUTE and refuses (409) instead
-- of dropping a user's value.
BEGIN;
REVOKE EXECUTE ON FUNCTION jw_dev.cinema_pg_order_terms_set(text,text,date),
                           jw_dev.cinema_pg_invoice_terms_set(text,text,date),
                           jw_dev.cinema_pg_payment_note_set(text,text,text) FROM jw_cinema_writer;
COMMIT;
