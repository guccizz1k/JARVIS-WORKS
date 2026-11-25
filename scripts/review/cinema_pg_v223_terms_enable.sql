-- Re-enable after cinema_pg_v223_terms_disable.sql (REVIEW CANDIDATE). Same grant as the proposal.
BEGIN;
GRANT EXECUTE ON FUNCTION jw_dev.cinema_pg_order_terms_set(text,text,date),
                          jw_dev.cinema_pg_invoice_terms_set(text,text,date),
                          jw_dev.cinema_pg_payment_note_set(text,text,text) TO jw_cinema_writer;
COMMIT;
