-- Rollback for cinema_pg_s4_dev_migration.sql (dev has zero ledger rows; the claim table is dropped).
-- Run as the SAME non-superuser owner role, as ONE transaction. DROP TRIGGER needs table OWNERSHIP,
-- so legacy-table triggers are dropped as the owner; objects owned by jw_cinema_owner are dropped under SET ROLE.
DO $r1$
DECLARE r record;
BEGIN
  FOR r IN SELECT g.tgname::text AS tgname, c.relname::text AS relname FROM pg_catalog.pg_trigger g
           JOIN pg_catalog.pg_class c ON c.oid=g.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
           WHERE n.nspname='jw_dev' AND g.tgname LIKE 'cinema\_pg\_s4\_%' AND NOT g.tgisinternal
             AND c.relname IN ('quotes','orders','invoices','payments') LOOP
    EXECUTE format('DROP TRIGGER %I ON jw_dev.%I', r.tgname, r.relname);
  END LOOP;
END $r1$;
GRANT jw_cinema_owner TO CURRENT_USER WITH SET TRUE, INHERIT FALSE;
SET LOCAL ROLE jw_cinema_owner;
DROP TRIGGER cinema_pg_s4_claim_new_quote ON jw_dev.cinema_pg_quotes;
DROP TRIGGER cinema_pg_s4_org_new_quote ON jw_dev.cinema_pg_quotes;
DROP FUNCTION jw_dev.cinema_pg_s4_claim_on_insert();
DROP FUNCTION jw_dev.cinema_pg_s4_org_immutable();
DROP TABLE jw_dev.cinema_pg_ledger_claims;
RESET ROLE;
REVOKE jw_cinema_owner FROM CURRENT_USER;
