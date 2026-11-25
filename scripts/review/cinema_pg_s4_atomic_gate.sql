-- S4 experimental extension: disposable PostgreSQL 17 only; NOT a shared DB migration.
-- Applies on top of the CINEMA engine on a CLEAN synthetic database. Adds an
-- append-only per-tenant claim and minimal BEFORE INSERT guards on both ledgers.
-- Claim row uniqueness serializes all competing writers across connections.
-- Deliberately refuses old business data: reconciliation is a separate gate.
--
-- DO NOT apply to Supabase, staging, operating, or a populated database.
DO $pre$
DECLARE v_super boolean;
BEGIN
  SELECT r.rolsuper INTO v_super FROM pg_catalog.pg_roles r WHERE r.rolname=current_user;
  IF current_database() !~ '^jw_cinema_s4_gate_[0-9a-f]{8}$' OR v_super IS DISTINCT FROM TRUE THEN
    RAISE EXCEPTION 'S4 disposable PG17 only; refusing shared database' USING ERRCODE='42501';
  END IF;
  IF to_regclass('jw_dev.cinema_pg_quotes') IS NULL
     OR to_regclass('jw_dev.quotes') IS NULL
     OR to_regclass('jw_dev.orders') IS NULL
     OR to_regclass('jw_dev.invoices') IS NULL
     OR to_regclass('jw_dev.payments') IS NULL THEN
    RAISE EXCEPTION 'S4 prerequisites missing; fail closed' USING ERRCODE='42501';
  END IF;
  IF EXISTS(SELECT 1 FROM jw_dev.quotes) OR EXISTS(SELECT 1 FROM jw_dev.orders)
     OR EXISTS(SELECT 1 FROM jw_dev.invoices) OR EXISTS(SELECT 1 FROM jw_dev.payments)
     OR EXISTS(SELECT 1 FROM jw_dev.cinema_pg_quotes) THEN
    RAISE EXCEPTION 'S4 refuses to attach to existing ledger; reconcile first' USING ERRCODE='23514';
  END IF;
  IF to_regclass('jw_dev.cinema_pg_ledger_claims') IS NOT NULL THEN
    RAISE EXCEPTION 'S4 claim guard already exists' USING ERRCODE='23505';
  END IF;
END $pre$;

-- PostgreSQL managed ROLE practices: temporary privileges, all revoked before
-- COMMIT. In the disposable CI superuser this is additionally verified.
GRANT jw_cinema_owner TO CURRENT_USER WITH SET TRUE, INHERIT FALSE;
GRANT CREATE ON SCHEMA jw_dev TO jw_cinema_owner;
GRANT TRIGGER ON jw_dev.quotes, jw_dev.orders, jw_dev.invoices, jw_dev.payments
  TO jw_cinema_owner;
SET LOCAL ROLE jw_cinema_owner;

CREATE TABLE jw_dev.cinema_pg_ledger_claims (
  org_id text PRIMARY KEY CHECK(length(btrim(org_id)) BETWEEN 1 AND 128),
  ledger text NOT NULL CHECK(ledger IN ('legacy','cinema')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK(org_id = btrim(org_id))
);
ALTER TABLE jw_dev.cinema_pg_ledger_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.cinema_pg_ledger_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY cinema_pg_claims_owner_internal
  ON jw_dev.cinema_pg_ledger_claims FOR ALL TO jw_cinema_owner
  USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE jw_dev.cinema_pg_ledger_claims FROM PUBLIC, jw_cinema_writer, jw_app_dev;

CREATE FUNCTION jw_dev.cinema_pg_s4_claim_on_insert()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog AS $trigger$
DECLARE
  expected text;
  actual text;
BEGIN
  IF TG_OP IS DISTINCT FROM 'INSERT' OR TG_TABLE_SCHEMA IS DISTINCT FROM 'jw_dev' THEN
    RAISE EXCEPTION 'S4 trigger called outside approved insert' USING ERRCODE='42501';
  END IF;
  expected := CASE
    WHEN TG_TABLE_NAME='cinema_pg_quotes' THEN 'cinema'
    WHEN TG_TABLE_NAME IN ('quotes','orders','invoices','payments') THEN 'legacy'
    ELSE NULL END;
  IF expected IS NULL OR NEW.org_id IS NULL
     OR length(btrim(NEW.org_id)) NOT BETWEEN 1 AND 128
     OR NEW.org_id <> btrim(NEW.org_id) THEN
    RAISE EXCEPTION 'S4 invalid ledger or organization' USING ERRCODE='23514';
  END IF;

  -- Unique row lock is transaction-scoped. Competing first writers are
  -- serialized, including different app servers and concurrent PostgreSQL
  -- connections. On conflicting modes the second transaction always aborts.
  INSERT INTO jw_dev.cinema_pg_ledger_claims(org_id,ledger)
  VALUES (NEW.org_id, expected)
  ON CONFLICT (org_id) DO UPDATE
    SET ledger=jw_dev.cinema_pg_ledger_claims.ledger
  RETURNING ledger INTO actual;
  IF actual IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'S4 tenant ledger already reserved for another writer'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $trigger$;
REVOKE ALL ON FUNCTION jw_dev.cinema_pg_s4_claim_on_insert() FROM PUBLIC, anon,
  authenticated, jw_app_dev, jw_cinema_writer;

CREATE TRIGGER cinema_pg_s4_claim_new_quote
  BEFORE INSERT ON jw_dev.cinema_pg_quotes FOR EACH ROW
  EXECUTE FUNCTION jw_dev.cinema_pg_s4_claim_on_insert();
CREATE TRIGGER cinema_pg_s4_claim_legacy_quote
  BEFORE INSERT ON jw_dev.quotes FOR EACH ROW
  EXECUTE FUNCTION jw_dev.cinema_pg_s4_claim_on_insert();
CREATE TRIGGER cinema_pg_s4_claim_legacy_order
  BEFORE INSERT ON jw_dev.orders FOR EACH ROW
  EXECUTE FUNCTION jw_dev.cinema_pg_s4_claim_on_insert();
CREATE TRIGGER cinema_pg_s4_claim_legacy_invoice
  BEFORE INSERT ON jw_dev.invoices FOR EACH ROW
  EXECUTE FUNCTION jw_dev.cinema_pg_s4_claim_on_insert();
CREATE TRIGGER cinema_pg_s4_claim_legacy_payment
  BEFORE INSERT ON jw_dev.payments FOR EACH ROW
  EXECUTE FUNCTION jw_dev.cinema_pg_s4_claim_on_insert();

RESET ROLE;
REVOKE TRIGGER ON jw_dev.quotes, jw_dev.orders, jw_dev.invoices, jw_dev.payments
  FROM jw_cinema_owner;
REVOKE CREATE ON SCHEMA jw_dev FROM jw_cinema_owner;
REVOKE jw_cinema_owner FROM CURRENT_USER;

-- Fail closed: a client cannot select, insert or update claims. Business
-- identities are derived only from the triggering RLS-guarded INSERT.
DO $post$
BEGIN
  IF pg_catalog.has_table_privilege('jw_cinema_writer',
     'jw_dev.cinema_pg_ledger_claims','SELECT,INSERT,UPDATE,DELETE') THEN
    RAISE EXCEPTION 'S4 claims table exposed to writer' USING ERRCODE='42501';
  END IF;
  IF (SELECT count(*) FROM pg_catalog.pg_auth_members m
      JOIN pg_catalog.pg_roles a ON a.oid=m.roleid
      JOIN pg_catalog.pg_roles b ON b.oid=m.member
      WHERE a.rolname='jw_cinema_owner' AND b.rolname=current_user) <> 0 THEN
    RAISE EXCEPTION 'S4 temporary role membership not removed' USING ERRCODE='42501';
  END IF;
END $post$;
