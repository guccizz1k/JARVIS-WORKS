-- S4 DEV MIGRATION CANDIDATE (two-ledger single-writer claim). NOT APPLIED ANYWHERE.
-- Target: Supabase dev project (PostgreSQL 17), schema jw_dev, applied by the legacy-table
-- owner role (postgres, NOT a superuser). Run as ONE transaction (psql --single-transaction
-- or a single migration call). Refuses to run unless every precondition below holds, so it
-- can never attach to existing business data (reconcile first) or be applied twice.
--
-- Differences from scripts/review/cinema_pg_s4_atomic_gate.sql (disposable-PG17-only):
--   * no superuser / database-name check; instead exact ownership, role-flag, empty-ledger,
--     absent-object and "no leftover temporary privilege" preconditions;
--   * temporary privileges are verified absent before and restored exactly afterwards;
--   * adds BEFORE UPDATE guard on the claim table's trigger tables for org_id (defense in
--     depth on top of the existing guard_core_trade_relationships / v82 identity triggers);
--   * claim triggers are AFTER INSERT (round 2): no orphan claims for ON CONFLICT / skipped rows (see the note at the function);
--   * claims are never deleted, so even a TRUNCATE of business tables cannot switch a tenant's ledger.
--
-- Hardening round 2 (independent review):
--   * emptiness checks are RLS-proof: the runner must be BYPASSRLS and counts run with row_security=off, so a
--     filtered read raises instead of silently returning 0 rows. The FORCE-RLS owner policy of cinema_pg_quotes
--     (org_id = session org) used to hide every row from the previous SET ROLE based check;
--   * the five ledger tables are locked (SHARE ROW EXCLUSIVE, lock_timeout 5s) between the checks and the trigger
--     installation, so no writer can slip a row in without a claim;
--   * the exact pg_auth_members rows and the CINEMA role attributes are fingerprinted inside the transaction before
--     the temporary grants and compared again at the end; any difference aborts the whole migration.
DO $pre$
DECLARE
  t text; v_owner oid; n int;
BEGIN
  PERFORM pg_catalog.set_config('lock_timeout','5s',true);
  PERFORM pg_catalog.set_config('row_security','off',true);   -- a read that RLS would filter now raises instead of undercounting
  IF current_setting('server_version_num')::int < 170000 THEN
    RAISE EXCEPTION 'S4 dev migration requires PostgreSQL 17+' USING ERRCODE='0A000';
  END IF;
  IF (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=current_user) THEN
    RAISE EXCEPTION 'S4 dev migration must run as the non-superuser table owner' USING ERRCODE='42501';
  END IF;
  IF NOT (SELECT rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=current_user) THEN
    RAISE EXCEPTION 'S4 dev migration runner must be BYPASSRLS so that emptiness checks cannot be hidden by row level security' USING ERRCODE='42501';
  END IF;
  IF to_regnamespace('jw_dev') IS NULL THEN RAISE EXCEPTION 'S4 prerequisite: schema jw_dev missing' USING ERRCODE='42501'; END IF;
  FOREACH t IN ARRAY ARRAY['quotes','orders','invoices','payments','cinema_pg_quotes'] LOOP
    IF to_regclass('jw_dev.'||t) IS NULL THEN
      RAISE EXCEPTION 'S4 prerequisite missing: jw_dev.%', t USING ERRCODE='42501';
    END IF;
    IF t = 'cinema_pg_quotes' THEN CONTINUE; END IF;  -- owned by jw_cinema_owner: locked and counted below ($pre2$)
    EXECUTE format('LOCK TABLE jw_dev.%I IN SHARE ROW EXCLUSIVE MODE', t);   -- fixed order; held until COMMIT
    EXECUTE format('SELECT count(*) FROM (SELECT 1 FROM jw_dev.%I LIMIT 1) x', t) INTO n;
    IF n <> 0 THEN
      RAISE EXCEPTION 'S4 refuses to attach to non-empty ledger table jw_dev.% (reconcile first)', t USING ERRCODE='23514';
    END IF;
  END LOOP;
  -- legacy tables must be owned by (or inheritable-owned by) the migrating role; cinema table by jw_cinema_owner
  FOREACH t IN ARRAY ARRAY['quotes','orders','invoices','payments'] LOOP
    SELECT relowner INTO v_owner FROM pg_catalog.pg_class WHERE oid=('jw_dev.'||t)::regclass;
    IF NOT pg_catalog.pg_has_role(current_user, v_owner, 'USAGE') THEN
      RAISE EXCEPTION 'S4: current_user does not own jw_dev.%', t USING ERRCODE='42501';
    END IF;
    IF NOT (SELECT relrowsecurity AND relforcerowsecurity FROM pg_catalog.pg_class WHERE oid=('jw_dev.'||t)::regclass) THEN
      RAISE EXCEPTION 'S4: jw_dev.% must keep FORCE ROW LEVEL SECURITY', t USING ERRCODE='42501';
    END IF;
  END LOOP;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_catalog.pg_class WHERE oid='jw_dev.cinema_pg_quotes'::regclass) <> 'jw_cinema_owner' THEN
    RAISE EXCEPTION 'S4: cinema_pg_quotes must be owned by jw_cinema_owner' USING ERRCODE='42501';
  END IF;
  -- role hardening must already be in place
  IF (SELECT count(*) FROM pg_catalog.pg_roles
      WHERE rolname IN ('jw_cinema_owner','jw_cinema_writer')
        AND NOT rolcanlogin AND NOT rolbypassrls AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb) <> 2 THEN
    RAISE EXCEPTION 'S4: CINEMA roles missing or not NOLOGIN/NOBYPASSRLS/NOSUPERUSER' USING ERRCODE='42501';
  END IF;
  -- nothing S4-ish may exist yet
  IF to_regclass('jw_dev.cinema_pg_ledger_claims') IS NOT NULL
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid=p.pronamespace
               WHERE s.nspname='jw_dev' AND p.proname LIKE 'cinema\_pg\_s4\_%')
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_trigger g WHERE g.tgname LIKE 'cinema\_pg\_s4\_%' AND NOT g.tgisinternal) THEN
    RAISE EXCEPTION 'S4 objects already exist; refusing to re-apply' USING ERRCODE='23505';
  END IF;
  -- no *effective* (SET/INHERIT) privilege may be left over. The creator's baseline ADMIN-only
  -- membership (set=false, inherit=false) that PostgreSQL 16+ records at CREATE ROLE is expected.
  IF pg_catalog.has_schema_privilege('jw_cinema_owner','jw_dev','CREATE')
     OR pg_catalog.has_table_privilege('jw_cinema_owner','jw_dev.quotes','TRIGGER')
     OR pg_catalog.has_table_privilege('jw_cinema_owner','jw_dev.orders','TRIGGER')
     OR pg_catalog.has_table_privilege('jw_cinema_owner','jw_dev.invoices','TRIGGER')
     OR pg_catalog.has_table_privilege('jw_cinema_owner','jw_dev.payments','TRIGGER')
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles a ON a.oid=m.roleid
               JOIN pg_catalog.pg_roles b ON b.oid=m.member WHERE a.rolname='jw_cinema_owner' AND b.rolname=current_user
                 AND (m.set_option OR m.inherit_option)) THEN
    RAISE EXCEPTION 'S4: unexpected pre-existing jw_cinema_owner privilege/membership' USING ERRCODE='42501';
  END IF;
  -- Supabase's postgres inherits pg_read_all_data and therefore ALREADY reads every table. Remember the runner's own SELECT state:
  -- a temporary grant is only made (and later revoked) when it is missing, and the end state must equal this one.
  PERFORM pg_catalog.set_config('jw.s4_runner_select', pg_catalog.has_table_privilege(current_user,'jw_dev.cinema_pg_quotes','SELECT')::text, true);
  -- Fingerprint every pg_auth_members row that involves a CINEMA role, plus the CINEMA role attributes. Compared in $post$.
  PERFORM pg_catalog.set_config('jw.s4_member_fp', (SELECT pg_catalog.md5(coalesce(pg_catalog.string_agg(
            m.roleid::text||':'||m.member::text||':'||m.grantor::text||':'||m.admin_option::text||m.inherit_option::text||m.set_option::text,'|'
            ORDER BY m.roleid,m.member,m.grantor),'')) FROM pg_catalog.pg_auth_members m
          WHERE m.roleid IN (SELECT oid FROM pg_catalog.pg_roles WHERE rolname LIKE 'jw\_cinema\_%')
             OR m.member IN (SELECT oid FROM pg_catalog.pg_roles WHERE rolname LIKE 'jw\_cinema\_%')), true);
  PERFORM pg_catalog.set_config('jw.s4_role_fp', (SELECT pg_catalog.md5(coalesce(pg_catalog.string_agg(
            rolname||rolsuper::text||rolinherit::text||rolcreaterole::text||rolcreatedb::text||rolcanlogin::text||rolreplication::text||rolbypassrls::text||rolconnlimit::text,'|'
            ORDER BY rolname),'')) FROM pg_catalog.pg_roles WHERE rolname LIKE 'jw\_cinema\_%'), true);
  PERFORM pg_catalog.set_config('row_security','on',true);
END $pre$;

-- Temporary privileges (all removed again before the end; verified in the $post$ block).
GRANT jw_cinema_owner TO CURRENT_USER WITH SET TRUE, INHERIT FALSE;
-- Step 1 (as the table owner): freeze CINEMA writers and give the runner a READ window on cinema_pg_quotes, because the
-- owner itself sees ZERO rows through its FORCE-RLS policy when no session is set (that made the old check vacuous).
SET LOCAL ROLE jw_cinema_owner;
LOCK TABLE jw_dev.cinema_pg_quotes IN SHARE ROW EXCLUSIVE MODE;
DO $g1$ BEGIN
  IF pg_catalog.current_setting('jw.s4_runner_select', true) IS DISTINCT FROM 'true' THEN
    EXECUTE format('GRANT SELECT ON TABLE jw_dev.cinema_pg_quotes TO %I', session_user);
  END IF;
END $g1$;
RESET ROLE;
-- Step 2 (as the BYPASSRLS runner, row_security=off): count the REAL rows.
DO $pre2$
DECLARE n bigint;
BEGIN
  PERFORM pg_catalog.set_config('row_security','off',true);
  SELECT count(*) INTO n FROM (SELECT 1 FROM jw_dev.cinema_pg_quotes LIMIT 1) x;
  PERFORM pg_catalog.set_config('row_security','on',true);
  IF n <> 0 THEN
    RAISE EXCEPTION 'S4 refuses to attach to non-empty ledger table jw_dev.cinema_pg_quotes (reconcile first)' USING ERRCODE='23514';
  END IF;
END $pre2$;
GRANT CREATE ON SCHEMA jw_dev TO jw_cinema_owner;
GRANT TRIGGER ON jw_dev.quotes, jw_dev.orders, jw_dev.invoices, jw_dev.payments TO jw_cinema_owner;
SET LOCAL ROLE jw_cinema_owner;
-- S4_BUILD_PHASE (all temporary privileges are active here; the CI harness inspects this exact state)

CREATE TABLE jw_dev.cinema_pg_ledger_claims (
  org_id text PRIMARY KEY CHECK(length(btrim(org_id)) BETWEEN 1 AND 128),
  ledger text NOT NULL CHECK(ledger IN ('legacy','cinema')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK(org_id = btrim(org_id))
);
ALTER TABLE jw_dev.cinema_pg_ledger_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.cinema_pg_ledger_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY cinema_pg_claims_owner_internal
  ON jw_dev.cinema_pg_ledger_claims FOR ALL TO jw_cinema_owner USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE jw_dev.cinema_pg_ledger_claims FROM PUBLIC, jw_cinema_writer, jw_app_dev, anon, authenticated;

-- The claim is taken by an AFTER INSERT row trigger, never BEFORE: a BEFORE trigger also fires for rows that are then NOT inserted
-- (INSERT ... ON CONFLICT DO NOTHING / DO UPDATE, or another BEFORE trigger returning NULL), which would leave an orphan claim
-- that reserves a tenant for a ledger it never wrote to. AFTER fires only for rows that really exist; a refusal still aborts the
-- statement, so no row of the wrong ledger can be committed.
CREATE FUNCTION jw_dev.cinema_pg_s4_claim_on_insert()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog AS $trigger$
DECLARE expected text; actual text;
BEGIN
  IF TG_OP IS DISTINCT FROM 'INSERT' OR TG_TABLE_SCHEMA IS DISTINCT FROM 'jw_dev' THEN
    RAISE EXCEPTION 'S4 trigger called outside approved insert' USING ERRCODE='42501';
  END IF;
  expected := CASE WHEN TG_TABLE_NAME='cinema_pg_quotes' THEN 'cinema'
                   WHEN TG_TABLE_NAME IN ('quotes','orders','invoices','payments') THEN 'legacy' END;
  IF expected IS NULL OR NEW.org_id IS NULL OR length(btrim(NEW.org_id)) NOT BETWEEN 1 AND 128
     OR NEW.org_id <> btrim(NEW.org_id) THEN
    RAISE EXCEPTION 'S4 invalid ledger or organization' USING ERRCODE='23514';
  END IF;
  INSERT INTO jw_dev.cinema_pg_ledger_claims(org_id,ledger) VALUES (NEW.org_id, expected)
  ON CONFLICT (org_id) DO UPDATE SET ledger = jw_dev.cinema_pg_ledger_claims.ledger
  RETURNING ledger INTO actual;
  IF actual IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'S4 tenant ledger already reserved for another writer' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $trigger$;

-- org_id may never move a row between tenants (and therefore between ledgers).
CREATE FUNCTION jw_dev.cinema_pg_s4_org_immutable()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog AS $trigger$
BEGIN
  IF NEW.org_id IS DISTINCT FROM OLD.org_id THEN
    RAISE EXCEPTION 'S4: organization cannot change on a ledger row' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $trigger$;

REVOKE ALL ON FUNCTION jw_dev.cinema_pg_s4_claim_on_insert(), jw_dev.cinema_pg_s4_org_immutable()
  FROM PUBLIC, anon, authenticated, jw_app_dev, jw_cinema_writer;

CREATE TRIGGER cinema_pg_s4_claim_new_quote   AFTER INSERT ON jw_dev.cinema_pg_quotes FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_s4_claim_on_insert();
CREATE TRIGGER cinema_pg_s4_claim_legacy_quote   AFTER INSERT ON jw_dev.quotes   FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_s4_claim_on_insert();
CREATE TRIGGER cinema_pg_s4_claim_legacy_order   AFTER INSERT ON jw_dev.orders   FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_s4_claim_on_insert();
CREATE TRIGGER cinema_pg_s4_claim_legacy_invoice AFTER INSERT ON jw_dev.invoices FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_s4_claim_on_insert();
CREATE TRIGGER cinema_pg_s4_claim_legacy_payment AFTER INSERT ON jw_dev.payments FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_s4_claim_on_insert();
CREATE TRIGGER cinema_pg_s4_org_new_quote   BEFORE UPDATE OF org_id ON jw_dev.cinema_pg_quotes FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_s4_org_immutable();
CREATE TRIGGER cinema_pg_s4_org_legacy_quote   BEFORE UPDATE OF org_id ON jw_dev.quotes   FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_s4_org_immutable();
CREATE TRIGGER cinema_pg_s4_org_legacy_order   BEFORE UPDATE OF org_id ON jw_dev.orders   FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_s4_org_immutable();
CREATE TRIGGER cinema_pg_s4_org_legacy_invoice BEFORE UPDATE OF org_id ON jw_dev.invoices FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_s4_org_immutable();
CREATE TRIGGER cinema_pg_s4_org_legacy_payment BEFORE UPDATE OF org_id ON jw_dev.payments FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_s4_org_immutable();

DO $g2$ BEGIN
  IF pg_catalog.current_setting('jw.s4_runner_select', true) IS DISTINCT FROM 'true' THEN
    EXECUTE format('REVOKE SELECT ON TABLE jw_dev.cinema_pg_quotes FROM %I', session_user);
  END IF;
END $g2$;
RESET ROLE;
REVOKE TRIGGER ON jw_dev.quotes, jw_dev.orders, jw_dev.invoices, jw_dev.payments FROM jw_cinema_owner;
REVOKE CREATE ON SCHEMA jw_dev FROM jw_cinema_owner;
REVOKE jw_cinema_owner FROM CURRENT_USER;

DO $post$
BEGIN
  IF pg_catalog.has_table_privilege('jw_cinema_writer','jw_dev.cinema_pg_ledger_claims','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
     OR pg_catalog.has_table_privilege('jw_app_dev','jw_dev.cinema_pg_ledger_claims','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') THEN
    RAISE EXCEPTION 'S4 claims table exposed' USING ERRCODE='42501';
  END IF;
  IF pg_catalog.has_schema_privilege('jw_cinema_owner','jw_dev','CREATE')
     OR pg_catalog.has_table_privilege('jw_cinema_owner','jw_dev.quotes','TRIGGER')
     OR pg_catalog.has_table_privilege('jw_cinema_owner','jw_dev.orders','TRIGGER')
     OR pg_catalog.has_table_privilege('jw_cinema_owner','jw_dev.invoices','TRIGGER')
     OR pg_catalog.has_table_privilege('jw_cinema_owner','jw_dev.payments','TRIGGER')
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles a ON a.oid=m.roleid
               JOIN pg_catalog.pg_roles b ON b.oid=m.member WHERE a.rolname='jw_cinema_owner' AND b.rolname=current_user
                 AND (m.set_option OR m.inherit_option))
     OR pg_catalog.has_table_privilege(current_user,'jw_dev.cinema_pg_quotes','SELECT')::text IS DISTINCT FROM pg_catalog.current_setting('jw.s4_runner_select', true) THEN
    RAISE EXCEPTION 'S4 temporary privilege/membership not removed' USING ERRCODE='42501';
  END IF;
  IF coalesce(pg_catalog.current_setting('jw.s4_member_fp', true),'') = '' OR coalesce(pg_catalog.current_setting('jw.s4_role_fp', true),'') = '' THEN
    RAISE EXCEPTION 'S4: membership fingerprint missing (the migration must run inside ONE transaction)' USING ERRCODE='25P01';
  END IF;
  IF (SELECT pg_catalog.md5(coalesce(pg_catalog.string_agg(
            m.roleid::text||':'||m.member::text||':'||m.grantor::text||':'||m.admin_option::text||m.inherit_option::text||m.set_option::text,'|'
            ORDER BY m.roleid,m.member,m.grantor),'')) FROM pg_catalog.pg_auth_members m
          WHERE m.roleid IN (SELECT oid FROM pg_catalog.pg_roles WHERE rolname LIKE 'jw\_cinema\_%')
             OR m.member IN (SELECT oid FROM pg_catalog.pg_roles WHERE rolname LIKE 'jw\_cinema\_%'))
       IS DISTINCT FROM pg_catalog.current_setting('jw.s4_member_fp', true) THEN
    RAISE EXCEPTION 'S4: CINEMA role memberships differ from the pre-install fingerprint' USING ERRCODE='42501';
  END IF;
  IF (SELECT pg_catalog.md5(coalesce(pg_catalog.string_agg(
            rolname||rolsuper::text||rolinherit::text||rolcreaterole::text||rolcreatedb::text||rolcanlogin::text||rolreplication::text||rolbypassrls::text||rolconnlimit::text,'|'
            ORDER BY rolname),'')) FROM pg_catalog.pg_roles WHERE rolname LIKE 'jw\_cinema\_%')
       IS DISTINCT FROM pg_catalog.current_setting('jw.s4_role_fp', true) THEN
    RAISE EXCEPTION 'S4: CINEMA role attributes differ from the pre-install fingerprint' USING ERRCODE='42501';
  END IF;
  IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgname LIKE 'cinema\_pg\_s4\_%' AND NOT tgisinternal AND tgenabled='O') <> 10 THEN
    RAISE EXCEPTION 'S4 expected exactly 10 enabled triggers' USING ERRCODE='23514';
  END IF;
END $post$;
