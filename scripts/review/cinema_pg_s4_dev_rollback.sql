-- Rollback for cinema_pg_s4_dev_migration.sql.  NOT APPLIED ANYWHERE.
--
-- SAFE-ONLY ROLLBACK. It removes S4 only while NOTHING has ever been written through it:
--   * jw_dev.cinema_pg_ledger_claims must hold 0 rows (claims are never deleted, so 0 claims means no tenant ever wrote), and
--   * jw_dev.quotes / orders / invoices / payments / cinema_pg_quotes must hold 0 rows.
-- Any row anywhere => SQL exception (SQLSTATE 55000), and because the whole rollback is ONE DO block (one atomic statement)
-- nothing at all has been dropped, granted or changed. An environment that already holds data is NOT rolled back by this
-- file: see docs/review/cinema-pg-p1-p2-install-rollback-recovery.md (separate approval + reconciliation).
--
-- Concurrency: every ledger table is locked ACCESS EXCLUSIVE in a fixed order (quotes, orders, invoices, payments,
-- cinema_pg_quotes, cinema_pg_ledger_claims) with lock_timeout 5s BEFORE the emptiness check; the locks are held until the
-- statement's transaction ends, so no writer can add a row between the check and the DROPs. A busy table makes the
-- rollback fail with 55P03 (lock_not_available) instead of waiting forever or racing.
-- Counts are RLS-proof: the runner must be BYPASSRLS and counts run with row_security=off (a filtered read raises).
-- The CINEMA owner's FORCE-RLS policy hides every row from the owner, so the owner is never used to count; it only grants
-- the runner a temporary SELECT, which is revoked again.
-- At the end the block re-checks that no S4 object remains and that memberships, role attributes and ACLs are
-- identical to the state it started from; any difference raises and undoes everything.
-- Run as the SAME non-superuser owner role as the install (psql --single-transaction is fine but not required).
DO $rb$
DECLARE
  v_me text := session_user;
  t text; r record; busy text[] := ARRAY[]::text[]; n int;
  v_mfp text; v_rfp text; v_acl text; v_mfp_after text; v_rfp_after text; v_acl_after text; v_sel_cq boolean; v_sel_cl boolean;
  mfp_sql constant text := $q$SELECT pg_catalog.md5(coalesce(pg_catalog.string_agg(
        m.roleid::text||':'||m.member::text||':'||m.grantor::text||':'||m.admin_option::text||m.inherit_option::text||m.set_option::text,'|'
        ORDER BY m.roleid,m.member,m.grantor),'')) FROM pg_catalog.pg_auth_members m
      WHERE m.roleid IN (SELECT oid FROM pg_catalog.pg_roles WHERE rolname LIKE 'jw\_cinema\_%')
         OR m.member IN (SELECT oid FROM pg_catalog.pg_roles WHERE rolname LIKE 'jw\_cinema\_%')$q$;
  rfp_sql constant text := $q$SELECT pg_catalog.md5(coalesce(pg_catalog.string_agg(
        rolname||rolsuper::text||rolinherit::text||rolcreaterole::text||rolcreatedb::text||rolcanlogin::text||rolreplication::text||rolbypassrls::text||rolconnlimit::text,'|'
        ORDER BY rolname),'')) FROM pg_catalog.pg_roles WHERE rolname LIKE 'jw\_cinema\_%'$q$;
  acl_sql constant text := $q$SELECT coalesce((SELECT pg_catalog.md5(coalesce(pg_catalog.string_agg(c.relname||coalesce(c.relacl::text,''),'|' ORDER BY c.relname),''))
        FROM pg_catalog.pg_class c WHERE c.relnamespace='jw_dev'::regnamespace
         AND c.relname IN ('quotes','orders','invoices','payments','cinema_pg_quotes')),'')
        ||'/'||coalesce((SELECT nspacl::text FROM pg_catalog.pg_namespace WHERE nspname='jw_dev'),'')$q$;
BEGIN
  PERFORM pg_catalog.set_config('lock_timeout','5s',true);
  PERFORM pg_catalog.set_config('row_security','off',true);   -- a read that RLS would filter raises instead of undercounting
  IF (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=current_user) THEN
    RAISE EXCEPTION 'S4 rollback must run as the non-superuser table owner' USING ERRCODE='42501';
  END IF;
  IF NOT (SELECT rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=current_user) THEN
    RAISE EXCEPTION 'S4 rollback runner must be BYPASSRLS so that emptiness checks cannot be hidden by row level security' USING ERRCODE='42501';
  END IF;
  IF to_regclass('jw_dev.cinema_pg_ledger_claims') IS NULL THEN
    RAISE EXCEPTION 'S4 rollback: claims table not found (S4 is not installed; nothing to roll back)' USING ERRCODE='55000';
  END IF;
  IF EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles a ON a.oid=m.roleid
               JOIN pg_catalog.pg_roles b ON b.oid=m.member WHERE a.rolname='jw_cinema_owner' AND b.rolname=current_user
                 AND (m.set_option OR m.inherit_option)) THEN
    RAISE EXCEPTION 'S4 rollback: unexpected pre-existing runner privilege/membership' USING ERRCODE='42501';
  END IF;
  -- Supabase's postgres inherits pg_read_all_data and already reads every table; only grant (and later revoke) what is missing.
  v_sel_cq := pg_catalog.has_table_privilege(current_user,'jw_dev.cinema_pg_quotes','SELECT');
  v_sel_cl := pg_catalog.has_table_privilege(current_user,'jw_dev.cinema_pg_ledger_claims','SELECT');
  EXECUTE mfp_sql INTO v_mfp; EXECUTE rfp_sql INTO v_rfp; EXECUTE acl_sql INTO v_acl;

  -- 1. lock every table that can receive data, fixed order, as the runner (owner of the four legacy tables)
  FOREACH t IN ARRAY ARRAY['quotes','orders','invoices','payments'] LOOP
    EXECUTE format('LOCK TABLE jw_dev.%I IN ACCESS EXCLUSIVE MODE', t);
  END LOOP;
  -- 2. cinema_pg_quotes + claims are owned by jw_cinema_owner: lock them as the owner, and open a temporary READ window for the runner
  EXECUTE 'GRANT jw_cinema_owner TO CURRENT_USER WITH SET TRUE, INHERIT FALSE';
  EXECUTE 'SET LOCAL ROLE jw_cinema_owner';
  EXECUTE 'LOCK TABLE jw_dev.cinema_pg_quotes IN ACCESS EXCLUSIVE MODE';
  EXECUTE 'LOCK TABLE jw_dev.cinema_pg_ledger_claims IN ACCESS EXCLUSIVE MODE';
  IF NOT v_sel_cq THEN EXECUTE format('GRANT SELECT ON TABLE jw_dev.cinema_pg_quotes TO %I', v_me); END IF;
  IF NOT v_sel_cl THEN EXECUTE format('GRANT SELECT ON TABLE jw_dev.cinema_pg_ledger_claims TO %I', v_me); END IF;
  EXECUTE 'RESET ROLE';

  -- 3. refuse when anything is there (count as the BYPASSRLS runner; the locks above stop concurrent writers)
  FOREACH t IN ARRAY ARRAY['cinema_pg_ledger_claims','quotes','orders','invoices','payments','cinema_pg_quotes'] LOOP
    EXECUTE format('SELECT count(*) FROM (SELECT 1 FROM jw_dev.%I LIMIT 1) x', t) INTO n;
    IF n <> 0 THEN busy := busy || t; END IF;
  END LOOP;
  IF cardinality(busy) > 0 THEN
    RAISE EXCEPTION 'S4 rollback REFUSED: data exists in %. Nothing was changed. Existing data needs a separately approved reconciliation, not this script.',
      array_to_string(busy, ', ') USING ERRCODE='55000';
  END IF;

  -- 4. safe state: nothing was ever written. Drop S4 (legacy-table triggers need table OWNERSHIP = the runner).
  FOR r IN SELECT g.tgname::text AS tgname, c.relname::text AS relname FROM pg_catalog.pg_trigger g
           JOIN pg_catalog.pg_class c ON c.oid=g.tgrelid JOIN pg_catalog.pg_namespace s ON s.oid=c.relnamespace
           WHERE s.nspname='jw_dev' AND g.tgname LIKE 'cinema\_pg\_s4\_%' AND NOT g.tgisinternal
             AND c.relname IN ('quotes','orders','invoices','payments') ORDER BY c.relname, g.tgname LOOP
    EXECUTE format('DROP TRIGGER %I ON jw_dev.%I', r.tgname, r.relname);
  END LOOP;
  EXECUTE 'SET LOCAL ROLE jw_cinema_owner';
  EXECUTE 'DROP TRIGGER IF EXISTS cinema_pg_s4_claim_new_quote ON jw_dev.cinema_pg_quotes';
  EXECUTE 'DROP TRIGGER IF EXISTS cinema_pg_s4_org_new_quote ON jw_dev.cinema_pg_quotes';
  EXECUTE 'DROP FUNCTION IF EXISTS jw_dev.cinema_pg_s4_claim_on_insert()';
  EXECUTE 'DROP FUNCTION IF EXISTS jw_dev.cinema_pg_s4_org_immutable()';
  IF NOT v_sel_cq THEN EXECUTE format('REVOKE SELECT ON TABLE jw_dev.cinema_pg_quotes FROM %I', v_me); END IF;
  EXECUTE 'DROP TABLE jw_dev.cinema_pg_ledger_claims';
  EXECUTE 'RESET ROLE';
  EXECUTE 'REVOKE jw_cinema_owner FROM CURRENT_USER';

  -- 5. self-verification: any difference aborts (and undoes) the whole rollback
  IF to_regclass('jw_dev.cinema_pg_ledger_claims') IS NOT NULL
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace s ON s.oid=p.pronamespace
               WHERE s.nspname='jw_dev' AND p.proname LIKE 'cinema\_pg\_s4\_%')
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_trigger g WHERE g.tgname LIKE 'cinema\_pg\_s4\_%' AND NOT g.tgisinternal) THEN
    RAISE EXCEPTION 'S4 rollback: S4 objects remain' USING ERRCODE='55000';
  END IF;
  IF pg_catalog.has_table_privilege(current_user,'jw_dev.cinema_pg_quotes','SELECT') IS DISTINCT FROM v_sel_cq
     OR pg_catalog.has_schema_privilege('jw_cinema_owner','jw_dev','CREATE')
     OR pg_catalog.has_table_privilege('jw_cinema_owner','jw_dev.quotes','TRIGGER')
     OR pg_catalog.has_table_privilege('jw_cinema_owner','jw_dev.orders','TRIGGER')
     OR pg_catalog.has_table_privilege('jw_cinema_owner','jw_dev.invoices','TRIGGER')
     OR pg_catalog.has_table_privilege('jw_cinema_owner','jw_dev.payments','TRIGGER') THEN
    RAISE EXCEPTION 'S4 rollback: temporary privilege left behind' USING ERRCODE='42501';
  END IF;
  EXECUTE mfp_sql INTO v_mfp_after;
  IF v_mfp_after IS DISTINCT FROM v_mfp THEN
    RAISE EXCEPTION 'S4 rollback: CINEMA role memberships differ from the state before the rollback' USING ERRCODE='42501';
  END IF;
  EXECUTE rfp_sql INTO v_rfp_after;
  IF v_rfp_after IS DISTINCT FROM v_rfp THEN
    RAISE EXCEPTION 'S4 rollback: CINEMA role attributes differ from the state before the rollback' USING ERRCODE='42501';
  END IF;
  EXECUTE acl_sql INTO v_acl_after;
  IF v_acl_after IS DISTINCT FROM v_acl THEN
    RAISE EXCEPTION 'S4 rollback: table/schema ACLs differ from the state before the rollback' USING ERRCODE='42501';
  END IF;
END $rb$;
