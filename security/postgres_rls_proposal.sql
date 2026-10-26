-- JARVIS WORKS V2.0 — HARDENED PostgreSQL RLS POLICY CANDIDATE.
-- NOT CONNECTED TO THE SQLITE APPLICATION. NEVER APPLY TO A LIVE DATABASE WITHOUT
-- A VERIFIED MIGRATION, SCHEMA BACKUP, ISOLATED INTEGRATION TESTS AND AUTH SERVICE.
-- PostgreSQL >=14, pgcrypto. Use a dedicated migration owner, NOT jw_app.
-- The old V1.8 design using a directly writable `jw.org_id` GUC was SPOOFABLE.
-- This replacement binds an MFA-verified session to a transaction-scoped,
-- database-signed organization claim. A raw SET jw.ctx_org cannot forge the proof.

BEGIN;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
-- Do not silently use a pgcrypto extension installed under a different schema.
-- Qualified function calls below require the extension to reside in public.
DO $preflight$
BEGIN
  IF pg_catalog.to_regprocedure('public.digest(bytea,text)') IS NULL
    OR pg_catalog.to_regprocedure('public.hmac(bytea,bytea,text)') IS NULL
    OR pg_catalog.to_regprocedure('public.gen_random_bytes(integer)') IS NULL THEN
    RAISE EXCEPTION 'pgcrypto functions must be installed in public schema; stop and audit extension placement';
  END IF;
END $preflight$;
CREATE SCHEMA IF NOT EXISTS jw_guard;
REVOKE ALL ON SCHEMA jw_guard FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA jw_guard TO jw_app;

DO $verify$
DECLARE app_oid oid; role_owner oid; item text;
BEGIN
  SELECT oid INTO app_oid FROM pg_catalog.pg_roles WHERE rolname='jw_app'
    AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole;
  IF app_oid IS NULL THEN
    RAISE EXCEPTION 'jw_app must exist with NOSUPERUSER NOBYPASSRLS NOCREATEROLE';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
    WHERE n.nspname='jw_guard' AND
      (n.nspowner=app_oid OR pg_catalog.pg_has_role(app_oid,n.nspowner,'MEMBER'))) THEN
    RAISE EXCEPTION 'jw_app must not own or inherit jw_guard schema owner privileges';
  END IF;
  IF pg_catalog.has_schema_privilege('jw_app','public','CREATE') THEN
    RAISE EXCEPTION 'jw_app must not have CREATE privilege on public schema';
  END IF;
  FOREACH item IN ARRAY ARRAY[
    'organizations','users','customers','quotes','orders','invoices','payments',
    'audit_logs','security_events','import_previews','quote_items','order_items',
    'invoice_items','sessions','mfa_credentials','mfa_recovery_codes','login_failures'
  ] LOOP
    SELECT relowner INTO role_owner FROM pg_catalog.pg_class
      WHERE oid=pg_catalog.to_regclass(pg_catalog.format('public.%I',item));
    IF role_owner IS NULL THEN RAISE EXCEPTION 'Missing migrated public table: %',item; END IF;
    IF role_owner=app_oid OR pg_catalog.pg_has_role(app_oid,role_owner,'MEMBER') THEN
      RAISE EXCEPTION 'jw_app must not own or inherit table owner privileges: %',item;
    END IF;
    -- RLS never protects TRUNCATE or TRIGGER/REFERENCES capabilities.
    IF pg_catalog.has_table_privilege('jw_app',pg_catalog.format('public.%I',item),
        'TRUNCATE, REFERENCES, TRIGGER') THEN
      RAISE EXCEPTION 'jw_app has dangerous non-RLS table privilege on: %',item;
    END IF;
    IF item IN ('sessions','mfa_credentials','mfa_recovery_codes','login_failures')
       AND pg_catalog.has_table_privilege('jw_app',pg_catalog.format('public.%I',item),'SELECT, INSERT, UPDATE, DELETE') THEN
      RAISE EXCEPTION 'jw_app must not already have direct auth privileges: %',item;
    END IF;
    -- Additional permissive policies would be OR-ed and could bypass this policy.
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_policies
       WHERE schemaname='public' AND tablename=item
       AND policyname NOT IN ('jw_org_scope','jw_tenant_scope','jw_child_scope','jw_rls_guard')) THEN
      RAISE EXCEPTION 'Unexpected RLS policy on %; manual security review required', item;
    END IF;
  END LOOP;
END $verify$;

-- All business references must contain a matching tenant key. Do not enable
-- RLS atop a schema with cross-tenant foreign-key references. The production
-- schema migrator must create/validate equivalent constraints FIRST.
DO $tenant_fk_preflight$
DECLARE rec record; valid_fk boolean;
BEGIN
  FOR rec IN SELECT * FROM (VALUES
    ('quotes','customers','customer_id','id'),
    ('quote_items','quotes','quote_id','id'),
    ('orders','quotes','quote_id','id'),
    ('order_items','orders','order_id','id'),
    ('order_items','quote_items','source_quote_item_id','id'),
    ('invoices','orders','order_id','id'),
    ('invoice_items','invoices','invoice_id','id'),
    ('payments','invoices','invoice_id','id')
  ) AS v(child_table,parent_table,child_key,parent_key)
  LOOP
    SELECT EXISTS (
      SELECT 1 FROM pg_catalog.pg_constraint c
      WHERE c.contype='f' AND c.convalidated
        AND c.conrelid=pg_catalog.to_regclass(pg_catalog.format('public.%I',rec.child_table))
        AND c.confrelid=pg_catalog.to_regclass(pg_catalog.format('public.%I',rec.parent_table))
        AND c.conkey=ARRAY[
            (SELECT a.attnum FROM pg_catalog.pg_attribute a
              WHERE a.attrelid=c.conrelid AND a.attname=rec.child_key),
            (SELECT a.attnum FROM pg_catalog.pg_attribute a
              WHERE a.attrelid=c.conrelid AND a.attname='org_id')
          ]::smallint[]
        AND c.confkey=ARRAY[
            (SELECT a.attnum FROM pg_catalog.pg_attribute a
              WHERE a.attrelid=c.confrelid AND a.attname=rec.parent_key),
            (SELECT a.attnum FROM pg_catalog.pg_attribute a
              WHERE a.attrelid=c.confrelid AND a.attname='org_id')
          ]::smallint[]
    ) INTO valid_fk;
    IF NOT valid_fk THEN
      RAISE EXCEPTION 'Missing validated composite tenant FK %.% -> %.%',
        rec.child_table,rec.child_key,rec.parent_table,rec.parent_key;
    END IF;
  END LOOP;
END $tenant_fk_preflight$;

-- Only trusted authentication processes may populate this PRIVATE session registry.
-- The application role never receives direct access, even to hashed tokens.
CREATE TABLE IF NOT EXISTS jw_guard.signing_key (
  key_id integer PRIMARY KEY CHECK (key_id = 1),
  secret bytea NOT NULL CHECK (octet_length(secret) = 32)
);
INSERT INTO jw_guard.signing_key(key_id,secret)
  VALUES (1,public.gen_random_bytes(32)) ON CONFLICT (key_id) DO NOTHING;
CREATE TABLE IF NOT EXISTS jw_guard.authenticated_sessions (
  token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest)=32),
  org_id text NOT NULL,
  user_id text NOT NULL,
  mfa_verified boolean NOT NULL DEFAULT false,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
REVOKE ALL ON ALL TABLES IN SCHEMA jw_guard FROM PUBLIC, jw_app;

-- Called ONCE per transaction using a high-entropy opaque session token; the
-- trusted auth service must first create the hashed session registry record.
CREATE OR REPLACE FUNCTION jw_guard.bind_session(raw_session_token text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, jw_guard, pg_temp
AS $body$
DECLARE v_org text; v_secret bytea; v_xid text; v_proof text; v_session_digest text;
BEGIN
  -- Never allow a bound transaction to switch tenants midway through work.
  IF NULLIF(pg_catalog.current_setting('jw.ctx_org',true),'') IS NOT NULL THEN
    RAISE EXCEPTION 'Tenant context already bound for this transaction';
  END IF;
  IF raw_session_token IS NULL OR length(raw_session_token) < 32 THEN
    RAISE EXCEPTION 'Invalid or expired verified session';
  END IF;
  SELECT s.org_id, pg_catalog.encode(s.token_digest,'hex') INTO v_org,v_session_digest FROM jw_guard.authenticated_sessions s
    WHERE s.token_digest=public.digest(pg_catalog.convert_to(raw_session_token,'UTF8'),'sha256')
      AND s.mfa_verified AND s.revoked_at IS NULL
      AND s.expires_at > pg_catalog.clock_timestamp();
  IF v_org IS NULL THEN RAISE EXCEPTION 'Invalid or expired verified session'; END IF;
  SELECT secret INTO v_secret FROM jw_guard.signing_key WHERE key_id=1;
  IF v_secret IS NULL THEN RAISE EXCEPTION 'Tenant signing key unavailable'; END IF;
  v_xid := pg_catalog.txid_current()::text;
  v_proof := pg_catalog.encode(public.hmac(
    pg_catalog.convert_to(v_org || '|' || v_xid || '|' || v_session_digest,'UTF8'),v_secret,'sha256'), 'hex');
  PERFORM pg_catalog.set_config('jw.ctx_org',v_org,true);
  PERFORM pg_catalog.set_config('jw.ctx_xid',v_xid,true);
  PERFORM pg_catalog.set_config('jw.ctx_session_digest',v_session_digest,true);
  PERFORM pg_catalog.set_config('jw.ctx_proof',v_proof,true);
END $body$;

-- RLS uses this function instead of directly trusting session GUCs.
-- A malicious SET jw.ctx_org / jw.ctx_xid cannot manufacture an HMAC.
-- Claims from prior transactions fail due to the transaction-bound XID.
CREATE OR REPLACE FUNCTION jw_guard.current_tenant()
RETURNS text LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, jw_guard, pg_temp
AS $body$
DECLARE v_org text; v_xid text; v_proof text; v_secret bytea; expected text; v_session_digest text;
BEGIN
  v_org := pg_catalog.current_setting('jw.ctx_org',true);
  v_xid := pg_catalog.current_setting('jw.ctx_xid',true);
  v_proof := pg_catalog.current_setting('jw.ctx_proof',true);
  v_session_digest := pg_catalog.current_setting('jw.ctx_session_digest',true);
  IF NULLIF(v_org,'') IS NULL OR NULLIF(v_xid,'') IS NULL
    OR NULLIF(v_proof,'') IS NULL OR v_session_digest IS NULL
    OR v_session_digest !~ '^[0-9a-f]{64}$' THEN RETURN NULL; END IF;
  IF v_xid IS DISTINCT FROM pg_catalog.txid_current_if_assigned()::text THEN RETURN NULL; END IF;
  SELECT secret INTO v_secret FROM jw_guard.signing_key WHERE key_id=1;
  IF v_secret IS NULL THEN RETURN NULL; END IF;
  expected := pg_catalog.encode(public.hmac(
    pg_catalog.convert_to(v_org || '|' || v_xid || '|' || v_session_digest,'UTF8'),v_secret,'sha256'), 'hex');
  IF v_proof IS DISTINCT FROM expected THEN RETURN NULL; END IF;
  -- Revalidate live session for EACH SQL statement, not merely at bind time.
  -- Under READ COMMITTED a revocation committed by the auth service invalidates
  -- the next statement in the current transaction. Higher isolation levels
  -- require short transactions and explicit cancellation controls.
  IF NOT EXISTS (SELECT 1 FROM jw_guard.authenticated_sessions s
      WHERE s.token_digest=pg_catalog.decode(v_session_digest,'hex')
        AND s.org_id=v_org AND s.mfa_verified
        AND s.revoked_at IS NULL
        AND s.expires_at > pg_catalog.clock_timestamp()) THEN RETURN NULL; END IF;
  RETURN v_org;
END $body$;
REVOKE ALL ON FUNCTION jw_guard.bind_session(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION jw_guard.current_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION jw_guard.bind_session(text) TO jw_app;
GRANT EXECUTE ON FUNCTION jw_guard.current_tenant() TO jw_app;

DO $policy$
DECLARE name text;
BEGIN
  FOREACH name IN ARRAY ARRAY[
    'organizations','users','customers','quotes','orders','invoices','payments',
    'audit_logs','security_events','import_previews','quote_items','order_items','invoice_items'
  ] LOOP
    EXECUTE pg_catalog.format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);
    EXECUTE pg_catalog.format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
    EXECUTE pg_catalog.format('DROP POLICY IF EXISTS jw_org_scope ON public.%I',name);
    EXECUTE pg_catalog.format('DROP POLICY IF EXISTS jw_tenant_scope ON public.%I',name);
    EXECUTE pg_catalog.format('DROP POLICY IF EXISTS jw_child_scope ON public.%I',name);
    EXECUTE pg_catalog.format('DROP POLICY IF EXISTS jw_rls_guard ON public.%I',name);
  END LOOP;

  EXECUTE 'CREATE POLICY jw_rls_guard ON public.organizations FOR ALL TO jw_app
    USING (id=jw_guard.current_tenant()) WITH CHECK (id=jw_guard.current_tenant())';
  FOREACH name IN ARRAY ARRAY[
    'users','customers','quotes','orders','invoices','payments',
    'audit_logs','security_events','import_previews'
  ] LOOP
    EXECUTE pg_catalog.format('CREATE POLICY jw_rls_guard ON public.%I FOR ALL TO jw_app
      USING (org_id=jw_guard.current_tenant())
      WITH CHECK (org_id=jw_guard.current_tenant())',name);
  END LOOP;
  EXECUTE 'CREATE POLICY jw_rls_guard ON public.quote_items FOR ALL TO jw_app
    USING (org_id=jw_guard.current_tenant() AND EXISTS (SELECT 1 FROM public.quotes q WHERE q.id=quote_id AND q.org_id=public.quote_items.org_id))
    WITH CHECK (org_id=jw_guard.current_tenant() AND EXISTS (SELECT 1 FROM public.quotes q WHERE q.id=quote_id AND q.org_id=public.quote_items.org_id))';
  EXECUTE 'CREATE POLICY jw_rls_guard ON public.order_items FOR ALL TO jw_app
    USING (org_id=jw_guard.current_tenant() AND EXISTS (SELECT 1 FROM public.orders o WHERE o.id=order_id AND o.org_id=public.order_items.org_id))
    WITH CHECK (org_id=jw_guard.current_tenant() AND EXISTS (SELECT 1 FROM public.orders o WHERE o.id=order_id AND o.org_id=public.order_items.org_id))';
  EXECUTE 'CREATE POLICY jw_rls_guard ON public.invoice_items FOR ALL TO jw_app
    USING (org_id=jw_guard.current_tenant() AND EXISTS (SELECT 1 FROM public.invoices i WHERE i.id=invoice_id AND i.org_id=public.invoice_items.org_id))
    WITH CHECK (org_id=jw_guard.current_tenant() AND EXISTS (SELECT 1 FROM public.invoices i WHERE i.id=invoice_id AND i.org_id=public.invoice_items.org_id))';
END $policy$;

-- Tenant-facing role gets ONLY business CRUD, never identity/session tables.
REVOKE ALL ON public.organizations, public.users, public.sessions,
  public.mfa_credentials, public.mfa_recovery_codes, public.login_failures,
  public.audit_logs, public.security_events FROM jw_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON public.customers, public.quotes,
  public.quote_items, public.orders, public.order_items, public.invoices,
  public.invoice_items, public.payments, public.import_previews TO jw_app;
-- Audit history must be append-only from a separate trusted writer, not editable
-- by the untrusted tenant application role. Security events are auth-service-only.
GRANT SELECT ON public.audit_logs TO jw_app;
COMMIT;
