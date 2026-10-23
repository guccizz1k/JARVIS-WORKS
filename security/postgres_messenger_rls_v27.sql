-- V2.7: synthetic-only PostgreSQL 17 messenger RLS review contract.
-- NOT CONNECTED TO FASTAPI/SQLITE, NOT A PRODUCTION MIGRATION.
-- Apply after pg_rls_test_fixture.sql and postgres_rls_proposal.sql inside
-- the existing dedicated jw_v20_test_<12 hexadecimal> CI database ONLY.
DO $preflight$
BEGIN
  IF current_database() !~ '^jw_v20_test_[0-9a-f]{12}$'
     OR pg_catalog.to_regclass('public.messenger_connections') IS NOT NULL
     OR pg_catalog.to_regprocedure('jw_guard.current_tenant()') IS NULL THEN
    RAISE EXCEPTION 'V2.7 messenger review SQL requires clean ephemeral PG17 CI database';
  END IF;
END $preflight$;
BEGIN;

-- Registered/directory-visible companies. No application-side permission to
-- certify, modify or unverify them. There is no users/contacts column.
CREATE TABLE public.messenger_companies (
  org_id text PRIMARY KEY REFERENCES public.organizations(id),
  company_name text NOT NULL,
  business_number text NOT NULL UNIQUE,
  verified_at timestamptz NOT NULL
);
CREATE TABLE public.messenger_connections (
  id text PRIMARY KEY,
  org_a text NOT NULL REFERENCES public.messenger_companies(org_id),
  org_b text NOT NULL REFERENCES public.messenger_companies(org_id),
  requester_org text NOT NULL REFERENCES public.messenger_companies(org_id),
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','pending')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(org_a,org_b),
  CHECK(org_a < org_b),
  CHECK(requester_org=org_a OR requester_org=org_b)
);
CREATE TABLE public.messenger_messages (
  id text PRIMARY KEY,
  connection_id text NOT NULL REFERENCES public.messenger_connections(id),
  sender_org text NOT NULL REFERENCES public.organizations(id),
  sender_user text NOT NULL,
  kind text NOT NULL CHECK(kind IN ('text','order','attachment')),
  body text NOT NULL CHECK(length(body) <= 2000),
  request_id text NOT NULL,
  message_seq bigint NOT NULL CHECK(message_seq > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(connection_id,message_seq), UNIQUE(sender_org,request_id),
  FOREIGN KEY(sender_user,sender_org) REFERENCES public.users(id,org_id)
);
CREATE INDEX messenger_message_page_v27 ON public.messenger_messages(connection_id,message_seq);
CREATE TABLE public.messenger_edits (
  id text PRIMARY KEY,
  message_id text NOT NULL REFERENCES public.messenger_messages(id),
  actor_user text NOT NULL REFERENCES public.users(id),
  previous_body text NOT NULL,
  new_body text NOT NULL,
  version integer NOT NULL CHECK(version>=2),
  UNIQUE(message_id,version)
);
CREATE TABLE public.messenger_attachments (
  message_id text PRIMARY KEY REFERENCES public.messenger_messages(id),
  filename text NOT NULL,
  data bytea NOT NULL CHECK(octet_length(data)>0 AND octet_length(data)<=5242880),
  content_hash text NOT NULL
);
CREATE TABLE public.messenger_read_positions (
  connection_id text NOT NULL REFERENCES public.messenger_connections(id),
  org_id text NOT NULL REFERENCES public.organizations(id),
  last_read_seq bigint NOT NULL DEFAULT 0 CHECK(last_read_seq>=0),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(connection_id,org_id)
);
CREATE TABLE public.messenger_receipts (
  message_id text PRIMARY KEY REFERENCES public.messenger_messages(id),
  receiver_org text NOT NULL REFERENCES public.organizations(id),
  receiver_user text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY(receiver_user,receiver_org) REFERENCES public.users(id,org_id)
);

-- Authorization must derive *actor* from the same MFA-verified, revocable,
-- transaction-signed session used by jw_guard.current_tenant(). A company ID
-- alone must not authorize impersonating another employee in that company.
CREATE OR REPLACE FUNCTION jw_guard.current_actor()
RETURNS text LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, jw_guard, pg_temp
AS $actor$
DECLARE v_digest text; v_org text; v_actor text;
BEGIN
  v_org := jw_guard.current_tenant();
  v_digest := pg_catalog.current_setting('jw.ctx_session_digest',true);
  IF v_org IS NULL OR v_digest IS NULL OR v_digest !~ '^[0-9a-f]{64}$' THEN
    RETURN NULL;
  END IF;
  SELECT s.user_id INTO v_actor FROM jw_guard.authenticated_sessions s
  WHERE s.token_digest=pg_catalog.decode(v_digest,'hex') AND s.org_id=v_org
    AND s.mfa_verified AND s.revoked_at IS NULL
    AND s.expires_at>pg_catalog.clock_timestamp();
  RETURN v_actor;
END $actor$;
REVOKE ALL ON FUNCTION jw_guard.current_actor() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION jw_guard.current_actor() TO jw_app;

-- The application role cannot touch the counter; a trusted trigger allocates
-- message sequences in a per-thread row lock held until COMMIT. Unlike a global
-- sequence/identity, it prevents an uncommitted earlier insert from appearing
-- after a client has already advanced its 'after' cursor.
CREATE TABLE jw_guard.messenger_counters (
  connection_id text PRIMARY KEY REFERENCES public.messenger_connections(id),
  last_seq bigint NOT NULL CHECK(last_seq>0)
);
REVOKE ALL ON jw_guard.messenger_counters FROM PUBLIC,jw_app;
CREATE OR REPLACE FUNCTION jw_guard.allocate_messenger_seq_v27()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog,jw_guard,pg_temp
AS $allocate$
DECLARE v_org text;
BEGIN
  v_org:=jw_guard.current_tenant();
  IF v_org IS NULL OR NEW.sender_org IS DISTINCT FROM v_org
      OR NEW.sender_user IS DISTINCT FROM jw_guard.current_actor() THEN
    RAISE EXCEPTION 'Messenger send requires a bound verified actor';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.messenger_connections c
    WHERE c.id=NEW.connection_id AND c.status='active'
      AND v_org IN (c.org_a,c.org_b)
  ) THEN RAISE EXCEPTION 'Invalid conversation membership'; END IF;
  IF NEW.message_seq IS NOT NULL THEN
    RAISE EXCEPTION 'Client cannot choose sequence';
  END IF;
  INSERT INTO jw_guard.messenger_counters AS counter(connection_id,last_seq)
    VALUES (NEW.connection_id,1)
    ON CONFLICT(connection_id) DO UPDATE SET last_seq=counter.last_seq+1
    RETURNING last_seq INTO NEW.message_seq;
  RETURN NEW;
END $allocate$;
REVOKE ALL ON FUNCTION jw_guard.allocate_messenger_seq_v27() FROM PUBLIC,jw_app;
CREATE TRIGGER jw_v27_message_seq BEFORE INSERT ON public.messenger_messages
  FOR EACH ROW EXECUTE FUNCTION jw_guard.allocate_messenger_seq_v27();

-- A bound org sees shared bilateral threads and their evidence, but a third
-- org never does. Starting a thread does not mean accepting a purchase order.
ALTER TABLE public.messenger_companies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messenger_companies FORCE ROW LEVEL SECURITY;
CREATE POLICY jw_v27_company_directory ON public.messenger_companies FOR SELECT TO jw_app
  USING (jw_guard.current_tenant() IS NOT NULL);
ALTER TABLE public.messenger_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messenger_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY jw_v27_thread_read ON public.messenger_connections FOR SELECT TO jw_app
  USING (status='active' AND jw_guard.current_tenant() IN (org_a,org_b));
CREATE POLICY jw_v27_thread_create ON public.messenger_connections FOR INSERT TO jw_app
  WITH CHECK (status='active' AND requester_org=jw_guard.current_tenant()
    AND jw_guard.current_tenant() IN (org_a,org_b));
ALTER TABLE public.messenger_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messenger_messages FORCE ROW LEVEL SECURITY;
CREATE POLICY jw_v27_message_read ON public.messenger_messages FOR SELECT TO jw_app
  USING (EXISTS (SELECT 1 FROM public.messenger_connections c WHERE c.id=connection_id
    AND c.status='active' AND jw_guard.current_tenant() IN (c.org_a,c.org_b)));
CREATE POLICY jw_v27_message_send ON public.messenger_messages FOR INSERT TO jw_app
  WITH CHECK (sender_org=jw_guard.current_tenant()
    AND sender_user=jw_guard.current_actor()
    AND EXISTS (SELECT 1 FROM public.messenger_connections c WHERE c.id=connection_id
      AND c.status='active' AND jw_guard.current_tenant() IN (c.org_a,c.org_b)));
ALTER TABLE public.messenger_edits ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messenger_edits FORCE ROW LEVEL SECURITY;
CREATE POLICY jw_v27_edits_read ON public.messenger_edits FOR SELECT TO jw_app
  USING (EXISTS(SELECT 1 FROM public.messenger_messages m WHERE m.id=message_id));
ALTER TABLE public.messenger_attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messenger_attachments FORCE ROW LEVEL SECURITY;
CREATE POLICY jw_v27_attach_read ON public.messenger_attachments FOR SELECT TO jw_app
  USING (EXISTS(SELECT 1 FROM public.messenger_messages m WHERE m.id=message_id));
CREATE POLICY jw_v27_attach_write ON public.messenger_attachments FOR INSERT TO jw_app
  WITH CHECK (EXISTS(SELECT 1 FROM public.messenger_messages m
    WHERE m.id=message_id AND m.sender_org=jw_guard.current_tenant()
      AND m.sender_user=jw_guard.current_actor()));
-- RLS alone cannot prevent a user from marking a future message read or
-- moving their cursor backward. Enforce a bounded, monotonic watermark.
CREATE OR REPLACE FUNCTION jw_guard.validate_read_watermark_v27()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,jw_guard,pg_temp
AS $watermark$
DECLARE v_last bigint;
BEGIN
  IF NEW.org_id IS DISTINCT FROM jw_guard.current_tenant() THEN
    RAISE EXCEPTION 'Read marker requires verified organization';
  END IF;
  IF TG_OP='UPDATE' AND NEW.last_read_seq<OLD.last_read_seq THEN
    RAISE EXCEPTION 'Read marker cannot move backward';
  END IF;
  SELECT COALESCE(MAX(m.message_seq),0) INTO v_last
  FROM public.messenger_messages m WHERE m.connection_id=NEW.connection_id;
  IF NEW.last_read_seq>v_last THEN
    RAISE EXCEPTION 'Read marker exceeds committed history';
  END IF;
  RETURN NEW;
END $watermark$;
REVOKE ALL ON FUNCTION jw_guard.validate_read_watermark_v27() FROM PUBLIC,jw_app;
CREATE TRIGGER jw_v27_read_watermark BEFORE INSERT OR UPDATE
 ON public.messenger_read_positions FOR EACH ROW
 EXECUTE FUNCTION jw_guard.validate_read_watermark_v27();
ALTER TABLE public.messenger_read_positions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messenger_read_positions FORCE ROW LEVEL SECURITY;
CREATE POLICY jw_v27_read_pos_read ON public.messenger_read_positions FOR SELECT TO jw_app
  USING (org_id=jw_guard.current_tenant() AND EXISTS(
    SELECT 1 FROM public.messenger_connections c WHERE c.id=connection_id));
CREATE POLICY jw_v27_read_pos_insert ON public.messenger_read_positions FOR INSERT TO jw_app
  WITH CHECK (org_id=jw_guard.current_tenant() AND EXISTS(
    SELECT 1 FROM public.messenger_connections c WHERE c.id=connection_id));
CREATE POLICY jw_v27_read_pos_update ON public.messenger_read_positions FOR UPDATE TO jw_app
  USING (org_id=jw_guard.current_tenant() AND EXISTS(
    SELECT 1 FROM public.messenger_connections c WHERE c.id=connection_id))
  WITH CHECK (org_id=jw_guard.current_tenant() AND EXISTS(
    SELECT 1 FROM public.messenger_connections c WHERE c.id=connection_id));
ALTER TABLE public.messenger_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messenger_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY jw_v27_receipt_read ON public.messenger_receipts FOR SELECT TO jw_app
  USING (jw_guard.current_tenant() IS NOT NULL
    AND EXISTS(SELECT 1 FROM public.messenger_messages m WHERE m.id=message_id));
CREATE POLICY jw_v27_receipt_write ON public.messenger_receipts FOR INSERT TO jw_app
  WITH CHECK (receiver_org=jw_guard.current_tenant()
    AND receiver_user=jw_guard.current_actor()
    AND EXISTS(SELECT 1 FROM public.messenger_messages m
      WHERE m.id=message_id AND m.sender_org<>jw_guard.current_tenant()));

-- Least privilege: evidence edits and deletes must go through a separate
-- audited writer, not direct raw SQL from an employee session.
REVOKE ALL ON public.messenger_companies,public.messenger_connections,
 public.messenger_messages,public.messenger_edits,public.messenger_attachments,
 public.messenger_read_positions,public.messenger_receipts FROM jw_app,PUBLIC;
GRANT SELECT(org_id,company_name) ON public.messenger_companies TO jw_app;
GRANT SELECT ON public.messenger_connections,public.messenger_messages,
 public.messenger_edits,public.messenger_attachments,
 public.messenger_read_positions,public.messenger_receipts TO jw_app;
GRANT INSERT(id,org_a,org_b,requester_org,status) ON public.messenger_connections TO jw_app;
GRANT INSERT(id,connection_id,sender_org,sender_user,kind,body,request_id)
 ON public.messenger_messages TO jw_app;
GRANT INSERT(message_id,filename,data,content_hash) ON public.messenger_attachments TO jw_app;
GRANT INSERT(connection_id,org_id,last_read_seq),UPDATE(last_read_seq,updated_at)
 ON public.messenger_read_positions TO jw_app;
GRANT INSERT(message_id,receiver_org,receiver_user) ON public.messenger_receipts TO jw_app;
COMMIT;
