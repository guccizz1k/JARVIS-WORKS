-- JARVIS WORKS V2.8: additive, disposable PostgreSQL 17 review hardening.
-- NEVER APPLY TO PRODUCTION. The SQLite FastAPI application is unchanged.
-- Runs ONLY after V2.7 in a randomly named, isolated jw_v20_test_* database.
-- Fail closed if legacy attachments have fake checksums or wrong message kinds;
-- migration of real historical evidence is a separate, audited project.
DO $v28_preflight$
BEGIN
  IF current_database() !~ '^jw_v20_test_[0-9a-f]{12}$'
     OR pg_catalog.to_regclass('public.messenger_attachments') IS NULL
     OR pg_catalog.to_regprocedure('jw_guard.current_actor()') IS NULL
     OR pg_catalog.to_regprocedure('public.digest(bytea,text)') IS NULL
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_trigger
        WHERE tgname = 'jw_v28_attachment_sender' AND NOT tgisinternal) THEN
    RAISE EXCEPTION 'V2.8 hardening requires a fresh isolated PG17 messenger test database';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.messenger_attachments a
    LEFT JOIN public.messenger_messages m ON m.id = a.message_id
    WHERE m.id IS NULL OR m.kind <> 'attachment'
       OR a.content_hash IS DISTINCT FROM pg_catalog.encode(public.digest(a.data,'sha256'),'hex')
  ) THEN
    RAISE EXCEPTION 'Legacy attachment integrity conflict; stop and audit before any migration';
  END IF;
END $v28_preflight$;
BEGIN;

-- The stored hash is evidence, not an arbitrary client-provided label.
-- The pgcrypto digest is recomputed by PostgreSQL at INSERT/UPDATE time.
ALTER TABLE public.messenger_attachments
  ADD CONSTRAINT jw_v28_attachment_sha256 CHECK (
    content_hash ~ '^[0-9a-f]{64}$'
    AND content_hash = pg_catalog.encode(public.digest(data, 'sha256'), 'hex')
  );

-- A member of a company may not attach a new file to another employee's
-- message, nor attach binary data to a non-attachment message. PostgreSQL
-- executes this SECURITY DEFINER trigger before the FK/UNIQUE checks.
CREATE FUNCTION jw_guard.validate_attachment_sender_v28()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,jw_guard,pg_temp
AS $v28_attach$
BEGIN
  IF jw_guard.current_tenant() IS NULL OR jw_guard.current_actor() IS NULL
     OR NOT EXISTS (
       SELECT 1 FROM public.messenger_messages m
       WHERE m.id=NEW.message_id
         AND m.sender_org=jw_guard.current_tenant()
         AND m.sender_user=jw_guard.current_actor()
         AND m.kind='attachment'
     ) THEN
    RAISE EXCEPTION 'Attachment requires the original verified message sender';
  END IF;
  RETURN NEW;
END $v28_attach$;
REVOKE ALL ON FUNCTION jw_guard.validate_attachment_sender_v28() FROM PUBLIC,jw_app;
CREATE TRIGGER jw_v28_attachment_sender
  BEFORE INSERT ON public.messenger_attachments
  FOR EACH ROW EXECUTE FUNCTION jw_guard.validate_attachment_sender_v28();

-- Clients cannot forge the recorded read timestamp. Keep the same V2.7
-- monotonic, bounded cursor semantics while assigning timestamps on server.
CREATE OR REPLACE FUNCTION jw_guard.validate_read_watermark_v27()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,jw_guard,pg_temp
AS $v28_read$
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
  NEW.updated_at:=pg_catalog.clock_timestamp();
  RETURN NEW;
END $v28_read$;
REVOKE ALL ON FUNCTION jw_guard.validate_read_watermark_v27() FROM PUBLIC,jw_app;
REVOKE UPDATE(updated_at) ON TABLE public.messenger_read_positions FROM jw_app;
COMMIT;
