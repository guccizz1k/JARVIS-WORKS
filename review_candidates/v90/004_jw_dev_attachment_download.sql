-- Additive staging ONLY: V9.0 attachment ACL RPC extracted from inspected dev database.

-- Do not apply to production or as a duplicate migration; reconcile V8.9 migration history first.

BEGIN;

CREATE OR REPLACE FUNCTION jw_dev.v90_download_attachment(p_connection_id text, p_message_id text)
 RETURNS TABLE(filename text, mime text, data bytea, size_bytes bigint, content_hash text)
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE v_org text; v_actor text;
BEGIN
 v_org := jw_dev.current_org_from_session();
 v_actor := jw_dev.current_actor_from_session_v82();
 IF v_org IS NULL OR v_actor IS NULL OR NOT EXISTS (
   SELECT 1 FROM jw_dev.messenger_connections c
   JOIN jw_dev.messenger_messages m ON m.connection_id=c.id
   WHERE c.id=p_connection_id AND m.id=p_message_id AND c.status='active'
   AND v_org IN (c.org_a,c.org_b)
   AND m.sender_org IN (c.org_a,c.org_b)
   AND EXISTS (SELECT 1 FROM jw_dev.messenger_companies mc WHERE mc.org_id=v_org)
   AND EXISTS (SELECT 1 FROM jw_dev.messenger_companies mc
               WHERE mc.org_id=CASE WHEN c.org_a=v_org THEN c.org_b ELSE c.org_a END)
 ) THEN RAISE EXCEPTION 'Not a verified attachment participant' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT a.filename,a.mime,a.data,a.size_bytes,a.content_hash
 FROM jw_dev.messenger_attachments a WHERE a.message_id=p_message_id;
END $function$;

REVOKE ALL ON FUNCTION jw_dev.v90_download_attachment(text,text) FROM PUBLIC,anon,authenticated,service_role;

GRANT EXECUTE ON FUNCTION jw_dev.v90_download_attachment(text,text) TO jw_app_dev;

COMMIT;

