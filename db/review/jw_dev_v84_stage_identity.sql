-- V8.4 reviewed Supabase jw_dev stage identity routine.
-- Already applied to the development project; keep for source-history parity.
-- DO NOT apply to a live production environment without review.
BEGIN;
CREATE FUNCTION jw_dev.stage_identity_v84()
RETURNS TABLE(actor_id text,org_id text,actor_role text,csrf_token text,org_name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT u.id,u.org_id,u.role,s.csrf_token,o.name
 FROM jw_dev.sessions s
 JOIN jw_dev.users u ON u.id=s.user_id
 JOIN jw_dev.organizations o ON o.id=u.org_id
 LEFT JOIN jw_dev.staff_disabled d ON d.user_id=u.id
 WHERE s.token_hash=nullif(current_setting('jw.session_hash',true),'')
   AND s.expires_at::timestamptz>clock_timestamp()
   AND d.user_id IS NULL AND s.csrf_token<>''
 LIMIT 1
$fn$;
REVOKE ALL ON FUNCTION jw_dev.stage_identity_v84() FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION jw_dev.stage_identity_v84() TO jw_app_dev;
COMMIT;
