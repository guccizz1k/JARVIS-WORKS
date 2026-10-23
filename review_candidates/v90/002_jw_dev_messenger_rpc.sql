-- JARVIS WORKS V9.0 / isolated messenger RPC candidate / staging ONLY.

-- Source: directly inspected PostgreSQL functions in jarvis-works-dev.jw_dev.

-- Precondition: V8.8+ schema, verified session functions, no production cutover.

-- V8.9 snapshot a3783ef is MISSING; this file is additive and not app-integrated.

-- Run on disposable staging clone and reconcile migrations before any integration.

BEGIN;

CREATE SEQUENCE IF NOT EXISTS jw_dev.messenger_seq_v90 AS bigint START WITH 1;

CREATE OR REPLACE FUNCTION jw_dev.v90_edit_text(p_message_id text, p_new_body text, p_expected_version bigint)
 RETURNS bigint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE v_org text; v_actor text; v_m jw_dev.messenger_messages%ROWTYPE; v_version bigint;
BEGIN
  v_org:=jw_dev.current_org_from_session(); v_actor:=jw_dev.current_actor_from_session_v82();
  IF v_org IS NULL OR v_actor IS NULL OR p_new_body IS NULL
    OR length(p_new_body)>5000 OR btrim(p_new_body)=''
  THEN RAISE EXCEPTION 'Invalid edit request or session' USING ERRCODE='42501'; END IF;
  SELECT m.* INTO v_m FROM jw_dev.messenger_messages m
  JOIN jw_dev.messenger_connections c ON c.id=m.connection_id
  WHERE m.id=p_message_id AND m.sender_org=v_org AND m.sender_user=v_actor
    AND m.kind='text' AND c.status='active' AND v_org IN(c.org_a,c.org_b)
  FOR UPDATE OF m;
  IF NOT FOUND THEN RAISE EXCEPTION 'Message not owned by actor' USING ERRCODE='42501'; END IF;
  IF clock_timestamp() > v_m.created_at::timestamptz + interval '30 minutes'
  THEN RAISE EXCEPTION 'Edit window expired' USING ERRCODE='42501'; END IF;
  IF p_expected_version IS DISTINCT FROM v_m.version
  THEN RAISE EXCEPTION 'Version conflict' USING ERRCODE='40001'; END IF;
  IF v_m.body IS NOT DISTINCT FROM p_new_body THEN RETURN v_m.version; END IF;
  v_version:=v_m.version+1;
  UPDATE jw_dev.messenger_messages SET body=p_new_body,version=v_version,
    edited_at=clock_timestamp()::text WHERE id=p_message_id;
  INSERT INTO jw_dev.messenger_edits
    (id,message_id,previous_body,new_body,actor_user,edited_at,version)
  VALUES(gen_random_uuid()::text,p_message_id,v_m.body,p_new_body,v_actor,clock_timestamp()::text,v_version);
  RETURN v_version;
END $function$;

CREATE OR REPLACE FUNCTION jw_dev.v90_mark_read(p_connection_id text, p_cursor bigint)
 RETURNS bigint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE v_org text; v_actor text; v_max bigint; v_out bigint;
BEGIN
  v_org:=jw_dev.current_org_from_session(); v_actor:=jw_dev.current_actor_from_session_v82();
  IF v_org IS NULL OR v_actor IS NULL OR NOT EXISTS(
    SELECT 1 FROM jw_dev.messenger_connections c WHERE c.id=p_connection_id
       AND c.status='active' AND v_org IN(c.org_a,c.org_b))
  THEN RAISE EXCEPTION 'Not a chat participant' USING ERRCODE='42501'; END IF;
  SELECT coalesce(max(message_seq),0) INTO v_max
    FROM jw_dev.messenger_messages WHERE connection_id=p_connection_id;
  IF p_cursor IS NULL OR p_cursor<0 OR p_cursor>v_max
  THEN RAISE EXCEPTION 'Invalid read cursor' USING ERRCODE='23514'; END IF;
  INSERT INTO jw_dev.messenger_read_positions
    (connection_id,org_id,last_read_rowid,updated_at,last_read_seq)
  VALUES(p_connection_id,v_org,0,clock_timestamp()::text,p_cursor)
  ON CONFLICT (connection_id,org_id) DO UPDATE
    SET last_read_seq=greatest(coalesce(jw_dev.messenger_read_positions.last_read_seq,0),
                                excluded.last_read_seq),
        updated_at=clock_timestamp()::text
  RETURNING last_read_seq INTO v_out;
  RETURN v_out;
END $function$;

CREATE OR REPLACE FUNCTION jw_dev.v90_send_text(p_connection_id text, p_request_id text, p_body text, p_filename text DEFAULT NULL::text, p_mime text DEFAULT NULL::text, p_data bytea DEFAULT NULL::bytea)
 RETURNS TABLE(message_id text, message_cursor bigint, replayed boolean)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE v_org text; v_actor text; v_saved jw_dev.messenger_messages%ROWTYPE;
  v_added boolean; v_sha text; v_file jw_dev.messenger_attachments%ROWTYPE;
BEGIN
  v_org:=jw_dev.current_org_from_session(); v_actor:=jw_dev.current_actor_from_session_v82();
  IF v_org IS NULL OR v_actor IS NULL
    OR NOT EXISTS (SELECT 1 FROM jw_dev.messenger_companies WHERE org_id=v_org)
    OR NOT EXISTS (SELECT 1 FROM jw_dev.messenger_connections c
      WHERE c.id=p_connection_id AND c.status='active' AND v_org IN(c.org_a,c.org_b)
      AND EXISTS (SELECT 1 FROM jw_dev.messenger_companies mc
                  WHERE mc.org_id=CASE WHEN c.org_a=v_org THEN c.org_b ELSE c.org_a END))
  THEN RAISE EXCEPTION 'Not a verified active chat participant' USING ERRCODE='42501'; END IF;
  IF p_request_id IS NULL OR length(p_request_id) NOT BETWEEN 8 AND 128 OR
     p_body IS NULL OR length(p_body)>5000 OR
     (btrim(p_body)='' AND p_data IS NULL)
  THEN RAISE EXCEPTION 'Invalid message request' USING ERRCODE='23514'; END IF;
  IF (p_data IS NULL AND (p_filename IS NOT NULL OR p_mime IS NOT NULL))
    OR (p_data IS NOT NULL AND
      (octet_length(p_data) NOT BETWEEN 1 AND 5242880
       OR p_filename IS NULL OR length(p_filename) NOT BETWEEN 1 AND 180
       OR p_filename LIKE '%/%' OR p_filename LIKE '%'||chr(92)||'%'
       OR p_mime IS NULL OR p_mime NOT IN (
         'image/jpeg','image/png','image/webp','image/gif','application/pdf',
         'text/plain','application/vnd.openxmlformats-officedocument.wordprocessingml.document',
         'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')))
  THEN RAISE EXCEPTION 'Invalid attachment' USING ERRCODE='23514'; END IF;
  v_sha:=CASE WHEN p_data IS NULL THEN NULL ELSE encode(sha256(p_data),'hex') END;
  INSERT INTO jw_dev.messenger_messages
    (id,connection_id,sender_org,sender_user,kind,body,actor_name,
     request_id,version,created_at,message_seq)
  VALUES (gen_random_uuid()::text,p_connection_id,v_org,v_actor,'text',p_body,
    '',p_request_id,1,clock_timestamp()::text,nextval('jw_dev.messenger_seq_v90'))
  ON CONFLICT (sender_org,request_id) DO NOTHING
  RETURNING * INTO v_saved;
  v_added:=FOUND;
  IF NOT v_added THEN
    SELECT * INTO v_saved FROM jw_dev.messenger_messages m
      WHERE m.sender_org=v_org AND m.request_id=p_request_id;
    IF NOT FOUND OR v_saved.connection_id IS DISTINCT FROM p_connection_id
      OR v_saved.sender_user IS DISTINCT FROM v_actor OR v_saved.kind<>'text'
      OR v_saved.body IS DISTINCT FROM p_body
    THEN RAISE EXCEPTION 'Idempotency key collision' USING ERRCODE='23505'; END IF;
    SELECT * INTO v_file FROM jw_dev.messenger_attachments a WHERE a.message_id=v_saved.id;
    IF (p_data IS NULL AND FOUND) OR (p_data IS NOT NULL AND
       (NOT FOUND OR v_file.filename IS DISTINCT FROM p_filename OR
        v_file.mime IS DISTINCT FROM p_mime OR v_file.content_hash IS DISTINCT FROM v_sha))
    THEN RAISE EXCEPTION 'Idempotency attachment mismatch' USING ERRCODE='23505'; END IF;
  ELSIF p_data IS NOT NULL THEN
    INSERT INTO jw_dev.messenger_attachments
      (message_id,filename,mime,data,size_bytes,content_hash)
    VALUES (v_saved.id,p_filename,p_mime,p_data,octet_length(p_data),v_sha);
  END IF;
  RETURN QUERY SELECT v_saved.id,v_saved.message_seq,NOT v_added;
END $function$;

CREATE OR REPLACE FUNCTION jw_dev.v90_start_chat(p_other_org text)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE v_org text; v_actor text; v_id text;
BEGIN
  v_org:=jw_dev.current_org_from_session(); v_actor:=jw_dev.current_actor_from_session_v82();
  IF v_org IS NULL OR v_actor IS NULL OR p_other_org IS NULL OR p_other_org=v_org
     OR NOT EXISTS (SELECT 1 FROM jw_dev.messenger_companies WHERE org_id=v_org)
     OR NOT EXISTS (SELECT 1 FROM jw_dev.messenger_companies WHERE org_id=p_other_org)
  THEN RAISE EXCEPTION 'Verified company session and different verified recipient required' USING ERRCODE='42501'; END IF;
  INSERT INTO jw_dev.messenger_connections
    (id,org_a,org_b,requester_org,status,created_at,accepted_at)
  VALUES (gen_random_uuid()::text,least(v_org,p_other_org),greatest(v_org,p_other_org),
    v_org,'active',clock_timestamp()::text,clock_timestamp()::text)
  ON CONFLICT (org_a,org_b) DO UPDATE SET status='active',
    accepted_at=coalesce(jw_dev.messenger_connections.accepted_at,clock_timestamp()::text)
  RETURNING id INTO v_id;
  RETURN v_id;
END $function$;

CREATE OR REPLACE FUNCTION jw_dev.v90_sync_edits(p_connection_id text, p_after_at timestamp with time zone DEFAULT '1970-01-01 00:00:00+00'::timestamp with time zone, p_after_edit_id text DEFAULT ''::text, p_limit integer DEFAULT 50)
 RETURNS TABLE(edit_id text, message_id text, version bigint, new_body text, edited_at text)
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE v_org text; v_actor text;
BEGIN
 v_org:=jw_dev.current_org_from_session(); v_actor:=jw_dev.current_actor_from_session_v82();
 IF v_org IS NULL OR v_actor IS NULL OR NOT EXISTS
 (SELECT 1 FROM jw_dev.messenger_connections c WHERE c.id=p_connection_id
   AND c.status='active' AND v_org IN(c.org_a,c.org_b))
 THEN RAISE EXCEPTION 'Not a chat participant' USING ERRCODE='42501'; END IF;
 IF p_after_at IS NULL OR p_after_edit_id IS NULL OR p_limit IS NULL
    OR p_limit NOT BETWEEN 1 AND 100
 THEN RAISE EXCEPTION 'Invalid edit sync cursor' USING ERRCODE='23514'; END IF;
 RETURN QUERY SELECT e.id,e.message_id,e.version,e.new_body,e.edited_at
 FROM jw_dev.messenger_edits e
 JOIN jw_dev.messenger_messages m ON m.id=e.message_id
 WHERE m.connection_id=p_connection_id AND
   (e.edited_at::timestamptz>p_after_at OR
     (e.edited_at::timestamptz=p_after_at AND e.id>p_after_edit_id))
 ORDER BY e.edited_at::timestamptz,e.id LIMIT p_limit;
END $function$;

CREATE OR REPLACE FUNCTION jw_dev.v90_sync_messages(p_connection_id text, p_after_cursor bigint DEFAULT 0, p_limit integer DEFAULT 50)
 RETURNS TABLE(message_id text, message_cursor bigint, sender_org text, sender_user text, body text, version bigint, created_at text, edited_at text, filename text, mime text, size_bytes bigint)
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE v_org text; v_actor text;
BEGIN
  v_org:=jw_dev.current_org_from_session(); v_actor:=jw_dev.current_actor_from_session_v82();
  IF v_org IS NULL OR v_actor IS NULL OR NOT EXISTS (
    SELECT 1 FROM jw_dev.messenger_connections c WHERE c.id=p_connection_id
    AND c.status='active' AND v_org IN(c.org_a,c.org_b))
  THEN RAISE EXCEPTION 'Not a chat participant' USING ERRCODE='42501'; END IF;
  IF p_after_cursor IS NULL OR p_after_cursor<0 OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100
  THEN RAISE EXCEPTION 'Invalid sync paging' USING ERRCODE='23514'; END IF;
  RETURN QUERY SELECT m.id,m.message_seq,m.sender_org,m.sender_user,m.body,
    m.version,m.created_at,m.edited_at,a.filename,a.mime,a.size_bytes
    FROM jw_dev.messenger_messages m
    LEFT JOIN jw_dev.messenger_attachments a ON a.message_id=m.id
    WHERE m.connection_id=p_connection_id AND m.message_seq>p_after_cursor
    ORDER BY m.message_seq LIMIT p_limit;
END $function$;

REVOKE ALL ON FUNCTION jw_dev.v90_start_chat(text) FROM PUBLIC,anon,authenticated,service_role;

REVOKE ALL ON FUNCTION jw_dev.v90_send_text(text,text,text,text,text,bytea) FROM PUBLIC,anon,authenticated,service_role;

REVOKE ALL ON FUNCTION jw_dev.v90_mark_read(text,bigint) FROM PUBLIC,anon,authenticated,service_role;

REVOKE ALL ON FUNCTION jw_dev.v90_edit_text(text,text,bigint) FROM PUBLIC,anon,authenticated,service_role;

REVOKE ALL ON FUNCTION jw_dev.v90_sync_messages(text,bigint,integer) FROM PUBLIC,anon,authenticated,service_role;

REVOKE ALL ON FUNCTION jw_dev.v90_sync_edits(text,timestamptz,text,integer) FROM PUBLIC,anon,authenticated,service_role;

GRANT EXECUTE ON FUNCTION jw_dev.v90_start_chat(text) TO jw_app_dev;

GRANT EXECUTE ON FUNCTION jw_dev.v90_send_text(text,text,text,text,text,bytea) TO jw_app_dev;

GRANT EXECUTE ON FUNCTION jw_dev.v90_mark_read(text,bigint) TO jw_app_dev;

GRANT EXECUTE ON FUNCTION jw_dev.v90_edit_text(text,text,bigint) TO jw_app_dev;

GRANT EXECUTE ON FUNCTION jw_dev.v90_sync_messages(text,bigint,integer) TO jw_app_dev;

GRANT EXECUTE ON FUNCTION jw_dev.v90_sync_edits(text,timestamptz,text,integer) TO jw_app_dev;

COMMIT;

