-- V9.0 code-review candidate ONLY, not applied to database. Critical cursor/commit inversion guard.

-- Requires source/function signatures in 002_jw_dev_messenger_rpc.sql. Perform on approved isolated Postgres staging.

-- PostgreSQL transaction-scoped advisory locks are released at commit or rollback.

-- In an individual chat, only one sender/editor can allocate a message cursor / edit timestamp until commit.

-- Important: independent DB-session tests are REQUIRED before applying or claiming operational PASS.

BEGIN;

SET LOCAL lock_timeout = '5s';

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
  -- Serialize writers per conversation until COMMIT; nextval must execute AFTER this lock.
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('jw_dev.v90.messenger/' || p_connection_id, 0));
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
  -- Match the send-path conversation lock: edits must commit in cursor order.
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('jw_dev.v90.messenger/' || v_m.connection_id, 0));
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

REVOKE ALL ON FUNCTION jw_dev.v90_send_text(text,text,text,text,text,bytea) FROM PUBLIC,anon,authenticated,service_role;

REVOKE ALL ON FUNCTION jw_dev.v90_edit_text(text,text,bigint) FROM PUBLIC,anon,authenticated,service_role;

GRANT EXECUTE ON FUNCTION jw_dev.v90_send_text(text,text,text,text,text,bytea) TO jw_app_dev;

GRANT EXECUTE ON FUNCTION jw_dev.v90_edit_text(text,text,bigint) TO jw_app_dev;

COMMIT;

