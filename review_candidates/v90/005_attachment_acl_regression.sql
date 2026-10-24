-- V9.0 attachment access regression: three synthetic tenants, rollback only.
BEGIN;
INSERT INTO jw_dev.organizations(id,name,created_at) VALUES
('v90att-A','QA 갑',now()::text),('v90att-B','QA 을',now()::text),('v90att-C','QA 병',now()::text);
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES
('v90att-uA','v90att-A','v90att-a@example.invalid','synthetic','A','admin',now()::text),
('v90att-uB','v90att-B','v90att-b@example.invalid','synthetic','B','admin',now()::text),
('v90att-uC','v90att-C','v90att-c@example.invalid','synthetic','C','admin',now()::text);
INSERT INTO jw_dev.messenger_companies(org_id,business_number,verified_at,verification_kind) VALUES
('v90att-A','4040404040',now()::text,'demo'),('v90att-B','5050505050',now()::text,'demo'),('v90att-C','6060606060',now()::text,'demo');
INSERT INTO jw_dev.sessions(token_hash,user_id,expires_at,csrf_token,id,created_at) VALUES
('v90att-hA','v90att-uA',(now()+interval '1 hour')::text,'x','v90att-sA',now()::text),
('v90att-hB','v90att-uB',(now()+interval '1 hour')::text,'x','v90att-sB',now()::text),
('v90att-hC','v90att-uC',(now()+interval '1 hour')::text,'x','v90att-sC',now()::text);
SET LOCAL ROLE jw_app_dev;
DO $t$
DECLARE c text; m text; d bytea;
BEGIN
 PERFORM set_config('jw.session_hash','v90att-hA',true);
 c:=jw_dev.v90_start_chat('v90att-B');
 SELECT message_id INTO m FROM jw_dev.v90_send_text(c,'v90att-request-0001','photo evidence','photo.png','image/png',decode('89504e470d0a1a0a','hex'));
 SELECT data INTO d FROM jw_dev.v90_download_attachment(c,m);
 IF d IS DISTINCT FROM decode('89504e470d0a1a0a','hex') THEN RAISE EXCEPTION 'A cannot download'; END IF;
 PERFORM set_config('jw.session_hash','v90att-hB',true);
 SELECT data INTO d FROM jw_dev.v90_download_attachment(c,m);
 IF d IS DISTINCT FROM decode('89504e470d0a1a0a','hex') THEN RAISE EXCEPTION 'B cannot download'; END IF;
 PERFORM set_config('jw.session_hash','v90att-hC',true);
 BEGIN
  PERFORM * FROM jw_dev.v90_download_attachment(c,m);
  RAISE EXCEPTION 'FAIL C accessed A/B attachment';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 PERFORM set_config('jw.session_hash','v90att-invalid',true);
 BEGIN
  PERFORM * FROM jw_dev.v90_download_attachment(c,m);
  RAISE EXCEPTION 'FAIL invalid session download';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $t$;
ROLLBACK;
