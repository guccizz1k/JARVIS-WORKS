-- JARVIS WORKS V9.0 staging-only A/B/C regression. NO persistent test data.
-- Run only in dev schema with test fixture IDs unused. A failed assertion aborts the transaction.
BEGIN;
INSERT INTO jw_dev.organizations(id,name,created_at) VALUES
('v90qa-a','QA 가온',now()::text),('v90qa-b','QA 나래',now()::text),('v90qa-c','QA 다온',now()::text);
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES
('v90qa-ua','v90qa-a','v90qa-a@example.invalid','synthetic','QA A','admin',now()::text),
('v90qa-ub','v90qa-b','v90qa-b@example.invalid','synthetic','QA B','admin',now()::text),
('v90qa-uc','v90qa-c','v90qa-c@example.invalid','synthetic','QA C','admin',now()::text);
INSERT INTO jw_dev.messenger_companies(org_id,business_number,verified_at,verification_kind) VALUES
('v90qa-a','1010101010',now()::text,'demo'),('v90qa-b','2020202020',now()::text,'demo'),('v90qa-c','3030303030',now()::text,'demo');
INSERT INTO jw_dev.sessions(token_hash,user_id,expires_at,csrf_token,id,created_at) VALUES
('v90qa-ha','v90qa-ua',(now()+interval '1 hour')::text,'x','v90qa-sa',now()::text),
('v90qa-hb','v90qa-ub',(now()+interval '1 hour')::text,'x','v90qa-sb',now()::text),
('v90qa-hc','v90qa-uc',(now()+interval '1 hour')::text,'x','v90qa-sc',now()::text);
SET LOCAL ROLE jw_app_dev;
DO $test$
DECLARE c text; m text; s bigint; s2 bigint; d boolean; n integer;
BEGIN
 PERFORM set_config('jw.session_hash','v90qa-ha',true);
 c:=jw_dev.v90_start_chat('v90qa-b');
 IF c IS NULL THEN RAISE EXCEPTION 'FAIL start'; END IF;
 SELECT message_id,message_cursor,replayed INTO m,s,d
 FROM jw_dev.v90_send_text(c,'qa-request-0001','안녕하세요');
 IF m IS NULL OR s<1 OR d THEN RAISE EXCEPTION 'FAIL send'; END IF;
 SELECT message_cursor,replayed INTO s2,d FROM jw_dev.v90_send_text(c,'qa-request-0001','안녕하세요');
 IF s2<>s OR NOT d THEN RAISE EXCEPTION 'FAIL dedup'; END IF;
 BEGIN
  PERFORM jw_dev.v90_send_text(c,'qa-request-0001','collision');
  RAISE EXCEPTION 'FAIL collision accepted';
 EXCEPTION WHEN unique_violation THEN NULL; END;
 PERFORM jw_dev.v90_send_text(c,'qa-request-0002','첨부','note.txt','text/plain',convert_to('hello','UTF8'));
 SELECT count(*) INTO n FROM jw_dev.v90_sync_messages(c);
 IF n<>2 THEN RAISE EXCEPTION 'FAIL messages sync %',n; END IF;
 IF jw_dev.v90_edit_text(m,'수정했습니다',1)<>2 THEN RAISE EXCEPTION 'FAIL edit'; END IF;
 SELECT count(*) INTO n FROM jw_dev.v90_sync_edits(c);
 IF n<>1 THEN RAISE EXCEPTION 'FAIL edits sync %',n; END IF;
 BEGIN
  PERFORM jw_dev.v90_edit_text(m,'stale',1);
  RAISE EXCEPTION 'FAIL stale version';
 EXCEPTION WHEN serialization_failure THEN NULL; END;
 IF jw_dev.v90_mark_read(c,s)<>s OR jw_dev.v90_mark_read(c,0)<>s
 THEN RAISE EXCEPTION 'FAIL cursor monotonic'; END IF;
 PERFORM set_config('jw.session_hash','v90qa-hb',true);
 IF jw_dev.v90_start_chat('v90qa-a')<>c THEN RAISE EXCEPTION 'FAIL duplicate conversation'; END IF;
 SELECT count(*) INTO n FROM jw_dev.v90_sync_messages(c);
 IF n<>2 THEN RAISE EXCEPTION 'FAIL B sync'; END IF;
 SELECT count(*) INTO n FROM jw_dev.v90_sync_edits(c);
 IF n<>1 THEN RAISE EXCEPTION 'FAIL B edit sync'; END IF;
 BEGIN PERFORM jw_dev.v90_edit_text(m,'forged',2);
  RAISE EXCEPTION 'FAIL cross-org edit';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 PERFORM set_config('jw.session_hash','v90qa-hc',true);
 BEGIN PERFORM * FROM jw_dev.v90_sync_messages(c);
  RAISE EXCEPTION 'FAIL C accessed A/B chat';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM * FROM jw_dev.v90_sync_edits(c);
  RAISE EXCEPTION 'FAIL C accessed A/B edits';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM * FROM jw_dev.v90_send_text(c,'qa-request-0003','forged');
  RAISE EXCEPTION 'FAIL C sent into A/B';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 PERFORM set_config('jw.session_hash','invalid',true);
 BEGIN PERFORM * FROM jw_dev.v90_sync_messages(c);
  RAISE EXCEPTION 'FAIL invalid session';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $test$;
RESET ROLE;
INSERT INTO jw_dev.messenger_messages(id,connection_id,sender_org,sender_user,kind,body,actor_name,request_id,version,created_at)
SELECT 'v90qa-old',id,'v90qa-a','v90qa-ua','text','old','','v90qa-old-request',1,
(now()-interval '31 minutes')::text
FROM jw_dev.messenger_connections WHERE org_a='v90qa-a' AND org_b='v90qa-b';
SET LOCAL ROLE jw_app_dev;
SET LOCAL jw.session_hash='v90qa-ha';
DO $test$
BEGIN
 BEGIN PERFORM jw_dev.v90_edit_text('v90qa-old','late',1);
  RAISE EXCEPTION 'FAIL expired edit';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $test$;
RESET ROLE;
DO $test$
BEGIN
 BEGIN DELETE FROM jw_dev.messenger_messages WHERE id='v90qa-old';
  RAISE EXCEPTION 'FAIL history deleted';
 EXCEPTION WHEN check_violation THEN NULL; END;
END $test$;
ROLLBACK;