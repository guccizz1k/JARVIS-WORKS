-- ISOLATED DEV ONLY: ephemeral, deterministic A/B/C HTTPS acceptance fixture.
-- These are deliberately non-customer TEST identities. Their sessions and rows
-- MUST be deleted by the paired cleanup after the live verification. The
-- protected external stage header is still required for every business route.
BEGIN;
SET LOCAL lock_timeout='1200ms';
SET LOCAL statement_timeout='15s';
DO $guard$ BEGIN
 IF current_database()<>'postgres' OR
   EXISTS(SELECT 1 FROM jw_dev.organizations) OR
   EXISTS(SELECT 1 FROM jw_dev.users) OR
   EXISTS(SELECT 1 FROM jw_dev.sessions) OR
   EXISTS(SELECT 1 FROM jw_dev.customers) OR
   EXISTS(SELECT 1 FROM jw_dev.messenger_messages) OR
   EXISTS(SELECT 1 FROM jw_dev.security_events)
 THEN RAISE EXCEPTION 'STAGE1_HTTPS_FIXTURE_DEV_NOT_EMPTY'; END IF;
END $guard$;
INSERT INTO jw_dev.organizations(id,name,created_at) VALUES
 ('jw-v140-org-a','JW V140 Synthetic A',now()::text),
 ('jw-v140-org-b','JW V140 Synthetic B',now()::text),
 ('jw-v140-org-c','JW V140 Synthetic C',now()::text);
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES
 ('jw-v140-user-a','jw-v140-org-a','jw-v140-a@invalid.test','synthetic-no-password','A synthetic','admin',now()::text),
 ('jw-v140-user-b','jw-v140-org-b','jw-v140-b@invalid.test','synthetic-no-password','B synthetic','admin',now()::text),
 ('jw-v140-user-c','jw-v140-org-c','jw-v140-c@invalid.test','synthetic-no-password','C synthetic','admin',now()::text);
INSERT INTO jw_dev.sessions(token_hash,user_id,expires_at,csrf_token,created_at) VALUES
 ('83aa26c07d7521f829c9ccba6696f865405ad114f455657fbb61b49c49f89bef','jw-v140-user-a',(now()+interval '15 minutes')::text,'v140-csrf-token-A-12345678901234567890123',now()::text),
 ('091de0606d2c1ea1ee0d38c1d5c805f29d236eedad4e329ad81515c3f719a671','jw-v140-user-b',(now()+interval '15 minutes')::text,'v140-csrf-token-B-12345678901234567890123',now()::text),
 ('dc315c0527a64cf251ca4437af609b2510239c570e06b7884fb1ce5a9ddbac2b','jw-v140-user-c',(now()+interval '15 minutes')::text,'v140-csrf-token-C-12345678901234567890123',now()::text);
INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES
 ('jw-v140-customer-a','jw-v140-org-a','JW V140 Synthetic Customer A',now()::text),
 ('jw-v140-customer-b','jw-v140-org-b','JW V140 Synthetic Customer B',now()::text);
INSERT INTO jw_dev.quotes(id,org_id,customer_id,customer_name_snapshot,doc_no,title,status,vat_mode,created_at,updated_at) VALUES
 ('jw-v140-quote-a','jw-v140-org-a','jw-v140-customer-a','JW V140 A','JW140-A','JW V140 Synthetic Quote A','draft','taxable',now()::text,now()::text),
 ('jw-v140-quote-b','jw-v140-org-b','jw-v140-customer-b','JW V140 B','JW140-B','JW V140 Synthetic Quote B','draft','taxable',now()::text,now()::text);
INSERT INTO jw_dev.messenger_companies(org_id,business_number,verified_at,verification_kind) VALUES
 ('jw-v140-org-a','7311400001',now()::text,'demo'),
 ('jw-v140-org-b','7311400002',now()::text,'demo'),
 ('jw-v140-org-c','7311400003',now()::text,'demo');
INSERT INTO jw_dev.messenger_connections(id,org_a,org_b,requester_org,status,created_at) VALUES
 ('jw-v140-chat-ab','jw-v140-org-a','jw-v140-org-b','jw-v140-org-a','active',now()::text),
 ('jw-v140-chat-bc','jw-v140-org-b','jw-v140-org-c','jw-v140-org-b','active',now()::text);
INSERT INTO jw_dev.messenger_messages(id,connection_id,sender_org,sender_user,kind,body,request_id,created_at) VALUES
 ('jw-v140-message-ab','jw-v140-chat-ab','jw-v140-org-a','jw-v140-user-a','file','jw-v140-synthetic-content','jw-v140-msg-request-ab',now()::text),
 ('jw-v140-message-bc','jw-v140-chat-bc','jw-v140-org-b','jw-v140-user-b','text','jw-v140-synthetic-content-bc','jw-v140-msg-request-bc',now()::text);
INSERT INTO jw_dev.messenger_attachments(message_id,filename,mime,data,size_bytes,content_hash) VALUES (
 'jw-v140-message-ab','jw-v140-synthetic.txt','text/plain',
 convert_to('jw-v140-test-attachment','UTF8'),
 octet_length(convert_to('jw-v140-test-attachment','UTF8')),
 encode(sha256(convert_to('jw-v140-test-attachment','UTF8')),'hex')
);
COMMIT;
SELECT CASE WHEN (SELECT count(*) FROM jw_dev.organizations WHERE id LIKE 'jw-v140-%')=3
 AND (SELECT count(*) FROM jw_dev.sessions WHERE user_id LIKE 'jw-v140-%')=3
 AND (SELECT count(*) FROM jw_dev.messenger_attachments WHERE message_id LIKE 'jw-v140-%')=1
 THEN 'PASS_SYNTHETIC_HTTPS_FIXTURE_READY'
 ELSE 'FAIL_SYNTHETIC_HTTPS_FIXTURE' END AS verdict;
