-- Review-only: synthetic non-messenger A/B/C fixture on verified-empty jw_dev.
-- All token hashes are SHA256 of matching synthetic cookies in the stage probe.
-- Must execute the paired cleanup after the hosted test regardless of result.
BEGIN;
SET LOCAL lock_timeout='1000ms';
SET LOCAL statement_timeout='15s';
DO $guard$
BEGIN
 IF current_database()<>'postgres'
 OR EXISTS(SELECT 1 FROM jw_dev.organizations)
 OR EXISTS(SELECT 1 FROM jw_dev.users)
 OR EXISTS(SELECT 1 FROM jw_dev.sessions)
 OR EXISTS(SELECT 1 FROM jw_dev.customers)
 OR EXISTS(SELECT 1 FROM jw_dev.quotes)
 OR EXISTS(SELECT 1 FROM jw_dev.orders)
 OR EXISTS(SELECT 1 FROM jw_dev.invoices)
 OR EXISTS(SELECT 1 FROM jw_dev.payments)
 OR EXISTS(SELECT 1 FROM jw_dev.messenger_messages)
 OR EXISTS(SELECT 1 FROM jw_dev.messenger_attachments)
 OR EXISTS(SELECT 1 FROM jw_dev.security_events)
 THEN RAISE EXCEPTION 'JW_V141_EMPTY_DEV_PRECONDITION_FAILED'; END IF;
END $guard$;
INSERT INTO jw_dev.organizations(id,name,created_at) VALUES
('jw-v141-orga','V141 Synthetic A',now()::text),
('jw-v141-orgb','V141 Synthetic B',now()::text),
('jw-v141-orgc','V141 Synthetic C',now()::text);
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES
('jw-v141-ua','jw-v141-orga','v141-a@invalid.test','synthetic-no-password','A','admin',now()::text),
('jw-v141-ub','jw-v141-orgb','v141-b@invalid.test','synthetic-no-password','B','admin',now()::text),
('jw-v141-uc','jw-v141-orgc','v141-c@invalid.test','synthetic-no-password','C','admin',now()::text);
INSERT INTO jw_dev.sessions(token_hash,user_id,expires_at,csrf_token,created_at) VALUES
('83aa26c07d7521f829c9ccba6696f865405ad114f455657fbb61b49c49f89bef','jw-v141-ua',(now()+interval '30 minutes')::text,'v141-csrf-A-12345678901234567890123456789',now()::text),
('091de0606d2c1ea1ee0d38c1d5c805f29d236eedad4e329ad81515c3f719a671','jw-v141-ub',(now()+interval '30 minutes')::text,'v141-csrf-B-12345678901234567890123456789',now()::text),
('dc315c0527a64cf251ca4437af609b2510239c570e06b7884fb1ce5a9ddbac2b','jw-v141-uc',(now()+interval '30 minutes')::text,'v141-csrf-C-12345678901234567890123456789',now()::text);
INSERT INTO jw_dev.customers(id,org_id,name,created_at) VALUES
('jw-v141-ca','jw-v141-orga','Synthetic Customer A',now()::text),
('jw-v141-cb','jw-v141-orgb','Synthetic Customer B',now()::text);
INSERT INTO jw_dev.quotes(id,org_id,customer_id,customer_name_snapshot,doc_no,title,status,vat_mode,created_at,updated_at) VALUES
('jw-v141-qa','jw-v141-orga','jw-v141-ca','Customer A','V141-A','Synthetic Quote A','draft','taxable',now()::text,now()::text),
('jw-v141-qb','jw-v141-orgb','jw-v141-cb','Customer B','V141-B','Synthetic Quote B','draft','taxable',now()::text,now()::text);
COMMIT;
SELECT CASE WHEN (SELECT count(*) FROM jw_dev.organizations WHERE id LIKE 'jw-v141-%')=3
 AND (SELECT count(*) FROM jw_dev.users WHERE id LIKE 'jw-v141-%')=3
 AND (SELECT count(*) FROM jw_dev.sessions WHERE user_id LIKE 'jw-v141-%')=3
 AND (SELECT count(*) FROM jw_dev.customers WHERE id LIKE 'jw-v141-%')=2
 AND (SELECT count(*) FROM jw_dev.quotes WHERE id LIKE 'jw-v141-%')=2
 THEN 'PASS_V141_ABC_HTTPS_FIXTURE_SEEDED' ELSE 'FAIL_V141_ABC_HTTPS_FIXTURE_SEEDED' END AS verdict;
