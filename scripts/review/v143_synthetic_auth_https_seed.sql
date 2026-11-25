-- V143 reviewed synthetic auth-only HTTP fixture. Isolated, empty jw_dev only.
-- Synthetic test password is NOT a customer password. Never use on production.
-- Paired cleanup mandatory on success, failure or interruption.
BEGIN;
SET LOCAL lock_timeout='1200ms';
SET LOCAL statement_timeout='20s';
DO $g$ BEGIN
 IF current_database() <> 'postgres'
 OR EXISTS(SELECT 1 FROM jw_dev.organizations)
 OR EXISTS(SELECT 1 FROM jw_dev.users)
 OR EXISTS(SELECT 1 FROM jw_dev.sessions)
 OR EXISTS(SELECT 1 FROM jw_dev.login_failures)
 OR EXISTS(SELECT 1 FROM jw_dev.security_events)
 OR EXISTS(SELECT 1 FROM jw_dev.messenger_messages)
 OR EXISTS(SELECT 1 FROM jw_dev.messenger_attachments)
 OR EXISTS(SELECT 1 FROM jw_dev.quotes)
 OR EXISTS(SELECT 1 FROM jw_dev.payments)
 THEN RAISE EXCEPTION 'V143_REQUIRES_EMPTY_ISOLATED_DEV'; END IF;
END $g$;
INSERT INTO jw_dev.organizations(id,name,created_at) VALUES
('jw-v143-orga','Synthetic V143 A',now()::text),
('jw-v143-orgb','Synthetic V143 B',now()::text);
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES
('jw-v143-ua','jw-v143-orga','jw-v143-a@invalid.test','pbkdf2_sha256$260000$71f93823ecb2e1bb50124ce7cc2c43eb$6b5d9f6475272ec71ea0f0c1cb5a1b1c42da933a2edd29fe7da25e422bfd9a64','Synthetic A','admin',now()::text),
('jw-v143-ub','jw-v143-orgb','jw-v143-b@invalid.test','pbkdf2_sha256$260000$7f7b7bee73311c46ebb05ae8d2a59594$e2b0604a491abd3a7dfd741c50b269049f0ce8303d2b015933c35b274e0d1d83','Synthetic B','admin',now()::text);
INSERT INTO jw_dev.mfa_credentials(user_id,secret_encrypted,pending_encrypted,last_counter)
 VALUES('jw-v143-ub','synthetic-mfa-device-does-not-exist','',12);
INSERT INTO jw_dev.mfa_recovery_codes(user_id,code_hash,created_at)
 VALUES('jw-v143-ub','9a41b44944a8a53730ebf2e821aa9d1c4db1d51d7db87d189e9fc057c48d7ea5',now()::text);
COMMIT;
SELECT CASE WHEN
 (SELECT count(*) FROM jw_dev.organizations WHERE id LIKE 'jw-v143-%')=2
 AND (SELECT count(*) FROM jw_dev.users WHERE id LIKE 'jw-v143-%')=2
 AND (SELECT count(*) FROM jw_dev.mfa_credentials WHERE user_id='jw-v143-ub')=1
 AND (SELECT count(*) FROM jw_dev.mfa_recovery_codes WHERE user_id='jw-v143-ub')=1
 THEN 'PASS_V143_SYNTHETIC_AUTH_FIXTURE_READY'
 ELSE 'FAIL_V143_SYNTHETIC_AUTH_FIXTURE' END AS verdict;
