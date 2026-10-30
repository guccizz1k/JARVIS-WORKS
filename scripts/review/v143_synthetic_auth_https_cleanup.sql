-- Paired V143 cleanup. Delete only exact synthetic test identities.
-- Runs even if the external HTTPS probe failed or was interrupted.
BEGIN;
SET LOCAL lock_timeout='1200ms';
SET LOCAL statement_timeout='20s';
DO $g$ BEGIN
 IF current_database()<>'postgres' OR
 EXISTS (SELECT 1 FROM jw_dev.messenger_messages WHERE id LIKE 'jw-v143-%')
 OR EXISTS (SELECT 1 FROM jw_dev.messenger_attachments WHERE message_id LIKE 'jw-v143-%')
 THEN RAISE EXCEPTION 'V143_UNEXPECTED_IMMUTABLE_MESSAGES'; END IF;
END $g$;
DELETE FROM jw_dev.security_events
 WHERE org_id IN ('jw-v143-orga','jw-v143-orgb')
 AND actor_id IN ('jw-v143-ua','jw-v143-ub');
DELETE FROM jw_dev.login_failures
 WHERE email IN ('jw-v143-a@invalid.test','jw-v143-b@invalid.test');
DELETE FROM jw_dev.sessions WHERE user_id IN ('jw-v143-ua','jw-v143-ub');
DELETE FROM jw_dev.mfa_recovery_codes WHERE user_id='jw-v143-ub';
DELETE FROM jw_dev.mfa_credentials WHERE user_id='jw-v143-ub';
DELETE FROM jw_dev.users WHERE id IN ('jw-v143-ua','jw-v143-ub');
DELETE FROM jw_dev.organizations WHERE id IN ('jw-v143-orga','jw-v143-orgb');
DO $c$ BEGIN
 IF EXISTS (SELECT 1 FROM jw_dev.organizations WHERE id LIKE 'jw-v143-%')
 OR EXISTS (SELECT 1 FROM jw_dev.users WHERE id LIKE 'jw-v143-%')
 OR EXISTS (SELECT 1 FROM jw_dev.sessions WHERE user_id LIKE 'jw-v143-%')
 OR EXISTS (SELECT 1 FROM jw_dev.login_failures WHERE email LIKE 'jw-v143-%')
 OR EXISTS (SELECT 1 FROM jw_dev.security_events WHERE org_id LIKE 'jw-v143-%')
 OR EXISTS (SELECT 1 FROM jw_dev.mfa_credentials WHERE user_id='jw-v143-ub')
 OR EXISTS (SELECT 1 FROM jw_dev.mfa_recovery_codes WHERE user_id='jw-v143-ub')
 THEN RAISE EXCEPTION 'V143_AUTH_FIXTURE_NOT_CLEAN'; END IF;
END $c$;
COMMIT;
SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM jw_dev.organizations WHERE id LIKE 'jw-v143-%')
 AND NOT EXISTS(SELECT 1 FROM jw_dev.security_events WHERE org_id LIKE 'jw-v143-%')
 AND NOT EXISTS(SELECT 1 FROM jw_dev.login_failures WHERE email LIKE 'jw-v143-%')
 THEN 'PASS_V143_AUTH_FIXTURE_CLEANED'
 ELSE 'FAIL_V143_AUTH_FIXTURE_CLEANUP' END AS verdict;
