-- Owner-approved isolated DEV review cleanup. Exact V141 synthetic IDs only.
-- Must execute after the hosted probe on PASS, FAIL, BLOCKED or interrupted run.
-- Never disable DELETE guards, RLS, immutable messenger triggers or audit.
BEGIN;
SET LOCAL lock_timeout='1200ms';
SET LOCAL statement_timeout='15s';
DO $guard$
BEGIN
 IF current_database()<>'postgres'
 OR EXISTS (SELECT 1 FROM jw_dev.messenger_messages WHERE id LIKE 'jw-v141-%')
 OR EXISTS (SELECT 1 FROM jw_dev.messenger_attachments WHERE message_id LIKE 'jw-v141-%')
 THEN RAISE EXCEPTION 'V141_UNEXPECTED_IMMUTABLE_MESSENGER_FIXTURE'; END IF;
END $guard$;
DELETE FROM jw_dev.quotes WHERE id IN ('jw-v141-qa','jw-v141-qb');
DELETE FROM jw_dev.customers WHERE id IN ('jw-v141-ca','jw-v141-cb');
DELETE FROM jw_dev.sessions WHERE user_id IN ('jw-v141-ua','jw-v141-ub','jw-v141-uc');
DELETE FROM jw_dev.users WHERE id IN ('jw-v141-ua','jw-v141-ub','jw-v141-uc');
DELETE FROM jw_dev.organizations WHERE id IN ('jw-v141-orga','jw-v141-orgb','jw-v141-orgc');
DO $assert$
BEGIN
 IF EXISTS(SELECT 1 FROM jw_dev.organizations WHERE id LIKE 'jw-v141-%')
 OR EXISTS(SELECT 1 FROM jw_dev.users WHERE id LIKE 'jw-v141-%')
 OR EXISTS(SELECT 1 FROM jw_dev.sessions WHERE user_id LIKE 'jw-v141-%')
 OR EXISTS(SELECT 1 FROM jw_dev.customers WHERE id LIKE 'jw-v141-%')
 OR EXISTS(SELECT 1 FROM jw_dev.quotes WHERE id LIKE 'jw-v141-%')
 THEN RAISE EXCEPTION 'V141_FIXTURE_RESIDUAL'; END IF;
END $assert$;
COMMIT;
SELECT CASE WHEN EXISTS(SELECT 1 FROM jw_dev.organizations WHERE id LIKE 'jw-v141-%')
 OR EXISTS(SELECT 1 FROM jw_dev.users WHERE id LIKE 'jw-v141-%')
 OR EXISTS(SELECT 1 FROM jw_dev.sessions WHERE user_id LIKE 'jw-v141-%')
 OR EXISTS(SELECT 1 FROM jw_dev.customers WHERE id LIKE 'jw-v141-%')
 OR EXISTS(SELECT 1 FROM jw_dev.quotes WHERE id LIKE 'jw-v141-%')
 THEN 'FAIL_V141_RESIDUAL_DATA' ELSE 'PASS_V141_SYNTHETIC_ABC_CLEANUP' END AS verdict;
