-- V14.9: live DEV PostgreSQL17 negative-session role proof, strictly READ ONLY.
-- Do NOT treat empty rows alone as proof of A/B/C positive tenant isolation.
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';
SET LOCAL lock_timeout = '900ms';
SET LOCAL ROLE jw_app_dev;
DO $v149_negative$
BEGIN
 IF current_user <> 'jw_app_dev'
 OR jw_dev.current_org_from_session() IS NOT NULL
 OR EXISTS (SELECT 1 FROM jw_dev.orders)
 OR EXISTS (SELECT 1 FROM jw_dev.invoices)
 OR EXISTS (SELECT 1 FROM jw_dev.payments)
 OR EXISTS (SELECT 1 FROM jw_dev.customers)
 OR EXISTS (SELECT 1 FROM jw_dev.messenger_messages)
 THEN
   RAISE EXCEPTION 'FAIL_V149_UNAUTHENTICATED_ROLE_ACCESS';
 END IF;
END $v149_negative$;
RESET ROLE;
ROLLBACK;
WITH c AS (
 SELECT
 (SELECT count(*) FROM pg_class k JOIN pg_namespace n ON n.oid=k.relnamespace
  WHERE n.nspname='jw_dev' AND k.relkind='r' AND k.relrowsecurity AND k.relforcerowsecurity) AS forced_rls,
 (SELECT count(*) FROM pg_policies WHERE schemaname='jw_dev') AS policies,
 (SELECT count(*) FROM pg_roles WHERE rolname IN ('jw_stage1_trade_20261030','jw_stage1_auth_20261030')
  AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolinherit) AS separated_logins,
 (SELECT count(*) FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace
  WHERE n.nspname='jw_dev' AND f.prosecdef
    AND EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a
       WHERE a.grantee=0 AND a.privilege_type='EXECUTE')) AS public_executable_definers
)
SELECT forced_rls,policies,separated_logins,public_executable_definers,
 CASE WHEN forced_rls=35 AND policies=40 AND separated_logins=2 AND
           public_executable_definers=0
      THEN 'PASS_V149_READONLY_NO_SESSION_ROLE_NEGATIVE_AND_CATALOG'
      ELSE 'FAIL_V149_CATALOG_INTEGRITY' END AS verdict
FROM c;
