-- V14.5: READ-ONLY actual PG17 signup readiness, never a signup or reset.
-- Run only against the approved jw_dev catalog; no customer rows or secrets.
-- This is an engineering subgate, NOT independent stage-2 acceptance.
WITH controls AS (
  SELECT
    EXISTS (
      SELECT 1 FROM pg_indexes
      WHERE schemaname='jw_dev' AND tablename='users'
        AND indexname='jw_v87_users_email_normalized_unique'
        AND indexdef ILIKE '%UNIQUE%'
    ) AS normalized_email_unique,
    EXISTS (
      SELECT 1 FROM pg_indexes
      WHERE schemaname='jw_dev' AND tablename='messenger_companies'
        AND indexname='messenger_companies_business_number_key'
        AND indexdef ILIKE '%UNIQUE%'
    ) AS business_number_unique,
    (
      SELECT count(*) FROM pg_roles
      WHERE rolname IN ('jw_stage1_trade_20261030','jw_stage1_auth_20261030')
        AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolinherit
    ) = 2 AS split_restricted_logins,
    (
      SELECT count(*) FROM pg_class c
      JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='jw_dev' AND c.relkind='r'
        AND c.relrowsecurity AND c.relforcerowsecurity
    ) = 35 AS forced_rls_baseline,
    EXISTS (
      SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='jw_dev' AND p.proname='v85_auth_issue_session'
    ) AS existing_session_issuer
)
SELECT *,
       CASE WHEN normalized_email_unique AND business_number_unique
              AND split_restricted_logins AND forced_rls_baseline
              AND existing_session_issuer
            THEN 'PASS_EXISTING_PREREQUISITES_ONLY'
            ELSE 'FAIL_EXISTING_PREREQUISITES' END AS catalog_gate,
       'NOT_VERIFIED'::text AS official_business_owner_proof,
       'NOT_VERIFIED'::text AS email_delivery_and_password_reset,
       'NOT_VERIFIED'::text AS public_signup_https_e2e,
       'BLOCKED'::text AS stage2_release_acceptance
FROM controls;
