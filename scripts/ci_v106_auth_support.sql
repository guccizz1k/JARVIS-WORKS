-- V10.6 CI ONLY: auxiliary auth tables on disposable PostgreSQL17.
-- NEVER execute this file on Render, Supabase, or any persistent database.
-- The actual auth routines come unmodified from migrations/v85_auth_stage.sql.
CREATE TABLE jw_dev.mfa_credentials (
    user_id text PRIMARY KEY REFERENCES jw_dev.users(id),
    secret_encrypted text NOT NULL DEFAULT '',
    last_counter bigint NOT NULL DEFAULT -1
);
CREATE TABLE jw_dev.staff_disabled (
    user_id text PRIMARY KEY REFERENCES jw_dev.users(id)
);
CREATE TABLE jw_dev.login_failures (
    email text PRIMARY KEY,
    attempts bigint NOT NULL,
    first_failed_at text NOT NULL
);
CREATE TABLE jw_dev.mfa_recovery_codes (
    user_id text NOT NULL REFERENCES jw_dev.users(id),
    code_hash text NOT NULL,
    consumed_at text,
    PRIMARY KEY (user_id, code_hash)
);
CREATE TABLE jw_dev.security_events (
    id text PRIMARY KEY,
    org_id text NOT NULL REFERENCES jw_dev.organizations(id),
    actor_id text NOT NULL REFERENCES jw_dev.users(id),
    event_type text NOT NULL,
    created_at text NOT NULL
);
ALTER TABLE jw_dev.mfa_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.mfa_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.staff_disabled ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.staff_disabled FORCE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.login_failures ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.login_failures FORCE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.mfa_recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.mfa_recovery_codes FORCE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.security_events FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ALL TABLES IN SCHEMA jw_dev FROM PUBLIC;
