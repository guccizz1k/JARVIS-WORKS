# JARVIS WORKS V1.9 — Advanced Tenant Isolation Hardening

**Candidate / no deployment.** This package is derived from V1.8. Original SQLite application and automatic document workflows remain unchanged. PostgreSQL is **not yet connected to FastAPI**. No real Postgres server was present in the local execution environment, so **runtime PostgreSQL RLS attack tests = NOT RUN**, not PASS. Never ingest real company information with this candidate.

## High-severity weakness discovered in the prior policy

The original V1.8 design used `current_setting('jw.org_id')` as the authorization source. PostgreSQL custom GUCs can be assigned by an ordinary connection; code execution or SQL injection under the tenant DB role could therefore switch to another organization's ID. RLS `FORCE` does not make an untrusted tenant ID trustworthy.

V1.9 replaces the **executable** `security/postgres_rls_proposal.sql` (not merely an extra policy) with a transaction-scoped **HMAC-protected tenant claim**. The production verifier has not been implemented yet.

## Trust boundaries

1. The trusted authentication subsystem authenticates the session, checks its MFA status, and creates an opaque unpredictable session token. Only a *separately privileged* authentication service may write `jw_guard.authenticated_sessions` (SHA-256 token digests, org/user ID, expiration, revocation, MFA confirmation). No raw token is written to the DB.
2. The regular application connects as `jw_app`, a non-owner, `NOSUPERUSER NOBYPASSRLS NOCREATEROLE` DB role without `CREATE` on `public`/`jw_guard`. It invokes `jw_guard.bind_session(token)` once **inside each explicit transaction** (including SELECT-only requests), using a backend parameter. Never concatenate credentials into SQL strings or log SQL parameters.
3. The `SECURITY DEFINER` binder validates MFA, revocation and expiry; retrieves an isolated DB signing key; and `SET LOCAL`s a tenant ID, current transaction ID and signature. The session registry and key are inaccessible to `jw_app`.
4. `jw_guard.current_tenant()` checks all three values, the **current transaction ID**, and the DB-side HMAC. Policies reference this function and include `USING` **and** `WITH CHECK`. Arbitrarily setting a tenant ID or replaying a previous transaction's claims must return zero rows / fail writes.
5. `FORCE ROW LEVEL SECURITY` applies to organization, customer, quote, order, invoice, payment, audit, event, import preview and child item tables. Parent-child policies inherit the signed organization; sensitive identity/auth tables are revoked from `jw_app`. Authentication and onboarding must use separate reviewed services.
6. An explicit transaction boundary is **mandatory**. Every transaction must bind the authenticated session; a connection-pool reuse must not inherit a tenant. The auth session record must be expired/revoked by the authentication service.

**Unresolved architectural items:** stronger composite tenant-scoped foreign keys (IDs can otherwise cross-link tenant records), actual PostgreSQL schema migration and adapter, sensitive-column encryption, staff RBAC, lifecycle/privilege separation for auth provisioning, statement timeout and pool hygiene, encrypted backups, antivirus sandbox, external independent pentest. PostgreSQL foreign keys can reveal existence of other-tenant IDs, even when rows are invisible under RLS. Do not call the whole DB layer secure until these are addressed.

## Runtime test instructions (for an independently provisioned PostgreSQL test cluster)

**Never run on production.** Provision a completely isolated *throwaway* DB whose name starts with `jw_v19_test_`. A privileged migration-owner connection and a **separate** unprivileged LOGIN role `jw_app` are required. Do not hardcode actual passwords in source. Provision `jw_app` externally with restricted privileges; it MUST NOT own the tables, own the guarded schema, inherit the owner role, be superuser, or have `BYPASSRLS`.

1. Ensure `pgcrypto` extension availability. Use an isolated ephemeral PostgreSQL cluster only.
2. As schema migration owner, execute `security/pg_rls_test_fixture.sql` in the empty test DB. This fixture refuses databases not named `jw_v19_test_*` and refuses overwriting existing customers.
3. As owner, execute `security/postgres_rls_proposal.sql` in that test DB (fixture first). Apply it to a real schema ONLY after verifying the real migrated schema and additive migration plan. Never apply this test fixture to an operational DB.
4. Install `requirements-postgres-check.txt` in an **isolated**, dependency-pinned development environment.
5. Configure **test-only** environment variables `JW_PG_TEST_ADMIN_DSN`, `JW_PG_TEST_APP_DSN`, and `JW_PG_ALLOW_TEST_WRITES=ONLY_EPHEMERAL_DATABASE` using Codespaces secret storage (not committed source). Run `python -m scripts.test_postgres_rls_runtime`.
6. For the read-only catalog audit use `JW_PG_CHECK_DSN` and `python -m scripts.check_postgres_rls`.
7. Record server version, database, fixture hash, both distinct roles, live pass/fail results and backup/restore outcome. If the PostgreSQL server, DSNs, or psycopg are absent, report **NOT RUN**.

The runtime suite attempts unbound access, forged tenant GUCs, wrong-MFA and expired sessions, cross-tenant reads/updates/deletes/inserts, child-record injection, direct identity/key access, transaction proof replay, B-tenant session separation and revoked-session reuse.

## Release gates

- **Gate 1:** policy syntax in PostgreSQL, roles, `SECURITY DEFINER` safe search path, no extra permissive policies.
- **Gate 2:** live A/B tenant SQL read/write attacks fail, no direct access to auth and secret material, forged GUCs fail.
- **Gate 3:** session expiry/revocation, prepared statements, savepoints, pooling, transaction replay, multi-worker concurrency, zero data loss during dual-write/migration, composite FK enforcement.
- **Gate 4:** quotation/order/import browser flows and explicit user approval with web UX/regressions.
- **Gate 5:** full app PostgreSQL adapter, MFA recovery, encrypted data/backups, production change plan and rollback, external security assessment.

**Current state:** offline hardening tests can PASS, live PostgreSQL and application integration must remain **NOT RUN/BLOCKED**. Maintain existing production fail-closed behavior in `app/main.py`.
