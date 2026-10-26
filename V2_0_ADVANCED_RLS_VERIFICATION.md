# JARVIS WORKS V2.0 — Advanced PostgreSQL Tenant Isolation Candidate

**Status: PARTIAL / LOCAL VERIFICATION. NOT DEPLOYED. NOT A PRODUCTION SECURITY ATTESTATION.**

Date: 2026-10-19. Base: V1.9 independently preserved candidate. No changes to the GitHub `main`, previous feature branches, Codespaces, or any production data.

## 1. Security objective and what actually changed

- Added PostgreSQL 17 manual-only ephemeral CI integration entry point (`.github/workflows/pg-rls-attack-gate.yml`) and a local `scripts/run_postgres_isolation_ci.py` runner. Both are candidates **not published to GitHub**, so no GitHub Actions were started.
- `security/postgres_rls_proposal.sql` now checks that every required validated `(foreign_id, org_id) -> (id, org_id)` composite FK exists before enabling RLS. `security/pg_rls_test_fixture.sql` models these relationships; cross-tenant references must be rejected.
- The `jw_app` DB role cannot UPDATE/DELETE/TRUNCATE privileged audit events and cannot directly read identity/session tables, security events, or signing keys. `scripts/check_postgres_rls.py` audits effective privileges and real catalog FK columns.
- Transaction-local RLS signed tenant context includes **session token digest** in the HMAC, not just organization and transaction ID. `jw_guard.current_tenant()` rechecks MFA status, revocation and expiry at statement evaluation. A revocation in another transaction should take effect on the following READ COMMITTED statement. This requires the live PG runtime test to establish, and strong isolation levels or long queries need additional operational limits.
- `scripts/test_postgres_rls_runtime.py` expands tests for cross-tenant foreign reference attempts, audit mutations, wrong-MFA/expired sessions, forged tenant context, cross-transaction replay, pool connection reuse and **revoke-after-bind**.
- Test-only Postgres runner refuses absent explicit allow flags and DSN, non-loopback hosts, non-`postgres` administrator, pre-existing non-template databases, non-system roles, and user-created public tables/views; creates random test DB and cleans up. This is defense in depth, not a guarantee that an external Postgres instance is disposable. Run only in dedicated ephemeral CI.
- Existing FastAPI SQLite application is intentionally **unchanged**. No implicit production DB switch, automatic migration or live deployment.

## 2. Verification evidence

| Test | Outcome | Scope |
|---|---|---|
| pytest security/auth/backup and PG static checks | 56/56 PASS | Offline/unit |
| pytest workflows/quote/automation | 48/48 PASS | SQLite app tests |
| pytest import supplement | 21/21 PASS | SQLite app tests |
| pytest smart import | 37/37 PASS | SQLite app tests |
| **Total automated tests** | **162/162 PASS** | Split invocations, not one uninterrupted session |
| `node --check app/static/app.js` | PASS | Frontend syntax |
| `python -m py_compile ...` | PASS | Backend and runners syntax |
| Browser smoke desktop/mobile Chromium | PASS | Quote→order→invoice→payment |
| Browser quote import Chromium | PASS | Upload→review→draft only |
| Browser order import Chromium | PASS | Upload→approval→order/analytics |
| Browser incomplete-order supplement Chromium | PASS | Missing field→review→order |
| Real PostgreSQL engine / RLS SQL execution | **NOT RUN** | No Postgres binary/server or psycopg in execution environment |
| Real A/B cross-tenant DB attack and audit | **NOT RUN** | Requires isolated PostgreSQL service |
| API PostgreSQL adapter / data migration | **NOT IMPLEMENTED** | SQLite app preserved |
| Real production MFA, encryption and penetration test | **NOT RUN / BLOCKED** | Do not use real customer PII |

**The SQL policy is unverified by PostgreSQL execution.** Source-level assertions cannot prove executable SQL correctness, query-plan behavior, actual grants or runtime security. Do not call V2.0 RLS production-ready.

## 3. Safely obtain real PostgreSQL proof (next independent gate)

1. Publish the independently reviewed V2.0 candidate to a **separate** protected branch only with authorized GitHub write access. Do not merge to `main` or lower repository security settings.
2. Manually dispatch `.github/workflows/pg-rls-attack-gate.yml` on the candidate branch; workflow has `permissions: contents: read`, a single ephemeral `postgres:17` CI service, no production DSNs, and an 8-minute job timeout. Confirm Actions $5 budget and stop-on-limit are active before running (this is not free guaranteed).
3. Require: CI job logs, PG version, exact commit SHA and all catalog/adversarial checks PASS. Any syntax error, missing privilege or attack success is FAIL; infrastructure not provisioned is NOT RUN.
4. Even if it passes: implement the FastAPI PostgreSQL adapter and migrate sample/legacy data with staged backup, dual-read validation, reconciliation and rollback; separately test connection pools, transaction isolation levels, staff RBAC, field encryption, key rotation, backups, malware scanner and independent security review before real data.

## 4. Fail-closed rules

- Production startup with the current SQLite architecture remains blocked. Do not upload real company documents.
- Strict no-change to earlier GitHub branches and stored ZIP source candidates.
- If test DB evidence is missing or tests cannot be reproduced, report **NOT RUN**.
- No automatic recurring GitHub Actions test; this gate is manual-only to avoid surprise CI charges.
