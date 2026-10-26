# JARVIS WORKS V1.9 — Advanced RLS Security Hardening Report

**Date:** 2026-10-18 (local development candidate). **Release:** PARTIAL / PRODUCTION BLOCKED.

## Objective

Upgrade the V1.8 PostgreSQL RLS candidate to defend against SQL injection attempts that assign another organization's GUC. Make cross-tenant checks, transactional scope, database privilege boundaries and realistic adversarial SQL verification explicit. Preserve all preexisting business/automatic-document workflows and the V1.8 SQLite production hard stop.

## Root cause fixed in candidate SQL

The prior `postgres_rls_proposal.sql` used `org_id = current_setting('jw.org_id')` as an RLS source. Custom PostgreSQL configuration settings are writable by database sessions and do not by themselves authenticate a tenant. A compromised/SQL-injected `jw_app` session could set another org ID. The executable policy file has now been replaced rather than retaining the vulnerable policy for reuse.

**New candidate mechanism:** separate guarded hashed MFA-authenticated session registry, signed per-transaction org claim stored in `SET LOCAL` GUCs, signature validated by a `SECURITY DEFINER` function with DB-protected HMAC key, table-wide `ENABLE/FORCE ROW LEVEL SECURITY`, parent-child policies, narrow business-table grants, access revocation on user/auth/private tables, fail-closed unexpected extra policies, function/schema checks, role owner checks. Never trust client-supplied `org_id`.

## Files updated / added

- `security/postgres_rls_proposal.sql`: hardened candidate replacing unsafe GUC-only authorization.
- `scripts/check_postgres_rls.py`: expanded live-catalog audit; returns exit 2 when missing database.
- `scripts/test_postgres_rls_runtime.py`: REAL PostgreSQL A/B read/write, forgery, replay, revocation adversarial suite, strictly requiring an isolated throwaway DB.
- `security/pg_rls_test_fixture.sql`: fabricated tables and records, refusing a non-test or nonempty database.
- `tests/test_rls_plan_v18.py`: old V1.8 policy expectation replaced with hardened assertions.
- `tests/test_pg_rls_v19.py`: 12 static/offline authorization/attack-model and fail-closed-gate tests.
- `docs/V1_9_RLS_HARDENING.md`, `docs/DEPLOYMENT_READINESS.md`, `README.md`: migration boundaries and future live-test runbook.

## Executed verification evidence

- Security/auth/encrypted backup + old/new RLS offline: **45 PASS**.
- Existing quotation/orders/invoice/payment workflow: **48 PASS**.
- Document import core test splits: **12 PASS + 12 PASS + 13 PASS**.
- Import supplement test: **21 PASS**.
- **TOTAL: 151/151 PASS**, split into 6 separately executed groups. The first unsegmented document-import run hit execution timeout and was NOT counted as PASS; all 58 targeted cases were subsequently run in three subgroups plus the 21-case supplement group.
- Python syntax compilation: PASS.
- Browser JavaScript syntax check: PASS (`node --check`).
- Real PostgreSQL RLS test gate: `python -m scripts.test_postgres_rls_runtime` returns exit code **2 / NOT RUN** when DSNs absent.
- Actual PostgreSQL syntax parsing, catalog audit, A/B attacks, session pooling and concurrency tests: **NOT RUN** (no `postgres`, `initdb`, `psql` or `psycopg` installed in the working environment).
- Real app SQLite→PostgreSQL migration: **NOT IMPLEMENTED**. Enterprise production deployment: **BLOCKED**.

## Security warnings / remaining gaps

1. The policy is NOT yet executable proof: PostgreSQL may uncover syntax or schema issues. Never mark live test PASS before running against a real isolated PostgreSQL database.
2. Authentication service syncing verified session hash/revocation to private `jw_guard.authenticated_sessions` is NOT implemented in FastAPI. Role segregation and secret provisioning must be verified end-to-end.
3. RLS is not a substitute for **tenant-matched foreign keys**; PostgreSQL FK checks bypass RLS and can create inference/cross-link problems. Define and validate composite tenant FKs / source-document relationships before production.
4. Financial PII at rest, user role RBAC, encrypted originals, malware sandbox/AV, scheduled encrypted backups with recovery drills, external pentest remain incomplete.
5. Signing key requires KMS/lifecycle/rotation; parameter logging must not record session tokens. Keep transaction times short and bind session on every DB transaction and pool checkout.
6. Existing 6 business functions remain backed by SQLite. Running the migration SQL against SQLite is unsupported and MUST NOT be attempted.

## 5-Gate

| Gate | Decision |
|---|---|
| 1 Code/syntax | PASS Python/JS and static candidate structure; PostgreSQL SQL parser NOT RUN |
| 2 Functional correctness | PASS 151 offline tests, real PostgreSQL authorization NOT RUN |
| 3 Integrity/regression | PASS offline workflow; SQL connection/pool + migration NOT RUN |
| 4 UI/UX | No UI changes; existing UI regression unit tests PASS, live browser NOT RUN this phase |
| 5 Operations/security | BLOCKED: no PG live RLS, no migration, no external pentest/production release |

**Next priority:** execute PostgreSQL fixture + hardened policies in an isolated throwaway PG server under separate admin/`jw_app` roles, run live adversarial suite and privilege catalog audit, fix any failures, then design composite tenant FKs and a transactional SQLite-to-PostgreSQL migration with backup/rollback and zero trusted-data loss checks. Operational deploy requires separate approval.
