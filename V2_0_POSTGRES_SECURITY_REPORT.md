# JARVIS WORKS V2.0 — Advanced PostgreSQL isolation release candidate

**Date:** 2026-10-19. **Status:** LOCAL CANDIDATE; **NOT PRODUCTION-READY**. No remote code, live customer records, or account billing changes.

## Mandate and baseline

Source of truth: V1.9 candidate from user's Library, verified locally before modification. Preserve SQLite web application and its document-confirmation workflow, V1.9 crypto-bound session mechanism, MFA and encrypted backup modules. Do not migrate operational DB or touch GitHub main.

## Security findings and candidate changes

1. **HIGH: Mutable audit/event records via regular tenant role.** V1.9 granted SELECT/INSERT/UPDATE/DELETE for both `public.audit_logs` and `public.security_events` to `jw_app`. A compromised app SQL context could falsify or erase security evidence. V2.0 explicitly REVOKEs those privileges, restores SELECT-only for tenant-filtered `audit_logs` and no direct access for `security_events`. A trusted append-only writer must be implemented independently before a full PostgreSQL app migration.
2. **HIGH: Missing tenant-composite relational integrity.** V1.9's synthetic schema linked quotes/orders/invoices and item records by IDs without tenant-scoped composite FKs. V2.0's synthetic fixture defines 8 **validated tenant-scoped composite FKs**, and policy installation refuses schemas without matching validated FK column pairs. Attack suite probes forged within-tenant records pointing at B-tenant customer/quote/order/invoice rows.
3. **HIGH: Postgres RLS does not mediate TRUNCATE/REFERENCES/TRIGGER.** Verify those privileges are absent on every protected table; preflight and read-only catalog audit reject them.
4. **MEDIUM: Mid-transaction tenant identity replacement.** Refuse `jw_guard.bind_session()` when a transaction already has a tenant claim, including when a second otherwise-valid token is supplied.
5. **MEDIUM: SECURITY DEFINER function search path defense.** Explicitly place `pg_temp` after trusted schemas; catalog audit checks exact list.
6. **Audit assurance:** verify catalog FK column orders and `convalidated`, audited role membership, no weak permissive policies, forbidden auth access, and malicious operation attempts.

These are policy/source changes, NOT proof of PostgreSQL enforcement. The current FastAPI app still uses SQLite; a PostgreSQL application adapter/migration, auth service role separation, production key management and trusted audit writer remain outstanding.

## Files changed or created

- `security/postgres_rls_proposal.sql`: tenant FK preflight, narrowed grants, dangerous-privilege preflight, trusted function path, no mid-transaction rebinding.
- `security/pg_rls_test_fixture.sql`: synthetic tenant-keyed FK test schema.
- `scripts/check_postgres_rls.py`: actual Postgres catalog FK, permissions and security-definer checks.
- `scripts/test_postgres_rls_runtime.py`: A/B row read/write, FK, audit deletion, rebind, session replay and revocation attacks.
- `scripts/run_postgres_isolation_ci.py`: fail-closed provision/test/destroy ephemeral PostgreSQL DB. Requires explicit local supervisor DSN, test-only guard and nonexisting jw_app.
- `.github/workflows/pg-rls-attack-gate.yml`: isolated PostgreSQL 17 GitHub Actions service, scoped to `feature/pg-rls-v2-0-gate` push or manual workflow dispatch, no schedule, read-only repository, eight-minute job cap. **Not uploaded/triggered.** If this branch is uploaded, the matching push triggers a billable GitHub Actions run; check spending limits first.
- `tests/test_pg_rls_v19.py`, `tests/test_pg_rls_v20.py`: offline regression and fail-closed gate checks.

## What was actually verified in this session

- Static security/MFA/backup/SQLite workflow group: **85 PASS** (after final tightening).
- Existing document supplement group: **21 PASS**.
- Existing order smart import group excluding randomized stress: **36 PASS**.
- Existing external quotation import group: **20 PASS**.
- Existing 200-case randomized money calculation test: **1 PASS**.
- **TOTAL = 163/163 PASS**, separately executed groups. One early combined import run timed out and was not counted; all individual tests were rerun successfully.
- `python -m compileall -q app scripts tests`: PASS.
- `node --check app/static/app.js`: PASS.
- `tests/browser_smoke.py`: PASS — desktop and mobile Chromium quote -> order -> invoice -> payment, prior web app workflow.
- ZIP inventory and SHA-256 manifest will be finalized on packaging.
- **Real PostgreSQL 17 live RLS, transactional pool re-use, policy syntax and actual tenant attack outcomes: NOT RUN.** Local server/psycopg absent; `apt-get update` timed out. CI workflow was not published, therefore no hosted test occurred. The runner without explicitly configured local DSN returns code `2` / NOT RUN.

## Mandatory release gates (fail closed)

1. Run `run_postgres_isolation_ci` on *real* ephemeral PG17 and record exact commits, runner/job IDs, 0 exit, RLS catalog query evidence and A/B cross-tenant attack outcomes. Until then, RLS database enforcement must NOT be marked PASS.
2. Build and validate schema-compatible PostgreSQL persistence adapter for all existing entities, full MFA authentication service / writer separation, tenant connection pooling, user role authorization.
3. Schema migration with replica/backup before cutover, immutable event journal writer, complete consistency checks, concurrency/race tests, injection audit, scanner process containment.
4. Independent adversarial assessment; test recovery and encrypted backups; security monitoring and alerts.
5. Deploy only after all gates pass. Do not use real customer identities/documents in this candidate.

**Overall: PARTIAL / PG LIVE TEST NOT RUN / PRODUCTION BLOCKED.**
