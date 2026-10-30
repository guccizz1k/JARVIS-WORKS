# V15.4 — Actual delivery review HTTP integration and PG17 audit validation

Date: 2026-10-30 (Asia/Seoul). Protected parent Draft PR #66 HEAD `783c6359856d9a712db26125a5ee60f67fc7ebd7`. Review-only changes. No main merge, no staging/production redeploy, no persistent Supabase migration/role/secret changes, no real business data, no paid CI/API.

## Actual engineering (not a test-only SQL script)

1. **New real FastAPI handler** `app/pg_delivery_review_api_v154.py`: `POST /api/pg-stage/v154/orders/{order_id}/delivery-review`. Explicit non-production opt-in only, off by default. Requires valid restricted PG session, company administrator, exact HTTPS Origin allowlist and CSRF token, known company+order, independent issuer key configuration and signed independent dispatch/receipt evidence. Only produces `PENDING_HUMAN_REVIEW`; physical-delivery, invoice and payment flags remain FALSE. Header `Cache-Control: no-store`. Proof payload constrained to 16 KiB (after parsing); no arbitrary issuer success claims.
2. **Actually wired to the existing PG-only app factory** in `scripts/jw_v104_standalone.py`, behind explicit optional registration; no production `app.main` routes changed. Missing/mismatched keys, disabled stage conditions and invalid startup mode fail closed.
3. **Transaction-bound audit** added to `app/pg_delivery_review_reservation_v151.py`: after inserting receipt, two nonces and verified source lines, append `jw_dev.audit_logs` entry bound to verified company+admin actor with source/evidence SHA only. Any audit failure bubbles up so the existing PG connection transaction cannot commit partial receipt.
4. Regression tests: `tests/test_pg_delivery_review_api_v154.py` exercises FastAPI TestClient origin/CSRF, admin, invalid order, malformed/oversize payload, key independence, missing DB, conflict and disabled-by-default cases. `tests/test_pg_delivery_review_reservation_v151.py` checks audit append, sensitive payload exclusion and error propagation. New `scripts/review/v154_signed_review_audit_rollback.sql` for actual DB.

## Execution evidence

- **Exact GitHub blob match on two new/changed executable modules** in isolated Python 3.13 container:
  - `app/pg_delivery_review_api_v154.py`: Git blob `49a0ead852548314e38df81367d47ce82396307a`.
  - `app/pg_delivery_review_reservation_v151.py`: Git blob `c1de3ed17ccb0b2a3668a4aa9cee1c5ca9e01be7`.
- During verification found an actual source defect: initial remote issuer-key length validation contained literal `\n` rather than a newline. Corrected and reconciled exact remote blob. Local FastAPI test first failed because a test double lacked the positional cursor argument; corrected both the local fixture and the remote regression test. **Not a product-code logic bug.**
- **Locally executed**, with actual FastAPI TestClient but mocked PostgreSQL cursor/issuer keys, 11/11 V15.4 route test cases PASS; 25/25 targeted route and V15.1 audited-writer tests PASS, combined two-module statement coverage **94%** (134 stmts, 8 not hit). Broader isolated local collection **133/133 PASS, 0 FAIL, 0 SKIP**, fatal ResourceWarning mode, compileall PASS. NOTE: some older local files are not exact-GitHub-HEAD; 133 PASS does **NOT** prove entire PR #67/full repo passed CI. Do not misstate.
- **Actual DEV Supabase PostgreSQL 17.11** executed exact fetched V15.2+V15.3 and V15.4 chained synthetic SQL under one BEGIN/ROLLBACK. Initially negative audit test expected permission/FK but existing `jw_dev.guard_reference_integrity_v81()` raised CHECK on cross-actor/tenant: test assertion updated to accept the legitimate denial; rerun returned **`PASS_V154_REAL_PG_ROLE_TENANT_AUDIT_ATOMIC_ROLLBACK`**. Restricted A admin audit INSERT succeeded, foreign tenant/actor INSERTs denied, no persistent fixtures or schema objects survived rollback. This is a DB-level test, **not** the live FastAPI-to-remote PostgreSQL HTTP request.
- An earlier actual DB V15.3 same-company member read/write denial, cross-tenant denial and unknown-session denial also PASS, preserved from parent.

## Important security/release boundaries

- The real DEV private ledger is **NOT INSTALLED** permanently. Thus the new opt-in API cannot persist a live HTTP request yet; startup defaults disabled. No externally verified dispatch/receipt signing keys are connected or approved and the app cannot certify independent physical delivery solely from a config acknowledgement. Neither actual client certificate/HTTPS source nor official business registry and email issuer checks are present.
- Current Render stage still uses **older deployed SHA**; no new stage deployment was made. Browser/Playwright full product E2E and UX/a11y for newest version NOT RUN. No actual two-process concurrent physical-delivery API test, nor exact-HEAD full J1–J6 GitHub Actions workflow. Fresh GitHub CI on this HEAD should remain NOT RUN until checked, regardless of previous isolated tests.
- The user's approval to execute tests does not override requirement for observed PASS, external issuer credentials, data governance, or protected main/production release gates.

## Evidence-based 5-Gate result

| Gate | V15.4 limited scope | Full JARVIS-WORKS |
|---|---|---|
| G1 Code/environment | Exact two executable module blob match; syntax compileall PASS; local scoped tests PASS | PARTIAL — full private repo exact-HEAD J1–J6 and build NOT RUN |
| G2 Functional accuracy | New isolated HTTP route correct mock session/CSRF/Origin/admin paths; actual PG role-audit PASS | PARTIAL — no actual third-party proof/real persistent business onboarding or delivery E2E |
| G3 Stability/regression | Local 133 PASS, proof replay/status guards, actual PG rollback; mandatory audit in same transaction | PARTIAL — live multiwriter physical-delivery API race and full regression NOT RUN |
| G4 UI/UX | HTTP route via TestClient only, no new UI | NOT RUN — actual latest hosted browser E2E/accessibility |
| G5 Security/operations | Existing tenant RLS, admin gate, cross-tenant audit denial PASS in real PG | PARTIAL — no external signed issuer/independent audit/full deployment recovery |

**Overall product release acceptance is PARTIAL/BLOCKED, not full PASS.** Next necessary operations are formally authorized isolated DEV persistent migration+restricted privileges, actual official issuer registration, protected stage deploy and same-SHA PG/browser J1–J6 end-to-end checks, independent signoff.

### Defects & preventive rules

1. After modifying remote source, verify exact Git blob and run actual Python parser: escaped `\n` text can destroy syntax.
2. Test doubles must preserve positional cursor signatures; direct HTTP TestClient catches mismatch.
3. Existing PostgreSQL integrity trigger may return SQLSTATE 23514 *before* grants or FK: negative tests must allow exactly documented deny outcomes.
4. A fully mocked unit suite cannot satisfy live external integration or product-wide Gate 4; never convert PARTIAL to PASS by changing report criteria.
