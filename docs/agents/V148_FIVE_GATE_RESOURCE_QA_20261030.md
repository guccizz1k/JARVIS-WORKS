# V14.8 — five-gate evidence-driven quality repair (2026-10-30 KST)

## Fixed defect, without release-gate relaxation

- Parent: protected Draft PR #60 `f78ad0ee081ffcc59cf6eea786957f5c18c629be`. Separate review branch only; all original test and production boundaries preserved.
- Defect reproduced: Python `sqlite3.Connection` is a transaction context manager but does NOT close on context exit. `pytest --cov` triggered multiple `ResourceWarning: unclosed database` during threaded V14.7 review reservation tests although 107 passed.
- Root-cause correction: `scripts/review/v147_enrollment_atomic_model.py` now explicitly closes each connection with `contextlib.closing` on success, rollback, duplicate rejection and failure; corresponding test database readers also explicitly close.
- Added targeted regression `test_sqlite_connections_closed_even_on_duplicate_failure` using tracked Connection subclass, proving all 3 database connections close after schema create, successful reservation and duplicate collision.

## Actual isolated-local verification

Test environment: Linux / Python 3.13 / pytest 9, only a limited mirrored review module set; no privileged DB credentials.

- `PYTHONWARNINGS=error::ResourceWarning python -m pytest -q tests -W error::ResourceWarning --cov=app.pg_signup_review_gate_v146 --cov=app.pg_delivery_evidence_gate_v147 --cov=app.pg_invoice_preview_v145 --cov=scripts.review.v147_enrollment_atomic_model --cov-report=term`
- **108 PASSED, 0 FAILED, 0 SKIPPED**; the named 4 source modules scored **95% combined statement coverage** (273 statements, 15 missing). Coverage does **not** represent the entire WORKS product.
- Local `python -m compileall -q app scripts tests`: PASS.
- Five additional independent invocations of the actual 10-test SQLite contention module under `-W error::ResourceWarning`: each 10 PASS (one earlier 20-iteration stress command hit execution timeout; not counted as PASS). This is a local SQLite reference only, NOT a real PostgreSQL concurrency signoff.

## Connected evidence: read-only DEV database and Render

- Actual Supabase DEV PG17 checked: 35 FORCE RLS tables, 40 policies, 2 separated NOINHERIT/NOBYPASSRLS stage logins, no V147 persistence table. `jw_dev` orgs/users/orders/invoices/payments each 0. No DDL, grants, deletes, customer fixtures or schema mutation.
- Supabase security advisor: seven INFO-level default-deny/no-RLS-policy internal tables. Do NOT add broad grants to clear informational warnings; independently review role privileges.
- Latest known Render isolated free HTTPS deployment stays on `92afea924d14b05e84a107b91db58250cc00f885`, **not** V14.8. Local container DNS/network request to the public staging hostname failed; hosted application/browser E2E has NOT been run for this SHA.
- Latest exact-head GitHub Actions full J1–J6 and independent signed Stage 1–8 receipts **NOT RUN**. Do not equate a green 108-test result or review CI with official stage acceptance.

## 5-Gate scoped versus product status

| Gate | V14.8 local change scope | Full product release gate |
|---|---|---|
| 1. Source/runtime | PASS: Python compilation, import and mirrored module tests | PARTIAL: full original CI/build and exact SHA not rerun |
| 2. Functional correctness | PASS: 108 local tests incl. closure success/error and isolated financial proof logic | PARTIAL: real signup/delivery/payment E2E not implemented/tested |
| 3. Stability / regression | PASS: no resource warnings under fatal warning setting, 5 independent contention test reruns | PARTIAL: real PG17 multi-writer and complete J1–J6 not independently checked |
| 4. UI/UX | N/A to this pure Python/SQLite reference fix (no UI changed) | NOT RUN: desktop browser, visual/a11y and product flow |
| 5. Operations/security | PASS for preserving read-only DEV catalog, existing RLS/roles and no deployment | PARTIAL/BLOCKED: no new hosted browser E2E or independent external review, no production launch approval |

**Do not promote the full five-gate release summary to PASS.** Core unresolved dependencies: actual business-owner/email verification issuers; atomic real PostgreSQL approval ledger and user enrollment; immutable verified delivery ledger with actor provenance; public/staged desktop E2E; exact-head full GitHub Actions J1–J6 proof, independent signed approval and owner launch signoff.

No main merge, no production/staging redeploy, no user-data transfer, no service-role keys, no paid actions.
