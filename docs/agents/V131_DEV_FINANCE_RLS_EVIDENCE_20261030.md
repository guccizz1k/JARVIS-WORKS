# V13.1 real Supabase development DB finance RLS — review only

Date: 2026-10-30 KST
Base JARVIS-WORKS review SHA: `f321358a4515b3396bced26489f5edef37f6d199`.
Target: *existing* Supabase `jarvis-works-dev` Postgres 17, `jw_dev`. No production DB access.
SQL: `scripts/review/v131_real_abc_finance_rollback.sql`; offline source-integrity tests: `tests/test_v131_finance_review_contract.py`.

## Evidence actually EXECUTED
- Executed a single `BEGIN … ROLLBACK` transaction in the actual Supabase developer PostgreSQL 17 with synthetic tenant A/B/C sessions and dataset; exact result **PASS_REAL_V131_ABC_FINANCE_RLS_PAYMENT_REVERSAL_ROLLBACK**.
- Preserved verified A/B/C customer, quote, order, messenger SELECT isolation from V9.9. Explicit positive and negative seeded rows, no empty-table-only RLS promotion.
- Verified invoice creation is denied before fulfilled order (SQLSTATE 23514), then staged order `received→processing→fulfilled` and linked invoice line items.
- Verified true JARVIS `record_payment_v83` SECURITY DEFINER business RPC: tenant A payment of 1,000 KRW, same idempotency key replay returns same ID and creates one payment, overpayment denied (23514), A calling B invoice denied (42501). Tenant B proper 9,900 KRW payment; C and unknown sessions denied; A and B payment rows isolated.
- Verified `financial_state_v83` internal account state calculation function is **not** directly executable by `jw_app_dev`; payment reversal (admin, legitimate invoice) succeeds, reversed reference reuse is denied (23514); final active A payment of 2,200 KRW reconciles.
- Initial predecessor SQL had exact source checks and `ROLLBACK`; latest fixture adds stricter finance guards and preserved source checks.
- **Independent post-transaction query**: `organizations`, `users`, `sessions`, `customers`, `quotes`, `quote_items`, `orders`, `order_items`, `invoices`, `invoice_items`, `payments`, `audit_logs`, and `messenger_messages` **0** each, policies **40**, FORCE RLS **35**.
- SQL source file was executed against real dev DB *before* it was committed as a separate Draft review candidate. A previous independent synthetic 2-tenant finance trial also passed. Other project files and existing DB state remain unchanged.
- Ten structural/source contract conditions for the committed SQL source inspected against GitHub and passed. New Python tests added to repo, **not yet executed in GitHub Actions on the final SHA**, so do not claim same-SHA CI.

## Not proven — must remain BLOCKED/PARTIAL
- Authenticated **external, persistently deployed** HTTPS user sessions with real Supabase DB, not merely role-scoped SQL or disposable-local HTTPS tests.
- Separate delivery-note/document production pipeline; this test covers `orders.status='fulfilled'` as delivery/fulfillment gate only, not source-linked delivery document.
- Live OCR original-document compare, attachments, full authorized 35-table positive controls, true invoice/payment HTTP API endpoints, realistic high-volume load, independent security attestation.
- Do not enable broad policies, relax TLS, add production secrets, auto-run privileged synthetic fixtures in CI, merge `main`, migrate customer data, or deploy.
- CORE-first shared private workflow remains independently BLOCKED pending its own repository/caller access and original full verification.

## Incident and recurrence ledger
1. Metadata SQL join was ambiguous (`SQLSTATE 42702`) during schema inspection. Fixed by qualifying `c.constraint_name`; no schema/data change.
2. ACL inspector incorrectly used pseudo-principal `PUBLIC` in `has_function_privilege` (`SQLSTATE 42704`). Fixed via `pg_proc.proacl` plus `has_function_privilege('jw_app_dev',p.oid,'EXECUTE')`; no schema/data change.
3. Unit tests or zero-row observation alone do not prove real tenant isolation. Insist on A/B/C positive and cross-tenant negative controls and an independent zero-residual query.
4. A transaction-scoped SQL PASS does not certify production HTTP, full document lifecycle or same-SHA CI. Preserve the statuses as NOT RUN/BLOCKED, never silently upgrade.

## Completion verdict
**PASS**: the explicitly scoped dev DB finance/RLS idempotency/reversal/rollback observations.
**NOT RUN**: complete J1–J6 exact new SHA CI, external HTTPS full business E2E and true production deployment.
**OVERALL_RELEASE**: **FAIL_NOT_APPROVED**.
