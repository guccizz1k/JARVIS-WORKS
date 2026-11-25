# V15.0 — Real PostgreSQL 17.11 ephemeral integrity and rollback gate

2026-10-30 KST. Parent Draft PR #62 exact HEAD: `bf4ffb941334477fff7e46382d609466a717a88b`. Separate Draft review only; protect J1–J6 and all existing behavior, stage and production, secrets, costs, customer data, schema, and release gates.

## Actual connected execution, not a simulation

- Executed GitHub-file exact source `scripts/review/v150_real_pg_temp_integrity_rollback.sql` on the connected `jarvis-works-dev` Supabase PostgreSQL 17.11. Preflight observed empty organizations/users/orders/invoices/payments/messages/audit and database `postgres`.
- Checked SQL text before execution: exactly four `CREATE TEMP TABLE` statements, all `ON COMMIT DROP`, one final `ROLLBACK`, **no COMMIT**, no permanent `jw_dev` inserts, no role/schema grants, no existing schema modification.
- Real PostgreSQL verdict: **`PASS_REAL_PG17_V150_TEMP_CONSTRAINTS_AND_ATOMIC_ROLLBACK`**.
- Actual temporary PostgreSQL native constraints rejected: reused normalized email, duplicated business number, reused nonce, partial enrollment transaction (subtransaction rollback), unauthorized APPROVED state, second delivery receipt for the same order across organizations, duplicate item ID, quantity divergence, same person dual attestation, reused dispatch/receipt nonce, dispatch/receipt amount mismatch, and partial delivery payload.
- After the full `ROLLBACK`, read-only database check: organizations, users, sessions, orders, invoices, payments, audit, messenger messages all **zero**; **35** FORCE RLS tables and **40** policies unchanged.
- Supabase security advisor still reports seven INFO-level no-policy/default-deny sensitive auth tables. Do not introduce policy/grant bypass just to eliminate informational advisories; [Supabase linter guidance](https://supabase.com/docs/guides/database/database-linter?lint=0008_rls_enabled_no_policy).
- `tests/test_v150_pg_temp_integrity_contract.py` added as a future exact-checkout regression. Connector static check on exact remote source confirmed 4 TEMP tables, 4 ON COMMIT DROP, 1 ROLLBACK, 0 COMMIT, 0 permanent INSERT, 12 fail-closed labels. **No claim the new Python test was executed on the exact remote checkout**.

## Scope boundaries and next actions

This is the **real DB engine** proving atomic subtransactions, UNIQUE/CHECK/FK integrity and rollback for a reference *temporary* schema. It is NOT a durable business enrollment implementation, restricted-role persistent writes, PostgreSQL application eight-worker concurrent signup, verified governmental registration, email ownership, authenticated dual human delivery attestation, real invoice posting, or payment. The application still needs an approved physical-delivery ledger and signed evidence-source integration.

There is no complete exact-head GitHub Actions J1–J6 workflow result for this new SHA; no hosted application/UI/Playwright execution of it; no independent release signoff. The Render hosted staging still deploys its old preview SHA, because no new deployment was requested or performed.

## Five Gates — evidence grounded

| Gate | Current narrow-scope result | Full product acceptance |
|---|---|---|
| G1 Code/environment | PASS: exact GitHub SQL source fetched and preflight static guard check | PARTIAL: whole repository exact-HEAD CI / build NOT RUN |
| G2 Functional accuracy | PASS: actual PG17 temp model rejects 12 invalid conditions | PARTIAL: real product account and shipment approval APIs not integrated |
| G3 Regression/stability | PASS: SQL subtransactions, rollback and postcheck no residues | PARTIAL: durable multi-session business transaction / J1–J6 not proven |
| G4 UI/UX | NOT APPLICABLE to DB-only probe | NOT RUN: desktop browser, accessibility and flows |
| G5 Operations/security | PASS: read-only catalog verification, no permanent business data or DDL, 35 RLS / 40 policies unchanged | PARTIAL / BLOCKED: independent auth/PG E2E and launch approval |

**Do not change overall five-gate or formal eight-stage release to PASS.** No main merge, no remote deployment, no real-data transfer, no paid CI/API, no unrestricted auth endpoint, no persistent schema mutation.
