# V15.1 — Private signup and physical-delivery review ledgers (2026-10-30 KST)

**Protected source:** Draft PR #63 HEAD `9034f0ad0435313e62e83147f45d1fbbaad1062c`. New review branch only. No main merge, no production/Render deploy, no persistent DEV schema changes, no role/secret/password modifications, no customer data transfer, no paid CI/API.

## Implemented source code

- `scripts/review/v151_private_review_ledger_candidate.sql`: 5 **candidate** persistent-review tables (signup requests + one-time issuer-nonce evidence; delivery receipt + unique issuer-nonce evidence + source-linked order items). Entire candidate is **DENY BY DEFAULT**: every table ENABLE+FORCE RLS, zero policies, revoke all privileges for PUBLIC, anon, authenticated, existing business/auth roles. Only `PENDING_HUMAN_REVIEW` state is permitted; physical-delivery, invoice and payment posted flags are constrained FALSE.
- Two new **SECURITY INVOKER** non-public triggers validate `order_id/org_id` against the actual acknowledged, fulfilled source order and delivery `source_item_id/order_id/position/quantity/unit_price` against original order items. This closes an earlier model weakness where separate FKs did not guarantee same-order evidence. Zero SECURITY DEFINER additions, PUBLIC EXECUTE revoked.
- `app/pg_delivery_review_reservation_v151.py`: non-public internal transaction helper requiring a verified PG actor/org, admin role, current PG identity recheck, order `FOR UPDATE` lock, no existing invoice, exact regenerated V14.5 order preview, V14.7 signed independent evidence verification, nonce replay check and pending-review-only inserts in the **caller's** transaction. No route registration, no unrestricted DSN, no COMMIT and absolutely no invoice/payment/customer INSERT.
- Two Python test files added: `tests/test_pg_delivery_review_reservation_v151.py`, `tests/test_v151_private_review_ledger_contract.py`. They exercise negative session/role/tenant/duplicate replay and static RLS/permission invariants. **They have NOT yet been executed as Python tests on an exact GitHub checkout**; GitHub connector source-level checks passed. Do not count them as pytest PASS.

## Actual DEV PostgreSQL 17.11 execution

1. Before execution: DEV `postgres`, business data empty. SQL candidate fetched from the actual private branch; assembled inside explicit `BEGIN`, strict lock and statement timeouts, fixed empty-DEV guard; completed with `ROLLBACK`. No permanent migrations were applied.
2. First actual PG verdict: `PASS_V151_PG17_CANDIDATE_DDL_DEFAULT_DENY_ROLLBACK`. Confirmed exactly five FORCE RLS private tables, no policies, no permitted app/anon grants, restricted business role unable to read private ledger.
3. Added synthetic real-order+line and enrollment and receipt assertion script. Actual PostgreSQL verdict: `PASS_V151_REAL_PG_LEDGER_CONSTRAINTS_AND_ROLLBACK`. Valid fixtures entered; invalid duplicate business/email, replayed nonce, unauthorized status elevation, spoofed paid/delivered flag and duplicate order line all rejected.
4. Identified source order/line cross-tenant integrity gap and added source guards (invoker-only) to the candidate. First revised test exposed an **outdated assertion expecting only UNIQUE violation**, while the new protective BEFORE INSERT trigger now correctly rejected first with CHECK violation. Fixed test to accept either safe-denial SQLSTATE; reran the actual connection: `PASS_V151_REAL_PG_TRIGGER_SCOPE_AND_ROLLBACK`. Tests explicitly reject wrong source org, position, quantity, unit price, public/definer trigger exposure.
5. Rollback result verified no candidate table, function or synthetic source rows remained. Original 35 FORCE RLS business tables and 40 policies were preserved. Actual permanent business account, physical delivery and payment pipelines unchanged.

## Security and deliberate operating blocks

**NO durable ledger is installed yet.** The candidate can be promoted only after formal migration process, source provenance/approval, issuer authority and independent role/tenant acceptance. Current table permissions intentionally deny writer access, so the internal Python writer **cannot successfully persist a live receipt in this state**. This is the correct fail-closed behavior, not a completed live feature.

Actual corporate registration still needs trusted government/registration checking + separate email ownership proof + unique official owner binding, restricted auth role, non-bypassable atomic stored transaction, human final review and secure password reset. Actual physical delivery still needs independent dispatch/recipient issuer keys, physical evidence, actor signatures, audited immutable history, and approved invoice posting flow. Source-bound original items are necessary but not sufficient. **No actual business activation, confirmed delivery, invoice or payment posting has been authorized.**

The protected source Python unit tests and current full repository exact-SHA J1–J6 GitHub CI, real multiwriter PG17 durability/concurrency, desktop Playwright accessibility and hosted HTTPS new-code end-to-end, independent signed acceptance receipt: **NOT RUN**. Overall product five-gate and eight-stage release acceptance remain **PARTIAL / BLOCKED**.

## Five Gates (no inflated PASS)

| Gate | Scope result | Full system |
|---|---|---|
| G1 Code/environment | GitHub source static invariants PASS; PG17 actual DDL dry-run PASS | PARTIAL: exact-SHA Python/full CI/build NOT RUN |
| G2 Functionality | Actual PG17 candidate constraints and source guard tests PASS | PARTIAL: user-facing enrollment/physical-delivery pipeline not wired |
| G3 Stability/regression | Explicit rollback + synthetic negative cases + revised test order PASS | PARTIAL: real independent multi-session writer race and J1–J6 NOT RUN |
| G4 UI/UX | No frontend changed | NOT RUN: browser E2E, a11y |
| G5 Operations/security | Actual permission deny, force RLS, invoker guard and no residual business data PASS for isolated candidate | PARTIAL: independent audit, official migration, deployment and issuer authority NOT RUN |

Next: reproduce *exact branch* Python tests in an approved nonpaid runner (not stale local mirror), then restricted-user PostgreSQL staged migration and concurrent requests on isolated synthetic fixtures, browser E2E and independent signoff before considering any activation.
