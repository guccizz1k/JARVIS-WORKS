# V15.3 — real restricted PostgreSQL A/B and administrator role proof

2026-10-30 KST. Protected parent Draft PR #65 HEAD `3118e05d37abcb2b77730b30a0de09edacf7490b`. No release merge, production deployment or persistent database changes.

## IMPLEMENTED (candidate only)

- `scripts/review/v153_restricted_review_writer_candidate.sql`: **six PostgreSQL policies** on the three private delivery-review tables, restricted to `jw_app_dev`. SELECT requires session org AND verified administrator; INSERT requires current verified admin, tenant-scoped order and fulfilled/acknowledged source. Signed receipt nonce and line reads/inserts depend on an RLS-protected parent receipt. Only SELECT+INSERT grants, no UPDATE/DELETE and **no signup ledger permission**. Existing V15.2 append-only triggers continue denying all after-insert modification.
- `scripts/review/v153_actual_pg_trade_rls_abc_rollback.sql`: synthetic companies A and B, admin A/B, member A, sessions, source orders and line items, all within explicit rollback-only TEST transaction.
- `tests/test_v153_restricted_role_rls_contract.py`: exact-checkout Python regression contract for fail-closed policies, role-scoped reads/inserts, and negative session tests. **Not yet executed under exact-HEAD repository pytest/CI**; statically checked actual GitHub blobs and SQL patterns in connector.

## ACTUALLY EXECUTED in connected Supabase DEV PostgreSQL 17.11

Constructed test from exact fetched GitHub SQL source: V15.2 five private review tables + original review constraint tests + V15.3 restrictive RLS policy candidate + synthetic A/B/member session test. Confirmed no COMMIT, no real invoice/payment writes, five new tables only inside transaction. Preexisting DEV protected business table rows were zero.

Initial PG attempt FAIL due **duplicate synthetic evidence SHA256 and nonces** across earlier fixture; corrected unique synthetic values. Re-run returned **`PASS_V153_REAL_PG_RESTRICTED_AB_SESSION_ROLLBACK`**.

Additional security counterexample: existing candidate allowed tenant non-admins to SELECT signed evidence. Fixed SELECT policy to require `stage_identity_v84().actor_role = 'admin'`. First negative test failed because synthetic role `staff` violated real DB `users_role_check` (only `admin`, `member`). Corrected fixtures to `member` using actual database catalog, reran actual PG17 test and obtained **`PASS_V153_PG17_ROLE_AB_MEMBER_NEGATIVE_ROLLBACK`**.

Actual scoped protections tested: A admin can write/read own review; B admin cannot read A records or write A receipts, but can write own; invalid session sees none and cannot insert; member in same company A **cannot read or insert** sensitive signed evidence; existing nonce/item INSERT and read honor parent RLS; source-line check and immutable evidence triggers remain active. All SQL executed inside BEGIN/ROLLBACK, no permanent ledger, role policy or synthetic data left.

This proves restricted-role PostgreSQL RLS and controlled transaction path **for synthetic actors**. It does **NOT** prove external independent issuer verification, real physical delivery, production credentials, billing/posting, full app API E2E, or actual two-thread simultaneous transactions on the same order. These remain BLOCKED/NOT RUN.

## Five-Gate scope & release status

| Gate | Evidence obtained | Full product acceptance |
|---|---|---|
| G1 Code/environment | 120 local focused tests PASS incl. exact Git blob V15.1 internal writer (55 statements / 95% coverage), V15.3 three-file remote static contract PASS | PARTIAL: full private repo exact-HEAD J1–J6/build CI absent |
| G2 Functional correctness | Actual PG17 A/B admin RLS, same-tenant member denial, no-session denial, delivery-review insertion and FK/source guard PASS | PARTIAL: official business/email issuer, genuine delivery attestation, actual service request not integrated |
| G3 Stability/regression | V15.2 immutable/rollback PASS, V15.3 role/tenant negative PASS; test collision and role mismatch corrected | PARTIAL: concurrent application transaction races, complete regression and recovery NOT RUN |
| G4 UI/UX | No UI changes | NOT RUN: exact-version hosted browser E2E/a11y |
| G5 Operations/security | FORCE RLS, no public grants, no update/delete; actual PG restricted role scope validated and transaction rolled back | PARTIAL: independent security audit, launch authorization, credentials and hosted integration NOT RUN |

**The product is not at global five-gate PASS.** Test-only candidate SQL must not be installed or broadly granted in production absent verified official issuer provenance, isolated signed receipts, and independent deployment/permission approval. No main merge, no production/staging deploy, no permanent Supabase DDL/grants or data transfer; no paid CI. The original GitHub Draft #65 is unchanged.

## Recurrent-error prevention

1. Before constructing chained synthetic SQL fixtures check global UNIQUE fields and proof nonces across *all* earlier fixtures; use distinct deterministic data namespaces.
2. Derive enum/check constraint values from live PostgreSQL catalog; do not assume employee roles (`jw_dev.users.role` allows `admin` and `member`).
3. Verify same-organization lower-privilege reader, not just cross-org denial; tenant isolation alone does not imply minimum authorization.
4. Final verdict must use current HEAD; an independently tested local fixture is not a full exact-head GitHub CI run.
