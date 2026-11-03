# V14.9 — verified DEV PostgreSQL rollback + source provenance gate

Date: 2026-10-30 KST. Review-only parent: Draft PR #61 exactly `bc77323c7b93fc004fa1f23ccfdc063db3355e14`. No merge/deploy, no paid CI, no permanent schema mutation, no customer-data migration.

## Actual connected PostgreSQL tests (not mocked)

1. PRECHECK: `jw_dev` organizations, users, messenger messages, audit logs, invoices, payments all zero. Reviewed original `scripts/review/v131_real_abc_finance_rollback.sql` for BEGIN, empty-state guards, ROLLBACK, residual fixture check, no COMMIT/DDL/GRANT.
2. EXECUTED in active `jarvis-works-dev` Supabase PostgreSQL **17.11**. Returned **PASS_REAL_V131_ABC_FINANCE_RLS_PAYMENT_REVERSAL_ROLLBACK**. This is the existing product PostgreSQL A/B/C synthetic finance and RLS rollback regression, NOT a test of the V14.7 proof module's external authorities.
3. POSTCHECK: organizations, users, sessions, customers, quotes, orders, invoices, payments, audit logs, messenger messages all zero; 40 RLS policies remain.
4. EXECUTED the **actual checked-in** `scripts/review/v149_live_pg_role_negative_readonly.sql`: BEGIN READ ONLY, SET LOCAL ROLE jw_app_dev, server-side DO verifies empty tenant context / zero visible tenant data, RESET ROLE and ROLLBACK, plus PostgreSQL catalog checks. Verdict **PASS_V149_READONLY_NO_SESSION_ROLE_NEGATIVE_AND_CATALOG**. 35 FORCE RLS tables; 40 policies; two restricted separated staging logins; zero SECURITY DEFINER routines executable by PUBLIC (22 checked in catalog).
5. Two independent PostgreSQL sessions (different backend PIDs) each entered a read-only transaction, used the same transaction-scoped advisory lock and exited without error. The result demonstrates a basic native advisory-lock/parallel session path only. **It does not prove application-specific multi-writer financial idempotence or real PostgreSQL signup reservation races.**

## Root-cause evidence integrity issue

Previous local `/mnt/data/jw_v147_review` was a manually assembled limited mirror, **not** a byte-for-byte checkout of the protected GitHub HEAD. Compared nine files by local `git hash-object` against exact GitHub connector blob SHA-1: **3 match, 6 differ**. Earlier 108/108 local PASS is **only local-mirror proof**, not evidence that PR #61 exact HEAD passed those Python tests. Preserve the local result while correcting its provenance. Do not count it as exact-SHA GitHub regression.

**Change implemented:** `scripts/review/v149_git_source_fidelity.json` pins nine exact GitHub blob hashes read from parent SHA; `tests/test_v149_source_integrity_and_pg_negative.py` checks exact Git blob hash, missing paths and safe read-only DB test SQL. A stale mirror now fails closed; an exact checkout can run the source fidelity check. No independent signed provenance or full CI success is claimed. Source manifest hash checks were verified against connected GitHub for all nine pinned files; **the new test itself is not reported as pytest PASS on exact GitHub checkout**.

## Five-Gate scope vs full product

| Gate | Evidence | Outcome |
|---|---|---|
| G1 code / environment | GitHub exact source manifest and remote path validation; original mirrored Python compile and 108 local tests | PARTIAL — no exact-HEAD full build/CI |
| G2 business function | Actual PG17 A/B/C role isolation + finance/payment/reversal rollback PASS; unchanged live DB | PARTIAL — new actual signup/delivery proof API unintegrated |
| G3 regression / stability | Real PG role-negative read-only proof PASS; two distinct PG advisory lock sessions; 108 local mirrored tests PASS; hash drift detected | PARTIAL — exact-HEAD J1–J6 and application multi-writer real PG tests NOT RUN |
| G4 UI / UX | New code has no UI; HTTPS service still runs old SHA, network browser inaccessible from local sandbox | NOT RUN for whole product |
| G5 security / deployment | Real catalog shows 35 forced RLS, 40 policies, 2 split roles, 0 public-executable security-definer functions; rollback left zero rows | PARTIAL — independent security review, signed acceptance, new SHA deployment NOT RUN |

**Release and 8-stage overall remains BLOCKED/PARTIAL.** Do not mark the 5-Gate full product PASS. Supabase advisor INFO-only default-deny internal tables must not be broadened with grants without separate review. Latest Render HTTPS is still older commit `92afea924d14b05e84a107b91db58250cc00f885`; no new deploy was made.

Next immediate priority: obtain an exact private GitHub checkout in an approved nonpaid runner to execute all J1–J6 / browser Playwright and source-fidelity checks on the same SHA, then implement and validate real PG17 restricted-role account reservation and human-attested delivery ledger under approved dev staging only.
