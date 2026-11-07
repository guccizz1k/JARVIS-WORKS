# JARVIS-WORKS V22.3 — actual development DB A/B post-P0 application and security regression

Date: 2026-11-07 KST. **Environment:** Supabase development project `jarvis-works-dev` (not production business data). Review-only branch `fix/jw-v223-terms-public-acl-20261107`. No main merge, deployment, Render change, or production-DB modification.

## P0 prerequisites
- Real encrypted source `jw_dev` PostgreSQL 17.11 backup and independent disposable PG17 restoration: **PASS as displayed in user's Codespaces transcript**. 62/62 tables, 22/22 engine transition rows, four cipher/restore negative tests PASS. One source/restored historical `review_signup_requests_v151_company_name_check` deparser difference was accepted **only** after pinned semantic equivalence, with old FAIL and v2 PASS reports retained separately.
- This P0 proof is **pre-A/B**. **No new post-A/B encrypted backup/independent restore has been performed.** Never equate the two.
- Live preflight before application: 62 `jw_dev` tables, 61 FORCE RLS, 22 transition rows, 0 quotes; dedicated `jw_backup_ro` readable on 62/62, no write. Source SQL candidates pinned on Track B `f6994a256dec7314804ad8e9a572852b8b6b8de1`; on PG17 synthetic CI terms 60/60, preflight 19/19 and C 16/16 (source branch).

## Actual Supabase development migrations (sequential)
1. `20261107134048 jw_v223_a_quote_two_person_constraint_20261107` — reviewed **A** CHECK on `jw_dev.cinema_pg_quotes` (both submitter/approver required, must be different) initially NOT VALID; verified 0 pre-existing quotes and original `supabase_admin` ADMIN-only owner membership preserved.
2. `20261107134136 jw_v223_b_order_invoice_payment_side_tables_20261107` — reviewed **B** side tables for order terms, invoice terms and payment notes with 3 SECURITY DEFINER functions, 3 append-only triggers, 6 org-filtering RLS policies.
3. **A SECURITY DEFECT DETECTED AFTER B APPLIED**: the original proposal ran its function `REVOKE ... FROM PUBLIC` as non-superuser `postgres` *after* `RESET ROLE`, so all 3 new functions retained default `PUBLIC EXECUTE`. A synthetic superuser-only gate missed this. No rows were present in those tables. This is a **historical failed security check**, not a PASS.
4. `20261107134332 jw_v223_b_public_execute_acl_repair_20261107` — fail-closed transactional repair: temporarily `SET LOCAL ROLE jw_cinema_owner`, revoke PUBLIC on exactly 3 new functions, explicitly grant execute to `jw_cinema_writer`, restore original admin membership and assert PUBLIC/anon/authenticated denial before commit. Live query after repair: **3/3** functions PUBLIC=false, anon=false, authenticated=false, writer=true.
5. `20261107134439 jw_v223_c_backup_select_new_side_tables_20261107` — 3 new tables granted *SELECT only* to existing `jw_backup_ro` as table owner, reversible temporary membership; assert 65/65 readable and 0 writable, preserve original membership.
6. `20261107134539 jw_v223_a_validate_quote_two_person_20261107` — validated original A CHECK (0 existing quotes); admin membership unchanged.

## Post-application read-only verification (live PostgreSQL 17.11)
| Measured | Result |
|---|---|
| `jw_dev` tables | **65** |
| FORCE RLS | **64** (3 new FORCE RLS) |
| New B tables and ownership | **3/3** owner `jw_cinema_owner` |
| New B SECURITY DEFINER functions with `search_path=pg_catalog` and no PUBLIC/anon/authenticated execute | **3/3** |
| B policies / append-only triggers | **6 policies / 3 triggers** |
| Tenant isolation of B RLS | `org_id = jw_dev.current_org_from_session()` for owner and writer; writer SELECT-only |
| A two-person CHECK, `convalidated=true` | **1/1** |
| Existing engine transition seed rows | **22** (unchanged count) |
| Quotes / original trade rows / B rows | **0 / 0 / 0** |
| Backup role readable `jw_dev` tables | **65/65**, writable **0** |
| `postgres` original `jw_cinema_owner` ADMIN-only membership | **1 preserved**, no temporary edge |
| Security advisor | 9 pre-existing RLS-without-policy INFO (deny-all protected); no new high severity findings |
| Performance advisor | 49 pre-existing unindexed-FK INFO; no speculative changes on empty business DB |

## Root-cause correction in GitHub
- Separate review branch `fix/jw-v223-terms-public-acl-20261107` (historical Claude Track B and `main` preserved).
- File `scripts/review/cinema_pg_v223_terms_proposal.sql`: execute the 3 function `REVOKE` operations **while still `SET LOCAL ROLE jw_cinema_owner`**, not after resetting to non-superuser; add a transaction-end authorization guard that raises an exception and rolls back if any PUBLIC/anon/authenticated EXECUTE remains.
- New gate `scripts/ci_cinema_pg_v223_b_acl_non_super_gate.py` reproduces Supabase's `NOSUPERUSER CREATEROLE BYPASSRLS` administrator and ADMIN-only owner membership. Intentionally mutates the SQL back to the bad ordering and proves **entire transaction rolls back**. Correct SQL applies successfully; public EXECUTE absent, FORCE RLS present, membership restored.
- CI workflow `.github/workflows/jw-cinema-pg-v223-preflight-gate.yml`: PG17 222/222 engine, 19/19 preflight, 16/16 C and **7/7 non-superuser B-ACL regression**. Real GitHub Actions [run #42378773239](https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/42378773239) completed SUCCESS. Synthetic-only CI is distinct from live read-only privilege evidence.

## 5-Gate / outstanding release blockers
1. Code, environment, SQL syntax: **PASS** for modified Track B candidate; actual DB migrations accepted.
2. Scoped functional behavior and authorization: **PASS** for installed A constraint, B structures, ACL/RLS assertions and synthetic PG17 gate. **Real HTTP customer-flow E2E: NOT RUN**.
3. Data integrity and regression: **PARTIAL**. Pre-A/B independent restoration PASS, 22 seed rows and admin role preserved after application, synthetic negative and rollback tests PASS. **New post-A/B encrypted backup → independent PG17 restore: NOT RUN**; real data-row fingerprint comparison with original separately held owner snapshot: NOT VERIFIED.
4. UI/UX: **NOT RUN** (no UI changes).
5. Operations/release: **BLOCKED** by post-migration P0 backup/restore, real HTTPS E2E and unrelated release gates. No production release.

**Important:** The dedicated `jw_backup_ro` has BYPASSRLS (read all business rows) and an existing expiration at 2026-11-09 00:00 KST. Do not reset a managed `postgres` password, weaken TLS/ACL checks, expose backup keys, or commit backup/credentials. The pre-A/B encrypted backup is preserved; it does not cover the newly created tables/functions.

**Safety:** The 5 development migrations above were intentionally applied only to the previously approved development database. No changes to GitHub `main`, production DB, Render, draft PR #139, or preexisting business rows.
