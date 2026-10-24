# V9.0 reciprocal role-boundary hardening — 2026-10-24

Scope: development/review only. **No database DDL, no customer data, no deployment.**

## Actual root cause and failing-first reproduction

V8.9 `pg_auth_v85._auth_cursor` already rejects an auth-stage PostgreSQL login if it can `SET ROLE jw_app_dev`.
However V9.0 `pg_v90_integrated_entry._pg_validated_cursor` did not reject the reciprocal misconfiguration: a **business login also allowed to `SET ROLE jw_auth_stage_v85`**.

- Old adapter + new executable regression: **HTTP 200 instead of expected 503**, 1 FAIL.
- Updated adapter checks the business login's `pg_has_role(session_user,'jw_auth_stage_v85','SET')` **before** `SET LOCAL ROLE jw_app_dev`. If unexpected role adoption is possible, it fails closed with HTTP 503.
- Restored V8.9 + V9.0 isolated FastAPI integration tests: **18 PASS, 0 FAIL**.
- Separate GitHub-contained code-boundary checks: **4 PASS**.
- PR integration module and static test file hashes match the locally executed sources. Production `app/main.py` unchanged.

## Release-gate false-positive repair

The earlier catalog release gate checked only a safe business gateway login. It would pass with a single login able to adopt both trading and auth roles, or with no auth gateway login, if other synthetic evidence was set to PASS.

- Three newly added regression tests: **3 FAIL before repair**, then **3 PASS after repair**.
- Current gate requires auth-stage role `NOLOGIN`, a dedicated nonprivileged auth login, and zero dual-capability login accounts.
- Nine catalog fixture tests plus four source boundary checks: **13 PASS**.
- Actual dev PostgreSQL read-only catalog: business gateway logins **0**; auth gateway logins **0**; both role targets `NOLOGIN`; two V9 sender/editor RPCs still **lack advisory transaction locks**. Gate exits **2, BLOCKED**.
- The two Supabase SQL tool calls attempted to overlap independent PostgreSQL backends for advisory contention; both reported successful lock acquisition. Backend PIDs differed, but **actual transaction overlap was not established**, so the result is **INCONCLUSIVE**, NOT PASS.
- No real credentials, no SSL-vetted nonprivileged PostgreSQL login, no real A/B/C RLS cross-tenant E2E yet.

## Acceptance and deployment constraints

1. Provision **two distinct non-superuser, NO-BYPASSRLS, NO-CREATEROLE LOGIN** credentials, with business membership limited to `jw_app_dev` and auth membership limited to `jw_auth_stage_v85`, managed in an approved secrets environment. Do not reuse the postgres/supabase service role.
2. Execute the existing `pg_advisory_probe_v90.py` from **two persistent independent TLS-verified connections** under the business role and verify transaction commit/rollback, wait and isolation.
3. Apply `006_commit_order_cursor_guard_candidate.sql` ONLY after approval and Postgres syntax/concurrency testing; it remains **UNAPPLIED**.
4. Reconcile the recovered V8.9 authoritative Git history with remote main in a dedicated review; do not merge this candidate PR over stale main.
5. Perform real A/B/C tenant, attachment, login/logout, deployed browser and recovery E2E before release.

**Final status: newly reproduced security check corrected and locally verified; real-DB release BLOCKED.**
