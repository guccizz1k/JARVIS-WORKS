# J1–J6 V9.1 — nonprivileged PostgreSQL gateway verification fix

**Date:** 2026-10-24. **Scope:** Review-only PostgreSQL preflight correctness. `main`, default production runtime and Supabase schema are unchanged.

## Evidence-proven root cause and fix

Actual Supabase `jarvis-works-dev` PostgreSQL 17.11 catalog (read-only):
- 35 FORCE-RLS application tables, 40 policies; sender/edit RPCs both retain advisory transaction locking.
- Historical `jw_trade_login_v86`/`jw_auth_login_v86` accounts were `NOLOGIN`.
- Effective restricted `jw_trade_gateway_v90` and `jw_auth_gateway_v90` are two `LOGIN NOINHERIT NOBYPASSRLS` accounts; their own stage roles can be adopted using SET ROLE; cross-membership is false.
- `jw_app_dev` cannot INSERT directly to payments; authorized payment RPC is callable.

**Problem A:** V8.7 and V8.8 hard-coded the two inactive V8.6 usernames and rejected V9.0 secure gateways. **Fix:** immutable allowlist of reviewed legacy and V9.0 principals, plus actual `rolcanlogin` requirement; direct grants/privileged/cross-role/SSL checks remain.

**Problem B:** V8.7 login-side `has_table_privilege(..., format('jw_dev.table'), ...)` caused SQLSTATE `42501` when evaluated by legitimate `NOINHERIT` raw gateways without `jw_dev` schema USAGE. Granting schema USAGE to gateway would expand permissions. **Fix:** join `pg_catalog.pg_class` + `pg_namespace` and inspect relation OIDs without resolving private table names as raw login; no new grants.

## J1–J6 test progression
- J1: protected `app/main.py`, static UI, source history, DB schema unchanged; full suite re-run on exact candidate.
- J2: targeted tests first, full 5-job pipeline after implementation; fail-closed on unresolved gate.
- J3: actual Supabase read-only catalog proof; synthetic PG17 SSL verified-full and failed wrong CA; separate secrets never embedded in CI.
- J4: RED commit `d5d5c688339bd5bfbfbbaa376c1de07701672c92`, 2 expected failures/26 pass; corrected target baseline 29 pass. A second real-network error SQLSTATE 42501 was diagnosed without credentials and fixed.
- J5: actual PG17 TLS self-signed ephemeral CA, nonprivileged auth/trade roles, real backend advisory contention, rollback, deleted synthetic Docker/container/cert after job.
- J6: independent evidence receipts and Draft PR with precise scope. The tool uses only local ephemeral credentials, never the remote Supabase CA or customer data.

**Verified SSL integration:** [CI run #40095096457](https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/40095096457) — both focused jobs success. 
The test enforces server CA *and* hostname verification, refuses a different CA chain and reversed auth/business DSNs. **This is NOT verification of the actual Supabase server certificate**.

## Remaining production blockers
1. CA certificate for the *actual* Supabase target and `sslmode=verify-full` from the genuine application runtime, with safely injected independent credentials.
2. Real enterprise auth + finance and document CRUD + messenger on PostgreSQL via deployed HTTPS (not isolated local SQLite and synthetic PG).
3. Representative full database migration, backup and recovery RPO/RTO, independent penetration review and signed cutover approval.

**Release state remains BLOCKED.** No production merge/deploy/credential exposure and no changes to real `jw_dev` schema in this patch.
