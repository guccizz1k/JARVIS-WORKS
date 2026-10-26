# JARVIS WORKS V8.8 — standalone live-readiness probe

## Purpose and limits

V8.8 extends V8.7's existing two-login verification. It checks PostgreSQL's **transaction-scoped advisory locking** with two independently opened, read-only connections. It never changes payment rows. It does not test or certify real multi-connection payment contention, application login/MFA E2E, data migration, or production deployment.

## Preconditions

The environment must be `JW_ENV=dev` (or `development`/`test`), `JW_PG_V88_LIVE_GATE=ISOLATED_DEV_ONLY`, and both `JW_PG_AUTH_STAGE_DSN` and `JW_PG_STAGE_DSN` must refer to different non-admin logins already provisioned in a secret manager. The database accounts must support a TLS certificate-verified connection. **Never place secrets in code, .env committed files, or chat.** At project date 2026-10-23 the database scaffolds are both `NOLOGIN`, so this gate intentionally reports BLOCKED.

Run `python scripts/check_pg_v88_live.py` in an isolated development environment. Exit 0 represents only the scoped connection/role/advisory-lock readiness. Exit 2 means BLOCKED. It does not switch SQLite or FastAPI to PostgreSQL.

## Checks

1. V8.7 validates independent non-admin logins, TLS and `SET LOCAL ROLE` boundaries.
2. Two *different backend sessions* use read-only transactions and `SET LOCAL ROLE jw_app_dev`.
3. First backend acquires a fixed namespaced `pg_try_advisory_xact_lock`.
4. Second backend must be unable to acquire it while held.
5. First backend rolls back, second backend must then acquire it.
6. Both connections roll back and close in `finally`, including on failure. All error output is redacted.

This is a useful readiness prerequisite but is **not** a substitute for using two actual clients to race `record_payment_v83` on a disposable funded invoice. Such a scenario requires approved non-production credentials and careful fixture cleanup.
