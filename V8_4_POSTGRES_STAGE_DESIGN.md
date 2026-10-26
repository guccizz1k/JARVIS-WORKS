# V8.4 — PostgreSQL FastAPI read-only stage integration

## Boundary

- Existing SQLite API and login, including app/main.py, remain byte-for-byte untouched; full cutover NOT DONE.
- Feature off by default. Only the SEPARATE `app.pg_dev_entry_v84:app` ASGI
  entrypoint mounts `/api/pg-stage/v84/*` with `JW_PG_STAGE_V84=ISOLATED_DEV_READ_ONLY` outside prod.
  Importing that entrypoint without opt-in raises; the original app.main:app never mounts it.
- Requires dedicated non-superuser Postgres LOGIN with `SET ROLE jw_app_dev`
  ability, TLS certificate validation, and a configured DSN from secrets.
- API uses the original `__Host-jw_session` cookie, but **requires it to
  exist in PostgreSQL**. SQLite sessions are NOT accepted as a fallback.
- `jw_dev.stage_identity_v84()` is SECURITY DEFINER, in a non-exposed schema,
  with EXECUTE restricted to `jw_app_dev`; no raw passwords/MFA data exposed.
- Every request opens a read-only PostgreSQL transaction, selects a low-privilege
  session role, sets only the SHA-256 of the cookie (never the raw token), and
  fetches the user/org identity inside Postgres. Disabled and expired sessions
  return no row; role is scoped to the transaction.
- PostgreSQL RLS remains the row authorization boundary. The route only
  selects fixed, explicit columns; no dynamic SQL identifiers or SELECT *.
- 6 read-only routes: /me, /customers, /quotes, /orders, /invoices, and
  /invoices/{id}/payments Limit: 1–100.
- No PostgreSQL API Login endpoint, session creation, session migration,
  write API mount, production cutover, or independent concurrent DB
  connection test is claimed.

## Enablement and tests

Do not enable until a restricted LOGIN has been provisioned and approved.
Install only the optional `requirements-pg-stage.txt` to use the feature.
Mounting this feature on the production deployment is blocked.

- FastAPI request tests use a FakeConnection: validates default off,
  unsafe-login rejection, session hashing, max page size, SQL binding,
  read-only transaction sequencing and nonexistent invoice rejection.
- Real Supabase SQL proof: synthetic valid/expired/disabled/missing sessions,
  tenant A/B SELECT isolation, function GRANTs, rollback.
- No real PostgreSQL driver-to-cloud end-to-end test was run (credentials
  intentionally absent in this environment).

## Next blockers

1. Set up dedicated non-privileged database login; security review of its
   memberships and TLS certificate trust.
2. Transactional PostgreSQL session/login/MFA migration with lockout,
   throttling, password hash and recovery-code parity.
3. Controlled dual-run parity for GET APIs and all remaining writes.
4. Two independent PostgreSQL connections to test ledger concurrency.
5. Restore/drill, browser session, CI and deployment validation before cutover.
