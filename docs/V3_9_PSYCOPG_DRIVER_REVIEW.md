# JARVIS WORKS V3.9 — safe Psycopg 3 connection lifecycle (review only)

**Scope:** existing Psycopg 3 driver integration hardened for the read-only, synthetic PostgreSQL 17 FastAPI TestClient bridge. **Never used by the production SQLite application.** No paid database, no live credentials, no customer data, no deployment.

## Driver decision

Psycopg 3 (`psycopg[binary]>=3.2,<4`) was **already** in `requirements-postgres-check.txt`, installed temporarily in the V2.8–V3.8 Docker/venv gate. Do not add duplicate drivers, always-on production dependencies or auto-start a database. Use the existing temporary environment. Optional `psycopg_pool` is **not** activated yet: pool reuse requires separate multi-tenant session-bleed, resource exhaustion, latency, and rollback testing on an actual write-capable operational schema.

## Changes

- `app/pg_driver_v39.py`: common bounded, disposable-only database connection helper for V3.8 read APIs. It checks the existing guard flags and loopback-only `jw_v20_test_*` DSN, validates runtime DB name, `jw_app` non-superuser/non-BYPASSRLS role and PG major version 17, then binds the signed tenant and actual actor inside one transaction.
- Every request now gets one fresh connection; transaction-scoped statement/lock/idle timeouts; **always** `rollback()` and `close()` after success or exception. The original database's `jw_guard.current_tenant()` and forced RLS remain the real authorization mechanism.
- In `app/pg_compat_read_api_v38.py`, only its existing `fetch()` connection lifecycle is refactored to use the helper; the same API paths, input validation and tenant-visible content remain unchanged.
- `scripts/test_postgres_driver_v39.py` adds live PG17 verification of distinct company A/B actor bindings, no inherited tenant context, invalid/revoked token denial and cross-tenant survival. It runs after the existing V3.8 gate only when the separate V3.9 environment flag is enabled.
- `tests/test_pg_driver_v39.py` uses a fake Python driver to prove errors, privileged roles, missing flags and wrong PG major version all **fail closed**, while both normal and exceptional requests close/rollback.

## Approvals and non-goals

- The current production-facing FastAPI app remains SQLite. No `app/main.py` import, production DSN, actual company provisioning, PG writes, migrations, connection pools, public listener, CI execution, secrets storage, PR, merge or paid deployment.
- The disposable test is intentionally conservative: a credentialed, real customer PostgreSQL connection must always fail before any external SQL.
- This is a **driver hardening candidate**, not a finished production database adapter or formal security certification.

## Verification commands

Offline: `pytest -q tests/test_pg_driver_v39.py tests/test_pg_compat_read_api_v38.py`.

Codespaces (existing free quota): `git fetch origin review/v39:v39 && git switch v39 && bash scripts/run_pg17_codespaces_v39.sh`.

**Live gate acceptance:** a distinct `PASS: V3.9 real Psycopg 3 PostgreSQL 17 ...`, inherited V3.8 PASS and final `PASS: PostgreSQL 17 live RLS attacks and ephemeral cleanup completed`, with no `FAIL` lines. Anything else means `FAIL` or `NOT RUN` and no production change.
