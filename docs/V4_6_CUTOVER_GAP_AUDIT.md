# JARVIS-WORKS V4.6 — Operational Schema Gap Audit (review-only)

## Why

V4.5 has passed in an isolated Codespaces PostgreSQL 17 instance. This does
**not** establish that the production-facing SQLite FastAPI messenger can
use the current `public.messenger_*` PG17 schema without evidence loss.

V4.6 introduces a **read-only, synthetic-only, fail-closed seven-table catalog
comparison**. It checks the actual `public` operational tables, independently
of the historical read-only `jw_migration_v37` compatibility schema.

It deliberately does NOT migrate data, add operating columns, change triggers,
register an API route, alter a customer database, or grant production cutover.
V4.5 and all earlier validation manifests are protected and unchanged.

## Detecting field-loss risk

Seven legacy SQLite tables are compared against actual PostgreSQL catalog
columns, with the V3.7 COLUMNS contract as a single trusted source.
The following fields of the current web messenger require a lossless mapping:

| Table | Known missing or incompatible operational metadata |
|---|---|
| messenger_companies | verification_kind |
| messenger_connections | accepted_at, connection_seq |
| messenger_messages | order_id, immutable_order_snapshot, actor_name, version, edited_at |
| messenger_edits | edited_at |
| messenger_attachments | mime, size_bytes |
| messenger_read_positions | last_read_rowid |
| messenger_receipts | actor_name |

Additional **semantic** blockers are independent of identical column names:
SQLite attaches files to a text-kind message, while PG17 distinguishes the
`attachment` kind; SQLite timestamp strings and PG17 `timestamptz` require a
proved reversible mapping; order and receipt lifecycle semantics, business
identities, dual-write and rollback are not yet approved.

Every result therefore has `decision=BLOCKED`, `cutover_approved=False`.
A successful gate proves that the *audit* correctly found and enforced
migration blockers, **not** that migration or deployment is safe.

## Safety rules

- Only the V2.8 historical gate's disposable `jw_v20_test_<12 hex>` database,
  PostgreSQL 17, and the `postgres` admin role are permitted for catalog audit.
- The same existing V4.5 synthetic supervisor must return zero before V4.6
  executes; V4.6 never proceeds after FAIL, SKIP or NOT RUN.
- PostgreSQL transaction is read-only (`SET TRANSACTION READ ONLY`). No SQL
  DDL/DML is issued by this audit; no real customer records are accessed.
- All seven messenger tables must exist, with RLS enabled and FORCE RLS.
  Any absent or inconsistent security metadata refuses readiness.
- The V3.6 in-memory SQLite fixture's exact legacy columns must match V3.7.
  No user-provided path, secret, SQL identifier or production DSN is accepted.
- The full pytest suite is re-run using V4.5's strict SKIP=>FAIL plugin.
- Docker instance, temporary Python venv, synthetic PG database and roles
  must be cleaned up successfully for the integration gate to report PASS.

## Execution

In the existing Codespaces terminal, from a detached `review/v46` worktree:

```bash
bash scripts/check_v46_review.sh
bash scripts/run_pg17_codespaces_v46.sh
```

The PG17 test log should include:

```
PASS: V4.6 read-only PG17 seven-table operational schema audit; forced-RLS verified; unsupported cutover DENIED
BLOCKED: V4.6 operational cutover: ...
PASS: V4.6 PostgreSQL 17 operational schema gap audit (cutover DENIED) and isolated Docker cleanup
```

The `BLOCKED` line is intentional: successful *risk detection* must not be
mistaken for a production cutover certificate.

## Local verification and remaining limitations

Local unit/reliability tests simulate PostgreSQL catalog results and verify
field mismatches, RLS gaps, unsafe role/DB/version rejection, no SQL writes,
chained runner restoration, and explicit operator denial. Local tests do not
substitute for a real `postgres:17` container or the private full project.

The pending Codespaces run must pass historical V2.8–V4.5 manifest verification,
full strict pytest regression with zero SKIPs, live PostgreSQL synthetic
RLS tests, new V4.6 catalog audit, and disposable container cleanup.

**Operational FastAPI migration, live customer data transfer, schema fixes,
full UI/Safari validation, and deployment remain BLOCKED/NOT RUN.**

### Deprecation warning

The residual `starlette.testclient` warning is due to recent Starlette
preferring `httpx2`. The official Starlette TestClient documentation describes
`httpx` as a deprecated fallback. This audit does not silently upgrade pinned
or historical dependencies; compatibility of `httpx2` with the whole B2B
application and pytest setup requires a separate verified change.
