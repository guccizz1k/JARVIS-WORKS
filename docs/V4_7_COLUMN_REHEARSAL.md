# JARVIS-WORKS V4.7 — PostgreSQL 17 ephemeral compatibility projection

## Why the V4.6 success was a cutover DENIAL

The actual Codespaces log showed that all historical V2.7–V4.5 isolated
PostgreSQL gates passed, and V4.6 positively detected the differences between
the seven-table running SQLite messenger schema and the PostgreSQL public
messenger schema. The last line reported **PASS: audit**, explicitly **cutover
DENIED**. It did not show a production migration or a live PostgreSQL service.

## V4.7 deliverable

A **13-column additive, nullable, no-default projection**, limited to the
existing V4.6 essential legacy field gaps, is rehearsed inside a PostgreSQL
transaction on a newly created ephemeral `jw_v20_test_<12hex>` PostgreSQL 17
database. The software is not a production migration, not an online schema
upgrade, and not a web API. The actual PostgreSQL `public.messenger_*` schema
is temporarily altered **inside the transaction**, then **always ROLLBACK**.
The PostgreSQL catalog must be identical to its original state after rollback;
failed ROLLBACK is an immediate gate failure.

| Table | Proposed additive fields (only in a rolled-back rehearsal) |
|---|---|
| messenger_companies | verification_kind TEXT |
| messenger_connections | accepted_at TEXT; connection_seq BIGINT |
| messenger_messages | order_id TEXT; immutable_order_snapshot TEXT; actor_name TEXT; version INTEGER; edited_at TEXT |
| messenger_edits | edited_at TEXT |
| messenger_attachments | mime TEXT; size_bytes INTEGER |
| messenger_read_positions | last_read_rowid BIGINT |
| messenger_receipts | actor_name TEXT |

Types `TEXT` on legacy timestamps and order JSON snapshots are deliberate:
converting them to PostgreSQL `timestamptz` or `jsonb` may change original bytes
or formatting. Exact reversible transformation remains a separate blocker.

## Mandatory gates

- Every table must already have PostgreSQL `ENABLE ROW LEVEL SECURITY` and
  `FORCE ROW LEVEL SECURITY` turned on, as verified by the V4.6 catalog guard.
- Exact V4.6 missing-column set required. Partially upgraded, drifted or
  inconsistent source/target schemas are refused; no best-effort migration.
- Typed columns must be nullable and have no implicit defaults in the
  transaction catalog. No existing constraints, policies or triggers are
  rewritten or dropped. Every change is rolled back, even if verification
  fails. After rollback, the same seven-table inventory must be restored.
- Administrative DSN must refer to an allowed disposable localhost-only
  PostgreSQL 17 database. Reject production environment, unsafe connection
  parameters, non-admin role, non-17 version and missing explicit lab flags.
- V4.6 and all earlier integrity manifests and PostgreSQL gates must PASS
  before V4.7 begins. Strict zero-SKIP regression is inherited from V4.5.
- Successful rehearsal **always** returns `decision=BLOCKED` and
  `cutover_approved=False`. All six prior semantic blockers remain.
- Complete disposable PostgreSQL container, roles, venv and temporary files
  must be cleaned up; failed cleanup is FAIL, not PASS.

## Run in a detached Codespaces review/v47 worktree

```bash
bash scripts/check_v47_review.sh
bash scripts/run_pg17_codespaces_v47.sh
```

Expected summary after verified real PG17 execution:

```
PASS: V4.7 PG17 13-column additive rehearsal, exact SQL types, forced RLS and unconditional rollback
BLOCKED: V4.7 production cutover DENIED; semantics, identity, dual-write and rollback readiness unresolved
PASS: V4.7 PG17 additive projection rollback rehearsal (cutover DENIED) and isolated Docker cleanup
```

The `BLOCKED` line is the correct safety decision. A nonzero exit, missing
manifest, missing rollback confirmation, lost RLS or absent Docker always blocks
this review. Never run the SQL against an operational or customer database.

## Remaining work

This review does **not** prove values can be mapped to the public operational
schema or that live web identity, attachment-kind semantics, receipt and order
lifecycles, editing concurrency, timestamp conversion, read-position history,
dual-write and recovery work safely. It does not change `app/main.py` or enable
PostgreSQL in the running B2B service. Investigate those blockers one at a time
on synthetic evidence before any authorization of a production transition.

## Verification claims and exclusions

Local pytest tests exercise exact statement count, read-only detection,
wrong baseline, SQL error injection, RLS drop, type drift, catalog restore,
rollback failure and historical runner failure propagation. They rely on a
mock PostgreSQL cursor and **do not constitute live PG17 validation**. Actual
Codespaces execution and browser/Safari UI checks are NOT RUN until observed.
The old Starlette TestClient deprecation warning is a separate dependency
maintenance item and is not silenced in this review.
