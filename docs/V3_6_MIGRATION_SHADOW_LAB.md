# JARVIS WORKS V3.6 — Lossless Synthetic Migration Shadow + Rollback Gate

**Review-only, disposable PostgreSQL 17 environment, synthetic data only. NOT a production migration.**

## What is verified

- A consistent, in-memory `sqlite3.Connection.backup()` copy of seven messenger evidence tables, including text history, edit history, read positions, received documents' message snapshots, receipts, business profiles and original attachment bytes.
- Every column and SQLite value type is explicitly encoded into deterministic UTF-8 payloads (`bytes` values as Base64). Every payload gets SHA-256; record keys use original primary keys; per-table counts and aggregate seal are compared against PostgreSQL-returned raw bytes.
- The PostgreSQL destination is **a separate, private shadow schema** (`jw_migration_v36`) created with no grants to `jw_app`. It is **not the live messenger SQL schema**. Every write is transaction-scoped and restricted to the parent runner's freshly provisioned `jw_v20_test_<12hex>` PostgreSQL 17 database.
- The live gate injects a deliberate fault after two inserted rows, checks that the entire schema creation rolled back, retries on a new shadow, checks byte-for-byte integrity, confirms the app role is denied, checks PG `digest()` rejects changed payload with a stale SHA, and deletes the shadow. The parent runner then drops the entire disposable DB and role.
- All earlier V2.7/V2.8 and V3.5 RLS/API tests run **before** this new stage. A failure never reports PASS.

## Why this is not a production cutover

The existing production-facing FastAPI service is SQLite. Its `messenger_messages` contain immutable `order_id`, `immutable_order_snapshot`, `actor_name`, `version`, `edited_at`; file attachments can belong to `text` messages; receipts contain employee `actor_name`; and SQLite's stable `message_seq` history differs from the PG allocation model. The current PostgreSQL trial schema cannot losslessly represent every field. This implementation therefore **refuses a direct operational import**; instead it verifies that all seven supported source tables can be preserved in an isolated, test-only escrow format. It does not migrate other order/invoice/payment tables or authenticate real enterprises.

Next after a V3.6 live PASS: design a versioned, operational PostgreSQL schema matching legacy evidence and transactional API semantics; migrate all dependent business tables with referential integrity, idempotency, encrypted attachment storage, legal retention and rollback. Perform repeated live test migrations before any cutover approval.

## Run in the pre-existing free-quota Codespace

After switching to the new private review branch, run exactly:

```bash
bash scripts/run_pg17_codespaces_v36.sh
```

Expected final output includes `PASS: V3.6 real PG17 synthetic SQLite shadow copy, exact SHA-256, cross-role denial, forced rollback and cleanup`, followed by `PASS: PostgreSQL 17 live RLS attacks and ephemeral cleanup completed`. `0=PASS`, `1=FAIL`, `2=NOT RUN` for the complete live gate. Do not use real customer databases or export credentials. Do not merge into `main`, deploy, or spend paid Actions minutes.
