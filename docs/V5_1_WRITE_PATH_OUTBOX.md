# JARVIS-WORKS V5.1: Actual B2B write-path transactional outbox foundation

## Why this is not another isolated PostgreSQL comparison

Unlike V4.4-V5.0 stand-alone shadow comparisons, V5.1 modifies the real
`app/messenger.py` schema-installation call path, but **only if two explicit
lab flags are set and SQLite is a file in the system temporary directory**.
Default app start and actual production remain byte-for-byte behaviorally
unchanged. Existing SQLite remains sole source of truth. This is an additive
integration foundation; there is no PostgreSQL write, replay worker or cutover.

## Atomic source changes (lab only)

`app/pg_transition_outbox_v51.py` creates a reference-only, append-only SQLite
outbox in the **same database and transaction** as live API source writes.
Triggers record message inserts and body changes, edit evidence inserts,
attachment inserts, receipts and read-position updates. They never store
message bodies, attachment bytes, credentials or original source records.
Messages already present before enabling need a separate verified baseline.
Read position reversals never become an `advance` event.

`JW_PG_OUTBOX_V51=ONLY_DISPOSABLE_LAB` and
`JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE` must BOTH be explicitly set.
A production JW_ENV, non-temporary path, symlink or broken source schema blocks
activation. **No operational deployment authorization** is provided.

## Verification

- Dedicated SQLite outbox tests: default off, bad flags, non-temp and invalid
  schema rejection, transactional rollback, immutability and idempotency.
- Full FastAPI `TestClient` verifies existing cookie+CSRF source write and
  original request-id replay with exactly one outbox append.
- `scripts/check_v51_review.sh` executes the complete historical regression
  once and rejects failures / skips through the existing no-skip harness.
- `scripts/run_pg17_codespaces_v51.sh` reuses the **unchanged V5.0 PG17 gates**
  rather than duplicating PG runners. V5.0 itself is NOT RUN in this session.

## Exclusions (must remain BLOCKED)

- No customer data backfill, production domain/DB endpoint, outbox dispatcher,
  dual writes, PG replay, ACK/checkpoint, recovery SLA or production cutover.
- Production-grade identity bridge and object storage are still unresolved.
- A test that passes on disposable SQLite/PG does not certify operational DB.
