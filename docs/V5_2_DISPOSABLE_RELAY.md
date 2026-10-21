# V5.2 — Isolated SQLite → PostgreSQL 17 reference relay

## What was built

This version is the first verified write from **the real V5.1 SQLite messenger
transactional outbox** into a **disposable PostgreSQL 17 staging ledger**. It
is **not** the operational messenger writer. It copies only validated
`message.insert` references and their event envelope—not body, attachments,
order snapshots, receipt evidence, credentials, or customer data.

No production app route or background worker is added. No live migration, main
branch update, webhook, remote deployment or real customer PostgreSQL access.

## Invariants

- Two V5.1 flags plus the independent V5.2 relay and PG17 test flags are
  mandatory. Production JW_ENV and any non-temporary SQLite location are denied.
- SQLite source must be file-backed in the disposable tmp tree, have FK checks,
  V5.1 immutable triggers and required provenance columns; prior writes cannot
  be mid-transaction when the relay takes ownership.
- Only event kind `message.insert` is supported. An attachment, edit, receipt,
  read-position, missing source reference, unknown actor or cross-tenant event
  must **fail without advancing the ACK**. No events are quietly skipped.
- The PostgreSQL client is **`jw_app`**, never admin, in a DB named
  `jw_v20_test_<random hex>` on loopback. It binds a signed, revocable PostgreSQL
  actor session, checks RLS and superuser/bypass-role flags and writes to
  `jw_relay_v52.inbox`, created ONLY in the V2.8 disposable supervisor DB.
- That table has forced RLS, SELECT and INSERT policies checking both verified
  tenant and actor, no UPDATE or DELETE to the application role, and a composite
  primary key `(stream_id, source_seq)`.
- A key replay with different content is a hard failure; equal content after
  `ON CONFLICT DO NOTHING` is accepted. PostgreSQL **commits before** advancing
  the SQLite checkpoint with compare-and-swap, protecting replay after a crash.
  The two databases are NOT one distributed transaction; exactly-once refers
  to ledger effect, not message delivery or complete business migration.
- SQLite source transaction is intentionally held during this tiny batch,
  **lab only**. This design is not suitable for a live high-traffic service;
  production work queue/lease, throughput and checkpoint design are outstanding.
- No baseline/backfill for pre-existing messenger rows is implemented.

## Test evidence / current limits

- Local Python unit and failure-injection tests: signed identity, RLS fixture
  definitions, bad inputs and flags, unsupported event, queue gap, conflict,
  PG offline, crash after committed sink write, exact replay, original-source
  rollback, and supervisor failure. PG real integration is NOT RUN locally.
- `jw 52` executes `check_v52_review.sh` (entire historical repository regression
  including V5.1) then an isolated PG17 container. The new runner reuses the
  existing V5.0 PostgreSQL chain and adds V5.2 only after it passes.
- Full release cutover remains BLOCKED: production identity mapping,
  attachments, edits, receipts, order evidence, legacy semantics, replay
  performance/monitoring, deployed service testing and rollback authorization.

## Strict status rules

A local PASS does not mean Codespaces PASS. All stage failures or cleanup errors
must return non-zero. Neither skipped tests nor `cutover DENIED` can be counted
as a production migration. The company-facing `app.main` is untouched.
