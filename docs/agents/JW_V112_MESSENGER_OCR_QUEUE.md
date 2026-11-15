# JARVIS-WORKS V11.2 — Event-driven PG messenger + leased OCR queue

**2026-10-25, review-only.** This document records a functional code candidate and an unperformed operational migration. It does not attest to 100,000 concurrent users, paid Render readiness or a permanent DB installation. J1–J6 and the one-primary-account/company rule remain intact.

## 1. Messenger: remove unconditional high-frequency SQL polling (opt-in)

- New `app/pg_v112_wakeup.py`: per-ASGI-worker bounded WakeHub keyed by `SHA256(connection_id)`, using 1 shared PostgreSQL LISTEN connection **per server instance**, not per socket. Notifications carry **only** a digest, never a tenant's company name, token, message, attachment or raw identifier.
- New `db/review/v112_ephemeral_only_pg.sql`: after-INSERT PG17 messenger message and edit triggers; transactional `pg_notify()` delivered only on successful commit. The SQL **REFUSES** any DB other than `jw_v112_ci_<12-hex>`; do **NOT** apply to real Supabase or Render DB.
- Existing `app/pg_messenger_realtime_v90.py` still uses its authenticated `jw_dev.v90_sync_*` RPCs and strictly monotonic cursors; a `wake_hub` optional parameter changes the wait into **notify wake + 10-second mandatory DB reconciliation** when listener is healthy, **2-second fallback** when not healthy. No change by default. Event subscriptions are removed even on WS exceptions/failed handshake. All initial RPCs authorize before accepting WebSocket.
- `app/pg_v90_integrated_entry.py`: only starts a dedicated background listener on explicit `JW_V112_PG_NOTIFY_ACK=ISOLATED_PG17_REVIEW_ONLY` plus nonproduction JW_ENV and **verified enabled triggers** on exact `jw_dev.messenger_messages` and `jw_dev.messenger_edits` tables. Listener requires actual `jw_trade_gateway_v90` raw login with nonprivileged roles, SSL active and transport connection `sslmode=verify-full`. Any missing schema refuses startup; unexpected listener disconnect restores bounded DB fallback.
- **Important architectural limitation:** notify hints are not durable; PG remains the message source of truth; reauthorization occurs on each fallback/wake DB read. The new branch is NOT presently deployed; real PG17 replication across two ASGI instances and >1k sockets is NOT MEASURED. A permitted persistent-schema migration must be separately reviewed after full tenant/role analysis.

### Forecast only (NOT a benchmark)

At 1,000 *busy* WS sockets with 2 DB queries per 0.3 seconds: around 6,667 queries/second. When fully idle and event notification succeeds, the 10-second reconciliation interval implies ~200 queries/second, or ~33x lower *baseline idle polling*. A disconnected listener's 2-second fallback implies ~1,000 queries/second. These are steady-state arithmetic models ignoring login/heartbeat and real messaging traffic; **no claim of actual database throughput or production savings**.

## 2. Durable OCR queue, bounded & tenant-bound

- `app/pg_v112_ocr_queue.py`: separate PG17 queue client for queue submission, atomic claim with `FOR UPDATE SKIP LOCKED`, at-most-3 processing attempts, 60-second lease, cryptographic fencing token, backoff, expired exhausted-job quarantine, deterministic result object key and per-company request idempotency.
- Queue rows contain only org/actor IDs, private object key, document filename, SHA256, status and non-sensitive error codes. Raw OCR bytes, customer records, payment amounts and secrets remain **outside the queue**. `process_one()` verifies content digest and size before invoking the caller-provided **resource-limited and malware-scanning OCR parser**. Results go to `needs_review` and cannot auto-create transactions or payments.
- Proposed SQL creates a FORCE-RLS table with no policies and no grants; therefore **not ready to execute against a persistent DB**. A dedicated narrowly-scoped worker role, private encrypted object store, malware scanning, read/write IAM and tenant-policy review must be implemented and independently tested before queue processing in Render.
- The existing SQLite demo synchronous evidence-preview path is intentionally not silently changed; the new distributed queue is **not hooked into public customer APIs**.

## 3. Verification / blockers

- Synthetic/local Python unit tests: **19 passed, 0 failed** after fixing a test stub which incorrectly required SQL placeholders for a parameterless housekeeping query. A syntax compile of added modules also passed.
- Browser/WebSocket/GitHub 887+/PostgreSQL real API full regression on this exact branch: **NOT RUN**. GitHub Actions $5/month overage already exhausted. No skip is hidden as PASS.
- Real persistent PG17 DDL, RLS policies, worker grants, listener/trigger acceptance, Render deployment, cross-instance WSS, backup/recovery, end-user MFA, actual 100k account performance: **BLOCKED/NOT VERIFIED**.
- No `main` merge, no actual Render service or database changed, no extra paid resources created, no CI jobs intentionally triggered.

## 4. Safe completion sequence

1. Review/pin this draft; run the same-commit offline tests and J1–J6 as the existing budget permits.
2. In fresh ephemeral PG17, apply only the CI-guarded SQL; verify NOTIFY commit/rollback, app restart, wake coalescing and 2 simultaneous instances, and ensure RLS/actor restrictions.
3. Design and independently audit minimum-privilege OCR worker role, tenant admission RLS, tenant-bound private object store and durable result writer. Check retries, poison jobs, outage, duplicate/concurrent imports and explicit preview approval.
4. Before any persistent DB change, obtain separate migration/backup/rollback and hosting cost signoff. Only then consider real HTTPS stage enablement.

**Latest product-release decision remains BLOCKED.**
