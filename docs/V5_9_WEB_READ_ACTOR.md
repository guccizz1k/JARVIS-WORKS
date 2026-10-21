# V5.9 — authenticated B2B web read-actor journal (review only)

## Root cause
Existing `/api/messenger/threads/{connection_id}/read` persisted only
`(connection_id, org_id, last_read_seq)`. It never persisted which currently
authenticated employee advanced the position. V5.8 synthetic PG receipts cannot
recover read actors from this mutable organization-level cursor.

## Scope
- Add append-only SQLite table `messenger_read_actor_history_v59`.
- In the existing authenticated FastAPI **read route**, retain the existing
  membership + message validation, then write org cursor and actor event in the
  same `BEGIN IMMEDIATE` transaction (main.py `transaction()`).
- Record only actual advances, not duplicate/old read cursor calls.
- Verify membership and message-sequence ownership in the DB again before write.
- Atomic rollback if journal insert fails. Keep HTTP `{'status': 'read'}` unchanged.
- Original session, CSRF, other messenger routes and previous PG17 gates untouched.

## Explicit boundaries
- This is a SQLite **source-of-truth extension in a review branch**; no
  PostgreSQL cursor delivery, no application production enablement, no RLS
  cutover, no backfill of historical unknown actors.
- Journal uses SQLite write protections (triggers) and is not a tamper-proof
  substitute for immutable external storage or a complete audit system.
- Earlier read positions already present on upgrade remain unattributed.
- No automatic migration of live customer data. Deploying a schema change to
  user databases requires backups, independent validation, and approval.
- PG17 read-actor recipient signature semantics will need separate mapping and
  readback tests before any operational DB switch.

## Gates
`bash scripts/check_v59_review.sh` checks V5.9 new-source SHA256, JS syntax
and mandatory FastAPI HTTP tests; `bash scripts/run_pg17_codespaces_v59.sh`
creates a **separate worktree pinned to immutable V5.8 commit**
`e8ea684c9af78debdfc26179641e3094f2d2ef20` to run unchanged historic
source SHA256/regressions and PostgreSQL 17 Docker gates. This preserves the
original V5.1 messenger checksum rather than weakening historical manifests.

Neither command may skip failed stages or authorize cutover. `jw 59` runs both.
