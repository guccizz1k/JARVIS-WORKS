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
`bash scripts/check_v59_review.sh` requires full historical source + UI
regression and real FastAPI HTTP tests, then
`bash scripts/run_pg17_codespaces_v59.sh` requires historical PG17 Docker gates.

Neither command may skip failed stages or authorize cutover. `jw 59` runs both.
