# V5.4 — Write-time mutation provenance, disposable-only

## Problem (root cause)
V5.1 outbox `message.body_changed` and `read_position.*` store only a mutable
entity reference. By the time a relay polls them, the current message version
or latest read cursor might have advanced. Reconstructing the old value from
that current row falsely attests historical state. V5.3 deliberately refuses
these types; it cannot be considered a lossless migration.

## Implemented (isolated lab, forward-only)
`app/pg_mutation_snapshot_v54.py` installs an **append-only sidecar** in a fresh
synthetic SQLite database, with explicit disposal/environment guards. It
replaces precisely three V5.1 *SQL triggers in that ephemeral DB* in one
transaction. For body changes, a matching immutable edit record with the
correct previous body, new body, sender and version is mandatory; otherwise
**the original UPDATE fails atomically**. The sidecar references the edit ID
and version at mutation time, not the latest message state.

For each read-position insert/advance, the sidecar captures the org, thread and
monotonic read sequence at that moment, keyed by exactly the original V5.1
outbox event sequence. It contains no message text, attachment bytes or auth
tokens. Receipt UPDATE and DELETE get fail-closed immutable SQLite triggers
for this lab only. The V5.1 code files and operational app schema are untouched.

Existing outbox events or checkpoints prohibit installing V5.4 without a
separate audited baseline. Repeated install is read-only/idempotent only after
verifying the trigger and sidecar contracts. Corruption, tenant mismatch,
missing history or tampering deny the audit. No PG relay is added for new
mutation types; missing employee **read actor identity is not invented**.

## Verification / status
- Local real SQLite tests: write-time two-version edits, 1→4→7 cursors,
  missing edit denial, immutable receipts, forged triggers, wrong tenant,
  outbox sequence equality, source transaction rollback, tampering, replay
  prerequisites and unrelated V5.3 regression.
- Full Codespaces regression and PG17 historical check: NOT RUN until `jw 54`.
- Actual legacy SQLite backfill, authorized employee identity, PG payload
  application writer, encrypted object storage, physical browsers and real
  customer onboarding: BLOCKED.
- Business deployment/production migration: NOT AUTHORIZED.

## Safe command
In existing Codespaces after published `review/v54`: `jw 54`.

Every mandatory test failure or SKIP must stop the suite; do not weaken the
authorization guards or claim operational cutover from successful lab tests.
