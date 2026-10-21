# V5.6 — Immutable original body and ordered edit-history replication

## Verified use case

An existing message may be edited before its original `message.insert` outbox
row is processed. Reading `messenger_messages.body` would transmit the latest
version in place of the original: a loss-of-evidence bug. V5.6 reconstructs
version 1 using the protected version-2 `previous_body`, then checks every
subsequent immutable edit's version, editor, before/after and V5.4 write-time
snapshot ID. No backfilled values are invented. A missing link blocks the
**entire batch** and SQLite ACK is not advanced.

## Isolation, data integrity, replay

The source must be an explicitly authorized temporary SQLite file with V5.1,
V5.4 and V5.5 guards. Events `message.insert`, `edit.insert`, and
`message.body_changed` are mapped to an append-only, forced-RLS PostgreSQL 17
ledger with original UTF-8 bodies and SHA256. Verified `(tenant,actor)` comes
from V5.2 signed PostgreSQL session, not user-supplied data. The PG app role
has no UPDATE or DELETE privileges. For duplicated `(stream,sequence)`, every
field must match, including the full plaintext body, version and edit ID.

PG commit precedes SQLite compare-and-swap ACK. Post-commit crash/replay,
forged edits, missing write-time snapshots, cross-company RLS access,
revoked sessions, unsupported event at the head, and Docker cleanup are
mandatory tests. No source data is silently skipped or acknowledged.

## Explicitly NOT covered

This is an **isolated test ledger**, not a production messenger writer or
operational schema migration. It does not support attachments, receipts,
read-position actor signing, order snapshots, enterprise employee enrollment,
customer data backfill, durable blob storage, or production cutover.
Existing V5.4 events are not automatically installed in the live web service;
they require explicit approved integration and historical baseline.

Local tests are distinct from live PostgreSQL tests. Codespaces `jw 56` will
run full historical source regression and the V5.6 live PostgreSQL 17 test
with temporary Docker; cutover remains DENIED.
