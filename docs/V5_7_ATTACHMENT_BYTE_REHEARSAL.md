# V5.7 — restricted attachment bytea parity, review only

## Scope

Only a **new, disposable SQLite-to-PostgreSQL17 laboratory** is supported. The
real B2B attachment endpoint inserts `messenger_messages` and
`messenger_attachments` in one transaction; V5.1 outbox records a consecutive
`message.insert`, `attachment.insert` pair. This relay requires that pair,
validates immutable attachment triggers, compares bytes, filename, MIME, size,
SHA256, message sender, thread membership and the signed PG identity, then
inserts bytes into a separate forced-RLS table. No customer or operational
object store is used, and no production credentials or deployment are touched.

A single PG transaction commits before the SQLite CAS checkpoint. After a crash
between commits, duplicate replay is accepted only if **every PostgreSQL field
including the entire bytea payload is equal**. Divergence, identity mismatch,
wrong filename or hash, out-of-order event, unexpected message, or unsupported
receipt/order/edit/read-position event fails before moving ACK. The test
limits file payload to 5 MiB and batches to 12 attachments.

## Important limitations

- This **is not** a general message/event replication engine. It requires a
  contiguous attachment-only stream and stops on interleaved plain text.
- Receipt actors belong to the **receiver tenant**. Reusing sender credentials
  to replicate receipts is not permitted. Receipt transfer remains BLOCKED.
- User-uploaded files need antivirus/content inspection, encrypted durable
  object storage and lifecycle controls before a commercial service.
- Historical backfill, production employee identity, live PG writer, public
  web UI, and production cutover remain BLOCKED.
- Static and synthetic SQLite/PG tests do not prove the public service works.

Run `jw 57` in Codespaces only after publishing `review/v57`. Earlier live
PostgreSQL versions run first. Any missing dependency, failure or mandatory
SKIP prevents a PASS. Cutover remains DENIED even if this test passes.
