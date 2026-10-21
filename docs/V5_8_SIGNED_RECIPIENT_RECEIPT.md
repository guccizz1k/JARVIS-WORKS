# V5.8 — signed recipient receipt proof (isolated)

Only a synthetic adjacent `message.insert` (order) followed by `receipt.insert`
for the same order is accepted. A signed PostgreSQL session for the **receiving
company employee** must match the stored `messenger_receipts.receiver_user` and
`receiver_org`. The sender's account can neither sign nor read this receipt.

The receipt record stores the immutable purchase-order snapshot SHA256,
receiver staff identifier, acknowledgement display name and exact receipt time.
This is **receipt of a document, not commercial approval or payment**.

The laboratory requires V5.1 immutable outbox, V5.4 immutable receipt triggers,
all existing V5.7 prerequisites and ephemeral SQLite/PostgreSQL fixtures.
PostgreSQL permits only SELECT and INSERT under forced RLS, with strict replay
read-back. PostgreSQL commit precedes the SQLite compare-and-swap ACK. A crash
before ACK repeats the record without altering existing contents.

## Explicit limitations

- **Delayed/interleaved receipts are not supported.** Real B2B receipts commonly
  arrive later. No events are skipped or ACKed in order to work around that.
- Historical receipts without a signed receiving staff mapping, read-position
  events, orders outside the adjacent pair, mixed-actor streams and customer
  data migration are explicitly blocked.
- No production PostgreSQL connection, attachment object-store migration,
  public deployment, approval, or operational cutover is authorized.

Run `jw 58` in the approved Codespaces **only after published branch verification**.
The result proves an isolated signed-actor contract, not launch readiness.
