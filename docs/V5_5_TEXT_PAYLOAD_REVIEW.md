# JARVIS-WORKS V5.5 — Disposable Signed Text Payload Review

## Scope and protection

Review-only feature, on top of `review/v54`. No production SQL migration, no
customer import, no merge, no deployed web endpoint and no modification of
`app/messenger.py`, `app/main.py`, historical validation manifests, or `/main`.

V5.2/5.3 signed role-binding and V5.4 immutable edit/read-position snapshots
are reused rather than rewritten. The feature accepts **only** unedited,
unattached, `kind=text`, version-1, positive-length UTF-8 messages from the
synthetic SQLite outbox. Order messages, edited messages, attachment-linked
messages, receipts and mutable read cursors are explicitly rejected. No
unsupported event may advance the new V5.5 ACK checkpoint. This restriction
means V5.5 is **not yet a complete historical replication service**.

## PG17 transaction model

* Verify an explicitly allowed, temporary SQLite database and V5.1 + V5.4
  immutable trigger contracts before opening the checkpoint.
* Reuse the existing signed `jw_app` session binder; reject tenant or actor
  mismatch before any PostgreSQL modification.
* On disposable PostgreSQL 17, create `jw_payload_v55.messages` with forced
  row-level security, SELECT/INSERT privilege only for `jw_app`, and no
  UPDATE/DELETE privilege.
* Store original UTF-8 `body`, `connection_id`, `created_at`, sender identity,
  entity reference, stream/sequence and SHA-256 in a private test ledger.
* Commit the PG transaction before updating the source SQLite ACK via CAS.
  A repeated `(stream,sequence)` may succeed only if **all** stored content
  is exactly equal. Any conflict, revoked credential, or RLS denial fails.
* No plaintext message body or credential is printed in error logs; the
  source V5.1 outbox remains reference-only.
* An isolated PG17 Docker test checks successful UTF-8 readback, fault injected
  commit-before-ACK crash/replay, cross-tenant denial, revocation, and cleanup.

## Verifications and limitations

Local synthetic tests cover source payload equality, UTF-8, ordering, message
limits, unsupported events, outbox rollback, idempotent replay, durable
conflicts, production denial and source guards. **Actual PostgreSQL 17 remains
NOT RUN** until `jw 55` executes on Codespaces and returns a V5.5 PG17 PASS.

This does not verify business-wide attachment storage, editable messages,
receipt verification, full historical cutover, real employee identity, public
web API writes or a reversible operational deployment. All eight release
readiness requirements remain independently gated and production cutover DENIED.

Commands: run `jw 55` in the existing Codespaces terminal after review branch
publication. It executes historical 5.4 regression before this new test and
retains fail-closed cleanup semantics.
