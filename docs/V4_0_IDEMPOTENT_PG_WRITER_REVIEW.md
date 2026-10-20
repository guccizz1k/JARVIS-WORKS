# JARVIS WORKS V4.0 — Idempotent PostgreSQL 17 write lab

**REVIEW ONLY · SYNTHETIC DATA · NO CUSTOMER TRAFFIC · NO PRODUCTION DB MIGRATION**

## Previous proof
Owner-provided Codespaces screenshot on 2026-10-20 verifies V3.9 Psycopg 3 PG17 driver session binding, per-request rollback, isolated RLS, revocation and ephemeral cleanup as PASS. This does not prove V4.0.

## Scope
Reuse the V3.5 `MessengerReviewAdapter` transaction-bound verified actor and V2.7's already proven `public.messenger_messages` RLS and trigger for server-assigned, per-thread monotonic sequence. A new lab-only `LabWriterV40` uses the canonical `(sender_org,request_id)` unique constraint as the authoritative idempotency key, returning the committed message for an exact retry and refusing payload/actor/thread changes with the same key. For concurrent insert collisions, only SQLSTATE 23505 on the **specific expected** constraint triggers a fresh verified-session lookup. No secondary cache, retry loop, client-chosen sequence, or privileged SQL role is used.

Only three new parts: `app/pg_write_replay_v40.py`, a TestClient-only HTTP `app/pg_write_api_v40.py`, and `scripts/test_postgres_writer_v40.py` + network-free pytest. Not imported or mounted in `app/main.py`, not bound to public HTTP, not connected to SQLite production app.

## Security risks / counter-evidence
- Two concurrent identical sends must converge on one `(id,message_seq)`, with one `201` and one replay `200`; different concurrent requests must receive different sequences.
- A different payload reusing a nonce or another actor reusing that nonce must fail, not return the first user's evidence.
- Tenant C cannot send to A↔B, nor can an expired/revoked token reauthorize. Tenant B remains able to send after A revocation.
- RLS, actual authenticated sessions and database uniqueness — not client-provided company IDs or HTTP status codes — are the security boundary.
- Every failure must roll back; test DB/role destroyed by inherited `scripts/run_postgres_isolation_ci_v28.py` harness.
- No persistent queue, at-least-once retry service, user-provisioning/onboarding migration, file-write API, multi-replica throughput SLA or production database rotation is implemented.

## Verification
Gate 1: syntax and six predecessor source manifests plus V4.0 manifest.
Gate 2: local input, idempotency, error-output tests; Codespaces real PG17 3-tenant attack gate.
Gate 3: existing B2B unit regression plus previous live tests V2.7→V3.9.
Gate 4: no UI changes; no live browser testing yet.
Gate 5: ONLY_EPHEMERAL_DATABASE; untrusted DSNs forbidden; server never published. Actual V4.0 PG17 result required before PASS.

Growth note: The customer value is fewer duplicate orders/messages and safer document trail, not unverified latency, zero-defect, or commercial-release claims. Customer research remains consent-first and unpublished.
