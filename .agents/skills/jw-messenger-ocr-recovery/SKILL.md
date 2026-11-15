---
name: jw-messenger-ocr-recovery
description: When modifying WebSocket messenger, PostgreSQL LISTEN/NOTIFY, reconnect/replay, job queues, OCR worker leases, backoff, retries, or outage recovery in JARVIS-WORKS.
---

# Messenger and OCR recovery

J1–J6 subordinate project skill. Review only; `main` unchanged, release BLOCKED.

1. PostgreSQL committed messages and monotonic cursors are authoritative. NOTIFY is just a wake hint; never include message bodies or tenant secrets in the event.
2. Prove reconnect, missed/duplicate notification, session revocation, message replay, multi-instance delivery and tenant-scoped RPC verification. An idle mock poll benchmark cannot establish external fanout.
3. OCR jobs need tenant-bound immutable source keys, `SKIP LOCKED` competition, bounded lease, fencing token, distinct proposal output per lease, retry/backoff and poison handling.
4. Block a stale worker from modifying current output; OCR never directly approves finance records. Audit all recovery paths, rollback and unauthorized worker grants.
5. Use a fresh local disposable PG17 cluster and explicit review approval for destructive fixture setup; do not connect to persistent Render/Supabase.
6. Record exact SHA and real PASS/FAIL/SKIP, mark unexecuted PG and two-instance tests NOT RUN, and trigger existing incident-retro only after a genuine reproduced failure.

Existing seams: `app/pg_v112_wakeup.py`, `app/pg_v112_ocr_queue.py`, `scripts/jw_v113_ephemeral_pg_integration.py`.
