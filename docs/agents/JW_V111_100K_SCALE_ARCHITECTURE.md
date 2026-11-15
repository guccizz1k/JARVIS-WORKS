# JARVIS-WORKS V11.1 — 100,000-account architecture / manual Render scaling

REVIEW ONLY / NOT DEPLOYED / 100k NOT MEASURED. Keep J1–J6, the one-account-per-company policy and PG role separation. This PR adds offline models, synthetic validation, a loopback-only test, and an explicit approval gate. It does not deploy Redis, workers, object storage or a 100k-user application.

## Stage 1 — Multi-instance design

- PostgreSQL is the source of truth; do not trust server memory or SQLite demo state for enterprise sessions, financial writes or audit. Separate auth and trade credentials; a validated role and session per transaction.
- Store private files in encrypted object storage with access-controlled retrieval and malware scanning.
- Offload OCR/PDF work into a durable shared queue with tenant-bound idempotency keys, bounded retries and recovery checkpoints. Require human confirmation for all OCR-generated finance documents.
- Use committed PG messages and durable message cursor replay. For multiple servers, build a shared cross-instance event/outbox broker; Redis Streams or equivalent can be evaluated later, not assumed implemented.
- Existing V90 polling executes about two DB calls per active 0.3-second tick: 1,000 busy WS clients could imply about 6,667 queries/s, and 10,000 about 66,667 queries/s, before backoff. These are modeling values, not measured infrastructure capacity. Do not scale that polling design to 100k accounts without an event-driven redesign.

## Stage 2 — Company isolation, identity and exact money

- Enforce 35-table FORCE RLS, no elevated login grants, real A/B/C tenant isolation for SELECT, INSERT, UPDATE, DELETE, RPC and attachments.
- One primary account per company: database uniqueness + normalized company identifier + concurrency race handling; no forced change to multi-staff policy.
- Quote, order, delivery, invoice, payment and reversals must be integer KRW, transaction-linked, actor-approved, idempotent and audited with an atomic commit/rollback. Current real isolated PG17 login-to-quote proof does not certify full billing.
- Explicit user-approved document review; protect against malformed PDFs, spreadsheet formula injection and malicious attachments.

## Stage 3 — Reproducible and bounded load evidence

- Capacity-model CLI: python -m scripts.jw_v111_capacity. Four modeled concurrency fractions: 1%, 5%, 10%, 100% of 100k registered users. None are benchmark results.
- Local-only HTTP smoke command: JW_ENV=review JW_SCALE_ALLOW_LOCAL_PROBE=YES_LOOPBACK_ONLY python -m scripts.jw_v111_local_load --url http://127.0.0.1:8765/healthz --requests 100 --concurrency 4
- Exact loopback 127.0.0.1 healthz only, GET only, no redirects, <=500 calls, <=16 worker threads, <=3-second per-request timeout. Never direct it at customer data or a public website.
- Future evidence: real staging A/B/C login, quote→payment E2E, document OCR worker/backpressure, live WSS across >=2 instances, 100k synthetic account fixture, measured 1k/5k/10k concurrent workload, p50/p95/p99/error, CPU/memory, DB waiting/connection cap, recovery under failure and RTO/RPO. Healthy healthz does not prove any of these.

## Stage 4 — Render expansion / cost and incident guard

- Render supports paid web-service manual horizontal scaling; free web service max 1; Pro+ workspace required for automatic scaling. Each running instance is billed. https://render.com/docs/scaling
- Render PG integrated PgBouncer supports transaction pooling on paid DB only. Validate V90 SET LOCAL ROLE and transaction-scoped session_hash semantics before use. LISTEN/NOTIFY or session locks need dedicated DB connections. https://render.com/docs/postgresql-connection-pooling
- Do not attach disks to horizontally scaled web servers; shared state belongs in DB/queue/object store.
- Current $5 GitHub Actions monthly overage limit retained. Render monthly cost approval remains NOT PROVIDED; max instance count before approval = 1; no automatic scaling or paid resource creation.
- Capacity assess_scale() yields REVIEW_ELIGIBLE at most, never deployment authorization. Requires 1000+ real business/security staging samples, explicit owner+billing approvals, candidate p95 <=500 ms, errors <=0.5%, no PG waits, queue <=100 and >=20 reserved DB connections.
- Stage rollout: verified exact SHA -> encrypted backup and restore drill -> 2-instance protected canary -> company access+money+WSS/OCR tests -> owner confirmation -> monitored manual scale. Any tenant crossing, money mismatch, queue duplicate, WSS loss, p95 breach or failed restore triggers rollback.

## Four-stage acceptance status

1. Architecture controls/model IMPLEMENTED AS REVIEW; actual distributed queue, WS relay, object store and dual-server testing BLOCKED.
2. Finance and tenant control definition IMPLEMENTED AS REVIEW; full real authenticated 35-table A/B/C and settlement E2E BLOCKED.
3. Capacity simulation and bounded loopback load probe IMPLEMENTED; 100k end-to-end capacity NOT MEASURED.
4. Explicit cost, connection and approval guard IMPLEMENTED; real Render paid capacity approval, HA/restore and canary BLOCKED.

Main untouched, J1–J6 preserved, no production deployment, no customer data used, no automatic CI budget expansion. Tests require same-commit independent evidence before PASS.