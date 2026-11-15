---
name: jw-render-capacity-cost
description: When planning Render deployments, sizing, database connections, 100000 registered company accounts, horizontal scaling, OCR throughput, reliability or infrastructure costs.
---

# Render growth and spending gate

J1–J6 subordinate project skill. Review only, `main` unchanged. Release BLOCKED without independent evidence and owner approval.

1. Separate 100000 registered company accounts from simultaneous browser users and persistent WebSocket connections; list explicit concurrency, HTTP, OCR and DB pool assumptions.
2. Verify per-instance statelessness, durable document store, job queue, tenant RLS and cross-instance message wake/replay before recommending horizontal scaling.
3. Count real PG connections per worker/instance; verify `SET LOCAL ROLE` and transaction-local session safety with PgBouncer under an approved temporary fixture.
4. Require actual staged 1→2-instance tests and p50/p95/p99 latency, errors, CPU, memory, queue pressure, backup restore and RTO/RPO. A forecast or healthz test is NOT MEASURED production capacity.
5. Retain **GitHub Actions $5/month additional spend ceiling** and **OpenAI API ₩50000/month cap**. Render paid budget remains unapproved; no automatic billing, workflow dispatch, scaling, deployment or secret changes.
6. Require explicit owner cost and rollout authorization, measured PASS/FAIL/SKIP evidence and reversible canary. Status remains BLOCKED when review controls cannot be satisfied.

Existing seams: `scripts/jw_v111_capacity.py`, `scripts/jw_v111_readiness.py`, `ops/jw_v111_scale_policy.json`.
