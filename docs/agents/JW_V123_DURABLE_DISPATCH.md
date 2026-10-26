# J team V12.3 — durable dispatch bridge (offline, review only)

This adds an injectable worker interface to the existing offline SQLite checkpoints. It does **not** connect the paid OpenAI runner, deploy a server or claim independent AI evaluation. Run `python -m unittest tests.test_jw_jteam_durable_dispatch -v`. The CLI always blocks without an authorized worker: `python scripts/jw_jteam_durable_dispatch.py --db /tmp/jteam.db --job-id demo --task demo`.

Atomic checkpoint completion and usage-event writes occur together. Resume skips COMPLETE roles. The worker must be idempotent because a process can crash after the remote call but before its local commit; real paid calls must not be enabled until provider request idempotency/reconciliation is implemented. `estimated_krw=NULL` means cost is **not measured**, not zero. Never authorize spend on this ledger alone. The reviewer is not independently attested and release remains BLOCKED.

Next: provider-side billing guard, fixed exchange-rate/pricing evidence, concurrency lease, secure receipt redaction, independent same-SHA browser/security workers, A/B trials on synthetic fixtures. No main merge or production changes.
