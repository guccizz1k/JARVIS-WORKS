# J team V12.4 — uncertain provider outcome guard

Root cause: the V12.3 dispatcher retried RUNNING/BLOCKED steps. If a paid remote response succeeded but the local process crashed before checkpoint commit, this could double-bill and double-execute. V12.4 fails closed on these states and requires manual/provider-side reconciliation before another attempt. COMPLETE checkpoints remain safely skippable. This is a safety patch, **not** a production-ready provider idempotency solution.

Offline checks: `python -m unittest tests.test_jw_jteam_durable_dispatch tests.test_jw_jteam_retry_safety -v`. Real model calls, A/B trials and server deployment remain NOT RUN; do not claim PASS without executed evidence.

Follow-up: design durable request IDs, provider request status reconciliation, transactional outbox, atomic cost reservation, provider-side cap and multi-worker lease fencing. No main merge or paid execution without explicit user approval.
