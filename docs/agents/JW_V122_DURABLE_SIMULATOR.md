# J team V12.2 — durable offline simulator

Review-only SQLite task/checkpoint implementation for J1–J6. Does not invoke AI, create server, use secrets, or run paid API. Simulated checkpoints are **not** agent reviews.

Run offline: `python scripts/jw_jteam_durable_simulator.py --db /tmp/jteam_sim.db --task "synthetic task"`
Repeat with `--job-id` to test idempotent resume. Different task with same ID fails closed. Unit tests: `python -m unittest tests.test_jw_jteam_durable_simulator -v`.

The existing OpenAI runner remains disabled by default. Before actual paid execution: durable token usage ledger, atomic budget reservation with authoritative model prices/FX, provider-side spend guard verified, secret storage, real role-separated model sessions and independent browser/security test workers. No live DB or production use. No main merge without user approval.
