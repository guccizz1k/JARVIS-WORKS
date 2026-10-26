# J team V12.5 — consolidated offline gates

Integrates a per-scope KRW reservation ledger, unknown-outcome reservation hold, five-role same-SHA evidence requirements, and A/B result classification for Playwright, axe-core, Ruff, Hypothesis and Schemathesis. The CLI is deliberately fail-closed when no evidence is supplied.

Commands:
- `python -m unittest tests.test_jw_jteam_integrated_gate tests.test_jw_jteam_retry_safety -v`
- `python scripts/jw_jteam_integrated_gate.py` (expected BLOCKED; zero model calls)

**Limitations:** a local reservation ledger is not an authoritative OpenAI billing cap, does not know provider pricing/FX and does not stop concurrent calls from other processes or projects. Never enable paid dispatch based on it. Distinct response IDs are necessary but insufficient proof of independent testing. A/B reports only classify externally supplied run data and do not execute those tools. An actual server, provider integration, browser worker and test environments remain outstanding. No user approval for paid calls, main merge, live migrations or production deployment has been given.

Before activation: approved credentials in secret manager; authoritative usage/price/FX verification; shared account-wide budget controls; reconciled provider request IDs; independent same-SHA test runner; license-reviewed pinned A/B tool versions; cost and rollback sign-off. Retain J1–J6 safeguards.
