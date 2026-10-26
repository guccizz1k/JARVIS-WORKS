---
name: jw-debug-root-cause
description: Investigate reproducible JARVIS-WORKS Python FastAPI PostgreSQL WebSocket JavaScript and CI errors with strict root cause evidence and controlled regressions.
---

# JARVIS-WORKS systematic debugging

J1–J6 review-only method. Never push main or claim a PASS from unrun tests; product release remains BLOCKED.

1. Establish baseline SHA, exact environment, observed symptom and one repeatable minimal failing test. Preserve error text without tokens, private files or SQL credentials.
2. Distinguish root cause categories: product bug, Python import/SDK mismatch, JavaScript state, DB/RLS privilege, transaction/locks, TLS/host, GitHub runner budget (zero test steps is BLOCKED, not code FAIL), Render limits or external dependency.
3. Reproduce deterministic RED; isolate one variable at a time; compare nearest green commit and diff. Never invent agent/subagent execution or silently repeat unsuccessful commands.
4. Implement minimum safe patch; targeted regression GREEN; extend negative cases for retry, concurrency, idempotency, recovery, auth, cross-company isolation and wrong financial totals.
5. Reuse existing pytest, Semgrep, Playwright, PG17 scripts; Ruff is an optional, separately approved future linter, not installed by this skill. Avoid unverified packages and installers.
6. Report exact SHA and observable RED/GREEN evidence, what was NOT RUN, rollback/recovery and blast radius. Trigger existing jw-evidence-retro only after a proven failure, per J4/J5.
7. Preserve all J1–J6 gates and authorization. No DB migration, loosened TLS or RLS, extra Actions spending or production changes by default. Release stays BLOCKED.
