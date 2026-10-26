# J1–J6 unified verification execution protocol

**Project:** JARVIS WORKS / V9.0 review only
**Baseline:** V8.9 `a3783ef9f7aeeeff655f1f0ac376f6d8edf5b338`; J6 reviewed parent `efc7dbab8fed5f7291bde1512da5f11566dd9e4e`.
**Authority:** J1–J5 preserved + new J6. Five product release gates remain unchanged.

## One integrated acceptance graph

1. **J1** source integrity, existing product regression (all historical tests, no skipped tests), static JS parsing.
2. **J2** GitHub Actions dependency graph: independent full regression, product browser, PG17 concurrency/recovery and security branches; aggregation runs only if every required job succeeds. No perpetual/paid agent execution.
3. **J3** outside-in behavior/evidence: actual HTTP through Chromium, integer KRW **1309 + 131 = 1440**, tenant B 404, and real JUnit result on exact Git SHA. Artifact receipts are in-job records, NOT cryptographic attestation; proof claims must be backed by actual CI logs.
4. **J4** error-specific red→green, false PASS detector, min suite checks, negative tests; retrospective only when tests fail, with evidence and tracked root cause.
5. **J5** nonprivileged PG17 two-session RPC cursor contention, rollback/retry, actual `pg_dump` / new DB `pg_restore` fingerprint comparison and cleanup.
6. **J6** project glossary/skills, evidence-format and presence validation, draft PR acceptance and skeptical review.

### Release blocker and scope labels
- This test exercises **real SQLite document UI** and **separately real synthetic PostgreSQL messenger backend**, not a combined full production PostgreSQL financial runtime.
- It uses local HTTP and ephemeral demo logins, NOT a deployed HTTPS service.
- Third-party Semgrep includes only 4 injected rules and is NOT comprehensive security certification.
- Do **not** promote PASS from a synthetic boundary to actual customer release; `release = BLOCKED` is mandatory.
- Full customer HTTPS, TLS verify-full, Supabase full integration, representative restore and independent security review remain NOT RUN/BLOCKED.
- This workflow creates no production Supabase roles, tables, Vault secrets or customer records and never merges `main`.

### Evidence inventory
- `scripts/jw_integrated_acceptance.py --junit <report.xml>`: enforces the historical 589-case minimum AND J6 43-case minimum, required modules, zero FAIL/ERROR/SKIP.
- `scripts/ci_playwright_cli_quote_form_e2e.py`: tests real quote HTML form (invalid→valid, 2 line items, VAT preview, actual submission, tenant B denial and A re-login).
- `scripts/ci_playwright_cli_document_e2e.py`: existing financial flow/API and cross-tenant tests (retained).
- `scripts/ci_v90_postgres_browser.py`, `scripts/ci_j6_postgres_restore.py`: existing real PG17 synthetic messenger/RLS/restore checks (retained).
- `scripts/ci_semgrep_security.py`: existing security checks (retained).
- Integrated workflow aggregates the five domain receipts only after all five jobs succeed; fails closed and leaves `release=BLOCKED`.
