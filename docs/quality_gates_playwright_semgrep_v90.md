# V9.0 independent quality gates — J1–J5 preserved

## Scope and isolation

This change adds two **new verification tools** to the exact V8.9→V9.0 review lineage. It does not change production application modules, SQL, RLS policies, authentication, dependencies used by users, or the original J1–J5 harness.

- J1 — Existing work rules and Git ancestry/baseline preserved. Checkout the original V8.9 ancestor and assert `app/main.py` has not changed.
- J2 — Existing agent execution/cost policies preserved. Both new tools run only on the isolated review branch or explicit manual dispatch; no Codex/API token needed.
- J3 — Proof-carrying acceptance: the Playwright CLI test performs HTTP fetches in Chromium against a real local FastAPI server, not a mocked JS fetch. Semgrep verifies that four injected unsafe fixtures trigger their own security rules and a safe fixture does not trigger them.
- J4 — Historical 589-case regression and PostgreSQL 17 RLS/lock CI remain separate, unchanged. Errors in the new checks must be explained and fixed, not silently marked as SKIP.
- J5 — Process cleanup, disposable SQLite demo DB in runner temp, bounded command timeouts, no production URL/credentials, and failure artifacts retained for review.

## Tooling

- Microsoft `@playwright/cli@0.1.22` (pin); automated browser actions in `scripts/ci_playwright_cli_smoke.py`.
- Semgrep `1.182.1` with **local** rules, `--metrics off`, no external rules registry, no login/API key; contract runner `scripts/ci_semgrep_security.py`.
- Workflow: `.github/workflows/jw-v90-quality-gates.yml`.

## What is actually tested

**Playwright**: real browser accesses `http://127.0.0.1:8765` over real HTTP to FastAPI in an isolated `DEMO_SEED=1` nonproduction server; asserts login screen, company A login, dashboard, logout revokes /api/me, company B login gives a *different* org, mobile viewport and navigation. Captures two synthetic screenshots as CI artifacts.

**Semgrep**: Python code static patterns for `eval(...)`, `subprocess.*(shell=True)`, unsafe Python pickle deserialization and disabled requests TLS. Each pattern must be detected in a deliberate fixture; the safe fixture must be clear. The production `app/` and `scripts/` Python code scanned; nonzero findings fail the new gate.

## Explicit non-claims

- Local SQLite demo is **not** live Supabase PostgreSQL V9.0 E2E.
- Local Semgrep rules are a narrowly targeted security baseline, **not** a comprehensive vulnerability audit or security certification.
- Tests are not automatically merged or deployed; J1–J5 acceptance requirements still apply, including distinct PG credentials, installed messenger cursor guard, live multi-session A/B/C RLS, rollback, document correctness, and protected GitHub release.
- Browser screenshot does not replace independently testing finance documents or user-reported usability.
- ChatGPT can inspect GitHub CI and findings; installing Playwright CLI in GitHub Actions does not itself install it inside ChatGPT.

**Release stance:** isolated review-only until independent CI evidence exists. Existing `main` and original V8.9 remain untouched.
