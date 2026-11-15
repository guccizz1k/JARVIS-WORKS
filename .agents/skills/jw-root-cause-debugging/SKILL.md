---
name: jw-root-cause-debugging
description: Investigate reproducible Python, FastAPI, PostgreSQL, OCR and browser defects with competing causes, regression tests and safe rollback.
---

# JARVIS-WORKS verified root-cause analysis
J1–J6 review only. PASS requires a real failing-before and passing-after observation on a cited SHA, else BLOCKED.
1. Identify symptom, scope, last-good commit, real environment and two or more competing causal hypotheses.
2. Choose a discriminating test for each hypothesis; reproduce RED and then a minimal code correction. Never suppress 500 errors or relax tenant roles to make a test green.
3. Keep immutable transactions, finance KRW precision, company RLS, auth, message replay and OCR approval intact. Use Hypothesis/Ruff/Schemathesis only after verified dependencies.
4. Inspect exception causes, concurrency, bad inputs and affected dependencies. Retry identical blocked probes no more than twice without new evidence.
5. Add a regression test and rollback; record exact SHA, pass/fail/skips, independent skeptical review and unresolved BLOCKED.
6. Invoke jw-evidence-retro only for verified failure. No main/production writes or unapproved spending.
