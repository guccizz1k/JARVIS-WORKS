# JARVIS WORKS V3.4 — Private review branch verification

**Date:** 2026-10-19 (KST)  
**Status:** LOCAL REGRESSION VERIFIED / ISOLATED LIVE POSTGRESQL 17 RLS GATE PASS (USER-SUPPLIED CODESPACES TERMINAL EVIDENCE) / NOT FOR PRODUCTION

## Source provenance

- Baseline: Library archive `JARVIS-WORKS-V2.9-V3.4-CONTINUOUS-REVIEW-CANDIDATE.zip`.
- Original ZIP SHA-256: `a9ee0f5845f2c96495b4572cf2d2772e2719a5af946fa2a44483191877a876ae`.
- Review branch is based on protected `main` commit `4fe542b9c5676ae3ee5237504426a938e422cd42`.
- Transferred 117 UTF-8 source, tests, configurations and documentation files plus 3 binary **synthetic test fixtures**.
- Every transferred Git blob hash matched the original archive: **120/120 exact matches**, zero mismatches.
- Three earlier `previews/*.webp` files already on `main` are preserved.
- Historical `proof/` screenshots and logs, other archive evidence and non-source artifacts are **not** uploaded to this review branch. They remain in the full original Library ZIP. Historical `MANIFEST_*.sha256` files describe the complete archive and cannot all be checked against this source-only branch.

## Executed local validation

- `python -m compileall -q app scripts tests`: PASS
- `node --check app/static/app.js`: PASS
- `bash -n scripts/run_pg17_codespaces_v28.sh`: PASS
- `PYTHONPATH=. python -m pytest -q --disable-warnings`: **254 passed in 108.78 seconds** (Python 3.13.5, 2026-10-19).
- Focused staff / RLS policy / PG adapter review / recovery tests: **38 passed**.
- Staff-center Chromium browser with FastAPI TestClient bridge: PASS at 1440x900 and 390x844. Does not prove real Safari or production behavior.

## PostgreSQL 17 mandatory gate — updated 2026-10-19 (KST)

- **PASS, evidenced by user's Codespaces screenshot dated 2026-10-19** on `review/v3-4-postgres-security-20261019` after `git pull --ff-only`, invoking `bash scripts/run_pg17_codespaces_v28.sh`.
- First live attempt reproduced a **FAIL** in V2.7's `messenger_receipts` RLS catalog rule, after the prior legacy RLS suite had already passed. The reviewed fix added the required explicit tenant session predicate, a regression test and updated two integrity manifests in commit `04e0b758784643ce28ec3e7e35d896792360528c`.
- After pulling that fix the user-observed output included:
  - `DB_ENGINE: PostgreSQL 17; test cluster only`
  - `PASS: isolated PG RLS authorization, spoof, replay, CRUD, child, auth and revocation tests`
  - `PASS: V2.7 PG17 live bidirectional thread isolation, actor forgery, immutable evidence, spoofing, parallel sequence`
  - `PASS: V2.8 live checksum, sender binding, message kinds, server read-time, monotonic cursors`
  - `PASS: ephemeral PG legacy + V2.7 + V2.8 integrity attacks; cleanup confirmed`
  - `PASS: PostgreSQL 17 live RLS attacks and ephemeral cleanup completed`
- This is **a genuine disposable PG17 live-run console result, not only static SQL tests**. This report relies on the displayed user-supplied screenshot; raw signed CI logs were not ingested, and the separate GitHub Actions workflow was **not** dispatched.
- The older local runner's `NOT RUN` result remains historical and applies only to the assistant's separate environment before the user provided a Codespaces PG17 runtime.
- The running FastAPI app **still uses SQLite**; these security policies are isolated test-database candidates and are **not yet integrated** with the production-facing message API. They are not a third-party security audit or certification.
- No paid cloud database, production DB, customer data, main merge or deployment was used.

## Safety / operational disposition

- `main` unmodified; no PR, merge, deployment, paid build, cloud database, real customer data, or live service change.
- The running application remains SQLite; PostgreSQL policy and adapter are review candidates, not integrated production API.
- Next: review and implement a separately scoped FastAPI PostgreSQL transaction adapter in an isolated candidate, followed by synthetic migration and rollback, live RLS-aware API integration tests, recovery and load tests. No production migration or customer data before these gates.

**Overall:** PARTIAL (GitHub staging PASS; local regression PASS with 255/255 tests after the receipt-policy fix; isolated PostgreSQL 17 legacy + V2.7 + V2.8 RLS gate PASS based on user-supplied Codespaces console evidence; real FastAPI PostgreSQL integration and production release NOT RUN).
