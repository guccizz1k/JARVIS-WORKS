# J team V12.0 — staged real-agent activation

Current J1–J6 team is **configured but no model runtime is connected**. The quality criteria in team.json are acceptance targets, not proof of expert performance.

## Gate 1 — Role contract
Five role definitions, stable machine ID, exclusive review-branch writer and independent reviewer requirements. Run `python -m unittest tests.test_jw_jteam_runtime_readiness -v`.

## Gate 2 — Model execution (BLOCKED)
Requires explicit API/provider authorization, approved per-run cost enforcement, isolated workspaces and real provider session receipts. ChatGPT subscription does not supply API billing. Do not invoke an external model just because this file exists. No credentials in repo. Verify five distinct session IDs and source SHA, plus provider logs. `python scripts/jw_jteam_runtime_readiness.py` intentionally exits blocked without receipts.

## Gate 3 — Independent verification (BLOCKED)
Director must execute independent checks against exact candidate SHA; same-model roleplay or self-asserted receipts do not prove independence. Validate RLS, auth, KRW, accessibility, regression and browser E2E separately.

## Gate 4 — external tool A/B (NOT RUN)
Playwright: existing browser baseline. axe-core: accessibility candidate; Ruff: Python lint candidate; Hypothesis: property tests; Schemathesis: API fuzz candidate. First verify licenses and compatible versions. Run on isolated synthetic fixtures, capture accuracy/false positives/time/resources before and after. No automatic dependency install, no paid CI.

## Gate 5 — user approval
Prepare Draft PR only. User approval is required before main merge, production, persistent DB migration or spending. No release approval is implied by a structural test PASS.
