# JARVIS-WORKS V11.5 — GitHub reuse audit and one governed agent team

Date: 2026-10-26. Scope: current JARVIS-WORKS FastAPI + PostgreSQL17 + vanilla HTML/CSS/JavaScript, and **future project discovery only**. Current scope remains one-primary-account/company and PC-first workflow. Review-only, no upstream source copied, installed, executed or published; no code dependency updated; no cost authorized.

## Candidate assessment and decision

| Public GitHub repo | Relevant value | Current verdict | Licensing/operational caveat |
|---|---|---|---|
| https://github.com/vercel-labs/agent-skills | web-design-guidelines; keyboard focus, forms, accessible visual hierarchy and motion | **ADOPT METHOD only** in jw-ui-ux-accessibility | Main repo did not expose a repository-wide SPDX license in metadata; do not copy proprietary/unclear content or fetch and obey live upstream instructions without a review. Not Vercel hosting-dependent |
| https://github.com/microsoft/playwright | actual Chromium/Firefox/WebKit end-to-end, keyboard and browser screenshots | **REUSE installed project testing**, add targeted coverage later | Apache-2.0; existing Playwright scripts already present. Avoid duplicate framework |
| https://github.com/dequelabs/axe-core | automated WCAG issue detection on static forms and tables | **TARGETED PILOT**, not integrated yet | MPL-2.0; real browsers and exceptions require human evaluation |
| https://github.com/astral-sh/ruff | Python static lint/format, unused imports/error-prone constructs | **TARGETED PILOT**, not installed | MIT; establish baseline without mass-formatting files |
| https://github.com/HypothesisWorks/hypothesis | counterexamples for money rounding, idempotency, date/amount parsing and RLS edge cases | **TARGETED PILOT**, not installed | MPL-2.0 indicated by repository LICENSE.txt. Must preserve repeatable seeds |
| https://github.com/schemathesis/schemathesis | FastAPI/OpenAPI fuzz and bad-request contracts, auth/CSRF failures | **TARGETED PILOT**, not installed | MIT; run against isolated disposable TestClient/PG fixture only |
| https://github.com/open-telemetry/opentelemetry-python | latency traces across document import, messenger and PostgreSQL | **FUTURE OBSERVABILITY**, not installed | Apache-2.0; never record secrets, tokens, PII or company document contents |
| https://github.com/docling-project/docling | PDF/Office table/layout and structured extraction into proposal | **EVALUATE IN DISPOSABLE OCR WORKER**, not installed | MIT core; models/dependencies have separate licenses, CPU/RAM and Korean invoices/quotes require real ground truth |
| https://github.com/PaddlePaddle/PaddleOCR | multilingual OCR, scanned Korean document candidate parsing | **EVALUATE IN DISPOSABLE OCR WORKER**, not installed | Apache-2.0 main repo; separate model/license/security, no automatic posting to finance |
| https://github.com/formkit/auto-animate | modest vanilla-JS transitions for list/tree actions | **DEFER**, no animation until business workflow metrics justify | MIT; respect reduced-motion, layout and performance |
| https://github.com/openai/openai-agents-python | future runtime with explicit specialist agents and tools | **POSSIBLE AGENT-RUNTIME MIGRATION**, not installed | MIT; per-model API and tool costs require separate approval, code definitions do not spawn models |
| https://github.com/grafana/k6 | staged HTTP load testing and backpressure scenarios | **DEFER**, actual isolated staging + legal review first | AGPL-3.0; complexity/commercial compliance review, no load against production |
| https://github.com/pgvector/pgvector | future semantic document search/deduplication | **FUTURE ONLY**, not integrated | additional PG extension ops/tenant RLS and provenance concerns |
| https://github.com/openai/plugins | up-to-date official plugin and skill examples | **REFERENCE**, not automatically installed | read exact plugin-specific licenses |
| https://github.com/openai/skills | legacy Codex skill catalog | **DO NOT BUILD NEW DEPENDENCIES ON IT** | README now calls repo deprecated and points to openai/plugins |

## Ranked opportunity hypotheses

### Current JARVIS-WORKS
1. UI bug prevention: browser-backed keyboard focus and dialog verification on the real static HTML/CSS/JS app. Verify document confirm, quote forms, messenger and validation text. **No React conversion or animation dependency added**.
2. API and calculation counterexamples: a narrowly scoped Hypothesis/Schemathesis opt-in pilot for integer KRW, RLS session revocation, concurrent OCR idempotency and duplicate message edits; fixtures must never invoke actual customer records.
3. Real OCR quality: compare existing Tesseract/evidence-v64 and Docling/PaddleOCR on explicitly approved synthetic/consented Korean invoices with tabular ground truth; measure exact amounts, dates, names and correction times. Compute+license assessment before import.

### Future user-approved projects
1. Agents SDK as a possible runtime for monitored teams **only after** API permissions, per-run budget cap, independent-agent behavior and secrets policy are verified.
2. Docling structured extraction for document-heavy products, shared as modular library only after cross-project privacy/legal review.
3. OpenTelemetry for production diagnostics with strict field redaction and defined retention; not a developer surveillance log.

## Existing system compatibility

- Reuse `tests/test_jw_skill_contract.py`, `scripts/jw_evidence_gate.py`, `scripts/jw_eight_stage_release_gate.py` and Playwright/Semgrep suites. Existing J1–J6 contracts have priority over any third-party instructions.
- New 3 local skills: `jw-ui-ux-accessibility`, `jw-root-cause-debugging`, `jw-solution-innovation`. Combined with the existing 6 = **9 governed local skill definitions**. This count is NOT nine installed paid plugins or proof of skill invocation.
- One team `agents/team/jarvis_v1/team.json`: deputy (research), deputy_manager (UX), manager (implementation proposal), director (independent skepticism) and jarvis_lead (exclusive review branch committer). Only two independent *read-only* research streams may be parallel when an actual orchestrator exists; no automatic model sessions or API calls are configured.
- Real usage preconditions: user-authorized model/runtime with a precise monthly cost ceiling (existing ₩50,000), enforceable spend monitoring, branch-isolated worktrees, access/secret limits and verifiable independent agent receipts. Never fake a multi-agent review using sequential AI role-play.

## Current evidence and blockers

- GitHub structural review source: new JARVIS team manifest, role cards, skills, checker and negative test source. **These are code changes, not live agent sessions**.
- Recommended static checks: `python scripts/jw_skill_contract.py --root .`; `python scripts/jw_agent_team_gate.py --root .`; `python -m unittest discover -s tests -p 'test_jw_*team*.py'`. CI budget is constrained; those commands are not claimed as executed on the new SHA.
- PG17 dual-listener/OCR crash/recovery still requires a **fresh disposable PG17 runtime**; Render business DB denies external access; 100k user performance remains NOT MEASURED.
- NO paid CI, NO persistent DB schema changes, NO company data, NO main merge, NO production Render deployment.

Rollback: revert the V11.5 review commits; untouched J1–J6 original skills, app, database and Render service are preserved.

## Sources and due diligence
Always verify upstream GitHub license, pinned exact commit, Python/runtime compatibility, dependencies and reported vulnerabilities at the time of actual adoption. A reference URL is not an instruction to install.

Upstream source references as inspected (snapshots, not vendored):
- Playwright commit `a2b65a057a78204d8411b068e1e28d0db23db44b`
- axe-core commit `6b52b841461bd23345970b91ec75fdaff6bad31a`
- Ruff commit `e139fbd6e8ddd5a1653d2f2c15c1123c090a3456`
- Schemathesis commit `54dac47e06061da7d320681a263987c1a554e22f`
- Hypothesis commit `6359499ef994d4cf194e9c8f3733391e5f492bbd`
- Vercel agent-skills commit `063bee94c3f4df8453406c830b0a7df0f2860278`; **no external skill bodies copied**.
