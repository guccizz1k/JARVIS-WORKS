# JARVIS-WORKS V11.4 — governed Codex Skills routing

Four **project-local** reviewed, narrowly scoped workflows are appended to the existing J6 pair. They summarize user-owned procedures and the already curated external methodological references in `docs/agents/JW_CURATED_SKILLS_V90.md`; NO third-party executables, auto-install scripts, marketplace hooks or agents were imported.

Official OpenAI pattern: https://developers.openai.com/blog/skills-agents-sdk and https://developers.openai.com/api/docs/guides/tools-skills

- `jw-verified-delivery`: existing mandatory spec→RED→GREEN→5-Gate→Draft PR procedure; retained verbatim.
- `jw-evidence-retro`: existing event-triggered failure retrospective; retained verbatim.
- `jw-tenant-security-review`: company A/B/C role/RLS and RPC denial proof planning.
- `jw-trade-document-integrity`: invoice/payment integer KRW, human OCR approvals and idempotency.
- `jw-messenger-ocr-recovery`: two-instance message replay, NOTIFY fallback and OCR lease fencing.
- `jw-render-capacity-cost`: 100k registered-account scenarios, manual Render scaling/cost bounds and measured performance.

Skills are reusable **instructions**, not automatic deployment agents. Their loading depends on the local Codex runtime and task matching, and is not evidence that the agent used the skill or completed tests.

Offline verification: `python scripts/jw_skill_contract.py --root .` and `python -m unittest discover -s tests -p test_jw_skill_contract.py -v`. Test results must be observed from the actual checkout. Existing J1–J6 and broader E2E do not run automatically on this review-only branch.

Release remains BLOCKED, no `main` merge, production data or paid services changes. Roll back by reverting the isolated review commit; existing J6 pair remains unchanged.

## GitHub comparison — priority selection for present and planned workflows (2026-10-26)

**Source-pinned references used for review**, not vendored or executed:
| Project | Checked commit | License/source status | Decision |
|---|---|---|---|
| [Vercel agent-skills / web-design-guidelines](https://github.com/vercel-labs/agent-skills/tree/main/skills/web-design-guidelines) | `063bee94c3f4df8453406c830b0a7df0f2860278` | Repository-wide license not confirmed; none copied | **Adopt review criteria as self-authored `jw-ui-ux-accessibility`**; never auto-fetch the latest third-party instruction text |
| [Microsoft Playwright](https://github.com/microsoft/playwright) | `a2b65a057a78204d8411b068e1e28d0db23db44b` | Apache-2.0 | **Reuse existing project Playwright CLI/Chromium evidence**; add keyboard, focus and screenshot assertions once authorized |
| [dequelabs axe-core](https://github.com/dequelabs/axe-core) | `6b52b841461bd23345970b91ec75fdaff6bad31a` | MPL-2.0 | **Later optional dependency** for automated accessible UI checks; not added to product bundle |
| [astral-sh/ruff](https://github.com/astral-sh/ruff) | `e139fbd6e8ddd5a1653d2f2c15c1123c090a3456` | MIT | **Adopt debugging workflow guidance**; separately assess Python lint only, no global tool installation |
| [HypothesisWorks/hypothesis](https://github.com/HypothesisWorks/hypothesis) | `6359499ef994d4cf194e9c8f3733391e5f492bbd` | MPL-2.0 verified LICENSE.txt | **Later property-test candidate** for tax, integer-money and idempotent state transitions; no code imported |
| [schemathesis/schemathesis](https://github.com/schemathesis/schemathesis) | `54dac47e06061da7d320681a263987c1a554e22f` | MIT | **Later isolated OpenAPI/REST fuzz candidate**, writes possible; NEVER run on shared/production Render or Supabase |
| [grafana/k6](https://github.com/grafana/k6) | evaluation only | AGPL-3.0 | **Deferred** pending load-test budget, legal/distribution assessment and isolated environment |
| [OpenAI Codex Skills Catalog](https://github.com/openai/skills) | `49f948faa9258a0c61caceaf225e179651397431` | licenses per-skill | Use **project-local SKILL.md packaging** only; don't install whole catalogue |

**Tech fit:** JARVIS-WORKS currently serves `app/static/index.html`, `style.css`, `app.js` and additional vanilla JS modules through FastAPI; React-only and Next/Vercel deployment practices are not current priorities. Existing Semgrep, Playwright, pytest and J1–J6 checks are reused rather than cloned. Suggested later additions are dependency/compatibility/license review candidates, not deployed libraries.

**Skills total:** 2 pre-existing + 4 enterprise controls + 3 new UI, root-cause and API-test specialties = **9 project-local Codex SKILL.md entries**. The validator `scripts/jw_skill_contract.py` enforces exact filenames, frontmatter, J1–J6 release guards and prohibited executable install/push instructions; these are STRUCTURAL checks only. Main/Render/Supabase/customer records unchanged, release BLOCKED and Actions monthly USD 5 extra cap unchanged.

## Grounded source inspection — current UI baseline (no product changes)

Read-only review of the exact dependency branch on 2026-10-26:
- `app/static/index.html`: Korean `lang=ko` present; native labels, buttons and one ARIA live region present. Actual keyboard/screen-reader UX: **NOT RUN**.
- `app/static/style.css`: responsive `@media` and `:focus-visible` present; no `prefers-reduced-motion` block observed. **Improvement candidate**, requires animation inventory and visual/keyboard regression before editing.
- `app/static/app.js`: contains uses of `innerHTML`. This is an **inspection target, not a proven XSS**; trace all untrusted paths to output sinks and reuse existing injection/security tests.
- `requirements.txt`: FastAPI, Uvicorn, Pydantic, openpyxl, pdfplumber etc.; **no React/Next or Ruff/Hypothesis/Schemathesis dependency added**.
- Existing `.github/workflows/jw-v90-quality-gates.yml` includes Semgrep and existing Playwright-based browser checks; do not create duplicated expensive CI.
These are source inspections, not runtime accessibility ratings or same-SHA end-to-end results.
