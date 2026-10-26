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
