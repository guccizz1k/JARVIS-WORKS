# J team V12.7 — Fabric patterns + Gitingest local pilot across J1–J6

## Verified upstream references (2026-10-26)
- Fabric: https://github.com/danielmiessler/Fabric ; MIT license; pinned reference commit `032e464558f483717874e06d96da821bdcf41ade`. We wrote **our own** J1–J6 patterns based on the pattern-directory convention; **no Fabric binary installed and no upstream pattern text copied**.
- Gitingest: https://github.com/coderamp-labs/gitingest ; MIT license; reference commit `4e259a02fe72115bee538271622f1234a81c8e1a`. Pinned isolated Python trial: `gitingest==0.3.1` in `requirements-jteam-external-pilot.txt`; never a production dependency.

## Integration that exists in code
- `agents/team/jarvis_v1/external_intelligence.json`: seven-tool routing is unchanged for existing quality tools, with these two adjuncts, plus J1–J6 mapping and five-role assignments.
- `agents/team/jarvis_v1/fabric_patterns/jw_j*/system.md`: six locally authored pattern contracts; Fabric-style markdown compatible with its custom pattern conventions.
- `scripts/jw_jteam_external_sources.py`: strict contract loader, 5-role J1–J6 pattern composition, and optional Gitingest ingestion of *only* sanitized temporary local public/synthetic fixtures. No network URL inputs, key reading, Git credentials, SaaS uploads, database connections or private repository dumps. CLI prints hashes and timing only, not source text.
- `scripts/jw_jteam_openai_runner.py`: injects role-relevant project-owned Fabric patterns into request instructions **when a model is explicitly authorized**. Existing J team paid-call guards still apply: no execution or provider cost is implied by wiring code.
- `.agents/skills/jw-external-intelligence/SKILL.md`: instructions intended for project-local Codex and Jarvis-assisted workflows; **does not install a global ChatGPT skill or modify model weights**.

## J1–J6 operational fit
| Phase | Fabric-style prompt | Gitingest application | Actual verification gate |
|---|---|---|---|
| J1 | requirements, baselines, regression seam | public reference file inventory | engineering acceptance tests |
| J2 | bounded alternatives, dependencies | public implementation comparison | real authorized dispatch evidence |
| J3 | ground-truth and independent counterexamples | public design review fixture | independent exact-SHA acceptance |
| J4 | proven-failure causal retrospective only | public regression examples | RED/GREEN and measured prevention |
| J5 | idempotency, unknown outcome and recovery | public failure-pattern references | crash/reconciliation test receipts |
| J6 | pinned license/provenance and change risks | optional sanitized fixture summarization | A/B evidence + license/security review |

All phases and five roles are governed by `agents/team/jarvis_v1/external_intelligence.json`; `jarvis_lead` receives all six patterns while the other four roles receive their job-specific subset. No new actual model session or independent reviewer has been started.

## Tests and safe opt-in pilot
- `python scripts/jw_jteam_external_sources.py --check`: checks local patterns for all five roles, 0 API calls.
- `python -m pytest -q tests/test_jw_jteam_external_sources.py tests/test_jw_jteam_tool_routing.py tests/test_jw_jteam_openai_runner.py`: source gates, secret/symlink injection, model mock, role routing.
- In **isolated CI only**, install `requirements-jteam-external-pilot.txt` and run `python -m pytest -q tests/test_jw_jteam_gitingest_pilot.py`, then `python scripts/jw_jteam_external_sources.py --demo-local`.
- A/B measurements compare elapsed extraction times and hashed text outputs **on the same synthetic fixture**; no conclusion about better code comprehension, correctness, privacy guarantees beyond the sandbox, or production performance can follow merely from extraction success.
- Keep private GitHub source, user/company data, secrets, tokens, Supabase or Render DB content away from external ingestion sites. Do **not** pipe the digest to a paid model without separate approval and budget evidence.

## Non-negotiable restrictions
J1–J6, 5 gates, Render stage boundaries, force-RLS, exact evidence, individual API budget, no production deployment, no `main` merge and no customer-data export remain unchanged. Fabric/Gitingest pattern results are untrusted suggestions; not evidence that a test ran. Existing J team real model dispatch remains NOT CONFIGURED until separately verified.

Rollback: remove the optional manifest references, pattern injection, skill, test-only package and isolated CI workflow from this review branch; main and production remain untouched.
