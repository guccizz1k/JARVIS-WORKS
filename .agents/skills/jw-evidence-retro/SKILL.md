---
name: jw-evidence-retro
description: Evidence-driven J4 retrospective for real regressions, failed gates or expressly requested review; never run compulsively.
---

# JARVIS WORKS — controlled retrospective

Trigger ONLY on: verified failed gate; reproducible defect; recurring expensive workflow mistake; explicit retrospective request.

1. Gather real failure evidence (exact SHA, observed symptom, run, environment, red/green reproduction, affected tenants).
2. Compare the nearest previous good state and current diff. Identify the narrow root cause; separate known from conjecture.
3. Check if a mechanical test/guard already exists but was not wired in. Prefer fixing coverage/execution over duplicating tests or adding generic prompts.
4. Suggest exactly one minimal prevention control for each proven cause; run a failing-before, passing-after test.
5. Assess blast radius, CI minutes, existing J1–J5 policy and costs. Do not edit global instructions or install plugins automatically.
6. Stop if issue is not reproducible: mark PARTIAL/BLOCKED and request only essential missing logs/permissions; do not simulate PASS.
7. Preserve the original code and rollback path. Integrate prevention changes only in an authorized review branch, with evidence.

Retro outcomes are reviewed by an independent reviewer where available. An AI-generated retrospective by itself proves no correction.
