---
name: jw-verified-delivery
description: JARVIS WORKS project-local controlled spec-to-delivery, test-first implementation, 5-Gate evidence and safe Draft PR.
---

# JARVIS WORKS — verified delivery

Scope: JARVIS WORKS only. This is a locally authored, reviewed adaptation of selected public methodologies; it does not delegate security or release approval.

1. Determine verified branch/SHA and known baseline; preserve existing functionality. Read `AGENTS.md`, `GLOSSARY.md`, latest J1–J5 gates.
2. Translate user goal into acceptance examples with measurable outcomes and *actual* seams (HTTP, Postgres tenant RLS, browser DOM, job runner). Reuse confirmed requirements, do not grill with duplicate questions.
3. For a multi-file change, model tickets as a dependency DAG with ready frontier; parallelize only if permitted independent worktrees/agents really exist.
4. Create a failing, behavior-observable test before implementation for bug fixes; capture the genuine RED output. Make minimum change needed for GREEN. Refactor only after independent review.
5. Review at least two axes: adherence to spec and standards/security. Include an independent skeptical reality check when feasible; differentiate actual separate reviewer from checklist-only review.
6. Execute Gate 1 syntax/deps; Gate 2 behavior; Gate 3 existing regression/rollback; Gate 4 relevant browser/visual/accessibility; Gate 5 PostgreSQL role isolation, RLS, secrets, performance and release readiness. Record not-runs truthfully.
7. Never release a system solely on synthetic DB, fake server data, local HTTP, mock browser, or SQL catalog checks. Escalate only blockers with concrete missing evidence.
8. Summarize PR in four concise parts: changed behavior; exact before→after proof; one-/two-way rollback path and blast radius; remaining FAIL/BLOCKED/NOT RUN. Commit only to review branch; never self-approve a production merge.
9. Validate the evidence file with `python scripts/jw_evidence_gate.py --check <report.json>`. It is a documentation gate, not proof of runtime behavior.

Reference decisions: `docs/agents/JW_CURATED_SKILLS_V90.md`.
