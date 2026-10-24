# J6 — Evidence-Gated Agentic Engineering & Selective Learning
**Protocol version:** J6.0 · **Project:** JARVIS WORKS · **Status:** REVIEW / active methodology; NOT a production release.

## Role and authority
J6 groups **all methodology additions approved on 2026-10-24**:
1. Selected concepts from alirezarezvani/claude-skills: Playwright review, incident-response discipline.
2. Selected concepts from msitarzewski/agency-agents: minimal-change review, skeptical release readiness, DB restore drills.
3. Selected concepts from mattpocock/skills: structured requirements, spec dependency graph, vertical-slice TDD, evidence PR, event-driven Retro.
4. Video review: https://youtu.be/ZE4hmiGglTM (requirements/Wait What/spec/PR/Retro).
5. The JARVIS-owned implementations: root AGENTS.md + GLOSSARY.md; `jw-verified-delivery`, `jw-evidence-retro`, `jw_evidence_gate.py`, tests and CI/evidence JSON.

**J6 extends and never replaces:** J1 = execution harness and engineering standards; J2 = controlled autonomous execution; J3 = ground-truth and independently demonstrable acceptance; J4 = verified improvement based on genuine failure; J5 = operational safety/recovery. All J1–J5 control policies remain in force.

## Mandatory J6 workflow
Source and baseline proof → acceptance seam → dependency-ordered tickets → targeted behavioral **RED** before fix → minimal implementation → reproducible **GREEN** → independent code/security review (or explicitly labeled checklist-only) → original full regression where relevant → real browser/PG/restore acceptance → evidence with precise SHA and run links → Draft PR → *separate* production approval.

- Retro is triggered only on proven failure/regression, recurrent measurable cost, or user-requested review. Do not run or continuously rewrite process after ordinary PASS.
- Prefer fail-closed correctness and verified role separation to simulated progress.
- J6 uses externally inspired methods **without copying/auto-running external scripts** or handing authorization to role-play personas. **NO upstream auto-install**, no automatic updates, no arbitrary plugin execution.
- Same review-only financial, tenant and messenger acceptance boundaries apply; J6 cannot claim unsupervised production readiness or bypass existing release blockers.
- Gate semantics remain the existing **five** gates, not a fictional sixth acceptance gate; J6 is the *harness protocol version*, not extra product scope.
- Recorded PASS only for a test actually run against the exact SHA/environment. Store SKIP and warning counts; include restoration and rollback evidence.

## Next development dependency graph (as of 2026-10-24)
Authenticated Postgres roles / committed messenger guards → verified PostgreSQL SSL trust setup → actual full product API and HTTPS browser E2E → PostgreSQL snapshot/restore recovery rehearsal → independent release review. Parallel work only when tests/branches are genuinely isolated.

**Current evidence:** 589 main regression PASS on previous review head, PG17 isolated browser/message RPC PASS, J6-methodology 24 PASS on previous head. These are NOT product-wide Supabase HTTPS tests. New J6-labelled changes must be tested separately. Real production status = **BLOCKED** until the remaining acceptance work runs successfully.

**Implementation pointers:** `docs/agents/JW_CURATED_SKILLS_V90.md`, `.agents/skills/jw-verified-delivery/SKILL.md`, `.agents/skills/jw-evidence-retro/SKILL.md`, `scripts/jw_evidence_gate.py`.
