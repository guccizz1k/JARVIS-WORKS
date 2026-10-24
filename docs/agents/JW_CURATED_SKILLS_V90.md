# JARVIS WORKS v9.0 — vetted external agent practices

**Status:** curated and project-integrated guidance, not installation of third-party execution environments. `main`/production unchanged. Sources are third-party material, treated as untrusted until reviewed.

## Exact upstream snapshots (2026-10-24)

| Source | Upstream commit (fixed for review) | Adopted idea | Decision |
|---|---|---|---|
| alirezarezvani/claude-skills | `6d2f02ea077eead1bee5411a31bcc6db5a11a70c` | Playwright test anti-pattern review, incident classification | Selective reference |
| msitarzewski/agency-agents | `4e3ac3ca6604c75113f52c695dbddcc7af928b46` | Minimal-change reviewer, reality check, DB restore proof | Selective reference |
| mattpocock/skills | `5beb35b040e3de97e54fa9e386d7e42d15c295c2` | Spec/tickets dependency DAG, TDD, PR before/after evidence, *event-triggered* retro | Selective adoption |

References: https://github.com/alirezarezvani/claude-skills ; https://github.com/msitarzewski/agency-agents ; https://github.com/mattpocock/skills .
All three were reported MIT by their GitHub metadata at review time. **No upstream scripts, dependencies, hooks, marketplace plugins, agents, or auto-updaters installed.** No copied upstream skill bodies.

### Video actually reviewed
- https://youtu.be/ZE4hmiGglTM — published 2026-10-22; captions consulted.
- 00:28 `grill-me`/grill-with-docs: batch *independent* requirements questions; for JARVIS WORKS use confirmed scope first, ask only essential unresolved constraints.
- 00:53 `wait-what`: translate implementation jargon to plain user-visible consequences.
- 01:19 `implement-spec`: tickets as a dependency DAG; safe independent work in parallel where environment permits; integration and review on protected branch.
- 02:15 `pr`: summarize changed behavior, observable red→green evidence, and rollback/blast radius.
- 03:07 `retro`: inspect *actual* failure, distinguish root cause, propose mechanical gate if useful. Never run retro continuously or rewrite guidance on every success.
- 04:06 legacy `CONTEXT.md` → `GLOSSARY.md`, `CONTEXT_MAP.md` → `GLOSSARY_MAP.md`: migration if those old files exist, with referential safety. No legacy files were present on this branch; created a new root `GLOSSARY.md` without destructive rename.

### Engineering decisions
1. Keep **J1–J5 and existing 5-Gate** as the authoritative system; the skills are methodology layers only. Do not install 400+ skills or 100+ agent personas; plugin instructions cannot override user authorization.
2. For significant changes: current SHA/branch → explicit acceptance examples/seams → dependency DAG → one red→green vertical slice → independent diff/spec/security review → existing full regression, actual PG/Chromium when applicable → evidence PR.
3. Multi-agent delegation is **conditional** on actual isolated agent/worktree tooling. Otherwise one executor plus independent review checklist; never falsely claim subagent execution.
4. Prioritize *real evidence*, not roleplay scores: Django-specific, Laravel-specific or marketing-oriented upstream persona instructions are not automatically appropriate to FastAPI+PostgreSQL.
5. Database migrations need exact preimage, transaction/lock budget, tenant boundary proof and rollback rehearsal. NO secrets in code, CI logs or agent context.
6. Controlled retrospective trigger: confirmed recurring bug / user-requested retro / actual failed gate. Human-approved action before changing global policy. Metrics must be measured.
7. PR summary must include changed files, exact commit, test run, skipped/not run tests, supported scope and rollback. A synthetic PG proof must be labeled synthetic and never silently promoted to LIVE.
8. Existing Semgrep + Playwright gates are *retained*, not reimplemented; new reviewer checks only add missing verified coverage when justified.

### Recommended task DAG for release-blocking work
```
baseline Git/DB verification
  ├─ role isolation + verified TLS material
  ├─ real independent PG runtime and session/cursor verification
  └─ source/document invariant fixtures
        └─ full desktop browser E2E + failure/recovery injection
              └─ 5-Gate acceptance and evidential PR
                    └─ separate release authorization
```
These dependencies do not assert that all tasks have completed.

### Source and scope limitations
- `claude plugin install mattpocock-skills@claude-plugins-official` and `/setup-matt-pocock-skills` are **Claude Code runtime commands**, not commands this GitHub connector can perform. They were reviewed, **not executed**.
- The setup skill prefers issue-tracker configuration and docs paths; here GitHub Draft PRs and `docs/agents/` are chosen without requiring user input or external app installation.
- Source snapshots may change; pin references before any later upgrade. Re-run license/security review before copying or executing upstream code.
- Evidence shape validation via `scripts/jw_evidence_gate.py` is a procedural check; a passing shape is **not a real integration test**.
- Keep current production-release blocker status; no main merge, Supabase cutover or production deploy follows from this guidance alone.
