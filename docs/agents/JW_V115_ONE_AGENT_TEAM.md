# JARVIS-WORKS — One Five-Role Agent Team

**One team, not five simultaneously executing agents.** J1–J6 remain mandatory. The machine-readable role definition is `agents/team/jarvis_v1/team.json`, and instructions are in its five `roles/*.md` files.

| Position | Role | Responsibility | Writable authority |
|---|---|---|---|
| 대리 | deputy | discovery, creativity, open-source due diligence | read-only |
| 차장 | deputy_manager | UI/UX, accessibility, workflows and browser evidence | read-only |
| 과장 | manager | minimum code/test candidate and cause analysis | proposal only |
| 부장 | director | skeptical independent security, finance, operational review | read-only |
| 총괄 자비스 | jarvis_lead | reconcile evidence, resolve conflicts, commit approved review branch | review branch only |

## Workflow, not role-play
1. Lead provides exact SHA and acceptance conditions.
2. Deputy and deputy_manager can research independently (maximum 2) if an **actual supported agent runtime** exists. In GitHub source alone they are role templates, not running agents.
3. Manager inspects both read-only artifacts, produces a minimal patch in isolation with explicit RED/GREEN evidence.
4. Director checks same-SHA patch and regression; a single model pretending to be five reviewers is labeled **CHECKLIST ONLY**, not independent review.
5. Lead resolves disagreement, preserves existing tests, and may create a **Draft PR only** with actual authorization and reviewer artifacts. Human authorizes merge, production and paid resource changes separately.

## Budget and security
- GitHub Actions overage $5/month, OpenAI API <=₩50,000/month. No autonomous paid calls; per-run budget enforcement unavailable, so runtime remains unconfigured.
- A role cannot elevate PostgreSQL/Supabase credentials, relax FORCE RLS, move business docs into another project, leak PII, disable security checks, or disable deployment gates.
- Offline team checker: `python scripts/jw_agent_team_gate.py --root .`. It verifies exactly one five-role team and fail-closed write/budget boundaries. Team skill router checker: `python scripts/jw_skill_contract.py --root .`. **Passing these structural checks cannot establish actual model delegation or 100k production throughput**.
- To use real Agents API / Agents SDK team orchestration later, first confirm official API access, adequate model capabilities, isolated sandboxes, spending caps and actual runtime support. Refer to https://developers.openai.com/api/docs/guides/agents-api/multi-agent and https://github.com/openai/openai-agents-python for future evaluation. Never treat descriptive role files as active background agents.

Status: ROLE DEFINITIONS IN REVIEW / TEAM_EXECUTION NOT RUN / J1–J6 PRODUCT RELEASE BLOCKED.
