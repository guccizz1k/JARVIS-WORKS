# J TEAM V13.1 — four optional skills / exact release boundary

Base: V13.0 Draft PR #46, latest head a831bb6ebead17923549194faf11879581cb1e7a. This is an additive review-only candidate, no main merge.

- Penpot: offline token parity bridge; remote MCP session NOT CONNECTED, browser pixel verification NOT RUN. Official Penpot MCP moved into penpot/penpot, legacy penpot-mcp repo archived; only design exports accepted.
- Whisper: transcript structure/digest validator; genuine acoustic transcription, diarization, accuracy benchmark NOT RUN.
- Ollama: local loopback /api/chat client with explicit dual approval and bounded synthetic input, no automatic model downloads. Actual runtime, independent 5 model performance and GPU baseline NOT RUN.
- n8n: plan-first fixed local review-only webhook, no third-party URLs or customer data. Actual installed n8n service and downstream effects NOT RUN. n8n license restrictions require separate legal review for commercial embedding.

Routing: agents/team/jarvis_v1/capability_routing.json; .agents/skills/jt-*; scripts/jw_jteam_optional_capabilities.py. Existing Fabric/Gitingest, Playwright, axe-core pilots, J1–J6 guard, J5 checkpoint, V13 media generator and all roles are left unchanged.

Run python scripts/jw_jteam_optional_capabilities.py --check and python -m pytest -q tests/test_jw_jteam_optional_capabilities.py tests/test_jw_skill_contract.py. The existing private PR guard additionally runs every test_jw_jteam*.py and test_jw_*.py. This checks fixture logic, not actual external applications.

5-Gate evidence: G1 metadata/AST/import; G2 positive and adversarial scenarios; G3 existing regression/guard; G4 design token only, full browser/Penpot NOT RUN; G5 permission, localhost/no-secret/no-cost fail-closed, external runtime BLOCKED. Keep owner API spend <=50,000 KRW/month and Actions extra <=$5/month. No production deploy, no main merge, no customer data movement, no OpenAI API calls.

Exit criteria: exact-SHA CI PASS on reviewed branch, recorded failure/skip counts, separate opt-in connected app tests and actual comparative benchmarks. Structural PASS is not integration acceptance.
