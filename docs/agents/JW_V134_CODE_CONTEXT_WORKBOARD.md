# J TEAM V13.4 — guarded Codebase Memory and Paperclip integration

## Decision and upstream (2026-10-27)
- Codebase Memory MCP: https://github.com/DeusData/codebase-memory-mcp . MIT licensed; local indexed symbols/dependencies and `detect_changes`/graph tracing. CLI/installer may rewrite agent settings and start daemon/index watchers. DO NOT run an installer, overwrite codex config, auto-sync private data, or assume vendor claims are verified.
- Paperclip: https://github.com/paperclipai/paperclip . MIT licensed; company-scoped task, agent, dashboard and cost APIs, but runtime `heartbeat` can launch agent sessions. Original J5 checkpoint/role authorization MUST stay system of record. No POST/PATCH/agent invoke endpoints used.
- Graft renamed Trail-Code: https://github.com/trailhq/Trail-Code . Comparison-only; independent A/B analysis needed, no simultaneous graph tools installed by default.
- Both external upstream metrics are vendor benchmarks, not measurements for J TEAM.

## Implemented here
`agents/team/jarvis_v1/code_context_workboard.json` is a strict fail-closed policy. `scripts/jw_jteam_code_context_board.py` provides two **functional but offline** adapters:
1. `analyze_code_graph(export)`: consumes an allowlisted synthetically generated or separately approved local Codebase Memory-like graph export, validates SHA freshness and paths, traverses reverse dependencies, returns candidate impacted paths and test references. Never skips full tests on graph confidence. No actual vendor binary is invoked.
2. `project_paperclip_board(snapshot)`: consumes allowlisted synthetic or independently authorized task snapshots, confirms exactly five roles, unique task/checkpoint IDs and approval state, returns a read-only workload count. Cannot schedule tasks, mutate J5, invoke agents, connect to a real company, or turn vendor data into a production approval.
3. `advise(task, domain)`: select code context tool for relevant software changes, Paperclip board projection only for explicit team/work/agent status requests; default no tool on unrelated tasks. Trail-Code only listed as A/B comparison candidate.
4. `role_instructions(role)`: five-role extension, no new autonomous agent identities. Existing J1–J6 and monthly budgets unchanged.

## 5-Gate verification and experiment plan
- Gate 1: Python compile/import, manifest pin, dependency-free stdlib functionality.
- Gate 2: graphs with direct/reverse dependencies, test relationships, stale sha, missing nodes, unsafe paths, mixed work order selection.
- Gate 3: existing J5/work-order and full Python regression, block duplicate task/checkpoint or unapproved done.
- Gate 4: real Paperclip dashboard in actual browser NOT RUN. No screenshot or accessibility PASS claims.
- Gate 5: fail closed on tenant/company mismatch, secrets, automatic agent heartbeats, external calls or spend. Actual Paperclip network & Codebase CLI/daemon NOT RUN.
- Comparative Trail-Code pilot (NOT MEASURED): fixed public/synthetic repository, same change tasks, identical source SHA, compare missing dependencies, recall for related tests, index wall time, peak RAM, CPU, query latency, tokens & agent tool calls. Require accuracy non-regression and actual benchmarks before choosing runner.

## Privacy, costs, release
Only synthetic fixtures are permitted in CI, no original product code uploaded to third-party service, no paid models, no client/tenant records, no main merge or production deployment. Use:
`python scripts/jw_jteam_code_context_board.py --check`
`python -m pytest -q tests/test_jw_jteam_code_context_board.py tests/test_jw_jteam_universal_work_order.py`
The existing private PR CI runs these and all Python regression. Do not interpret offline fixture PASS as real installed MCP or Paperclip connector.

## Rollback
Revert this V13.4 change as a separate branch/commit; retain existing V13.0–V13.3 candidates, team manifest, J1–J6 RLS and J5 ledger unchanged.

**Graph correctness safeguard:** Full reverse dependency traversal is mandatory even for chains deeper than 6 edges; declared related tests missing from the indexed file universe fail closed. This detects candidate scope only and cannot replace complete regression. Synthetic provenance is still not vendor-execution proof.
