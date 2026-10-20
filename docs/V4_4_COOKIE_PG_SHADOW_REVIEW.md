# JARVIS-WORKS V4.4 — Cookie-authenticated read-only PostgreSQL shadow review

**Date:** 2026-10-20  
**Baseline:** `review/v43` at `b182cec1865d9080db8d4f72485af113ba07c02d`.  
**State:** *additive review candidate; NOT deployed, NOT a production migration*.

## What V4.3 proved and what V4.4 changes

Owner-provided Codespaces evidence: **454 passed, 1 skipped, 1 Starlette deprecation warning** plus `PASS: V4.3 PostgreSQL 17 integration and isolated Docker cleanup`. This is credible evidence of V4.3's **isolated** FastAPI–PG17 lab, not the public website's PostgreSQL transition. The previous V4.3 lab uses a separate `X-JW-Lab-Session` header and synthetic records. The actual website is still `app.main` with SQLite `sessions`, HTTP-only cookie, CSRF, staff disablement, and a broad message/finance API.

V4.4 provides **one narrowly scoped, read-only slice** of the planned integration:

1. `app/pg_cookie_shadow_v44.py` supplies an **unmounted, isolated** FastAPI application whose GET-only shadow endpoint depends on the *existing* `app.main.current_user` function (unless a fake is injected into a unit test). Thus it uses the website's actual cookie verification, expiry and disabled-employee policy, and does not trust any browser-supplied org or PG token.
2. A strictly server-injected `ReviewBinding` maps a verified website org + user and thread to a separate synthetic PG org + actor and thread. The mapping is checked against the authenticated website identity, then independently checked **inside** an actual `jw_app` `jw_guard.bind_session`/RLS transaction. There is **no general-purpose production identity issuer** and the lab never accepts `X-JW-Lab-Session` from the browser.
3. SQL queries first verify an active bilateral SQLite thread and that *both* companies are verified; PG then checks an RLS-visible active thread. Both reads are bounded to 201 rows. The comparator compares exact message IDs, sequences, organizations, actor IDs, message kind and body after applying a fixture-only explicit mapping.
4. The API returns **only a comparison status and bounded counts**, not tokens, SQL, message content, private company identifiers, DSNs, or raw exception strings. Results are `MATCH`, `MISMATCH`, `UNSUPPORTED`, `INCOMPLETE` or `EMPTY_UNVERIFIED`. All but `MATCH` are explicitly non-matches. Even `MATCH` only sets `text_row_parity: true`; **`cutover_approved` is always false**.
5. `scripts/test_postgres_cookie_shadow_v44.py` is a follow-on **real PG17 + real website TestClient** lab gate: it provisions **entirely synthetic** PG companies/sessions, a temporary SQLite website DB, uses the actual `/api/login` cookie through `app.main.current_user`, validates one nonempty text row in both stores, detects tampering, blocks forged/missing cookies, then verifies independent website and PG session revocation. The parent PG supervisor owns database teardown.
6. New V4.4 launchers wrap the untouched V4.3→V2.8 historical test chain, verify all historical SHA256 manifests and provision a **new localhost-only disposable** postgres:17 Docker container. They do not mount routes into `app.main`, change a production database, or install any permanent PG runtime dependency.

**Critical safety constraint:** The in-process fixture broker in the synthetic test is NOT a trusted production cookie-to-PG session issuer. Production-grade signed identity provisioning, mapping lifecycle/revocation guarantees, full finance schema, attachment evidence, editing, order snapshots, read receipts, server-sent events, and actual browser UI remain **unimplemented**. No live B2B website traffic must be connected to these lab routes.

## Execution / evidence

Run in an isolated worktree of `review/v44`, with the normal approved disposable Codespaces resources:

```bash
bash scripts/check_v44_review.sh
bash scripts/run_pg17_codespaces_v44.sh
```

`check_v44_review.sh` checks its own manifest and runs the existing complete V4.3 preflight, including the full project pytest suite and JavaScript, PDF, Korean TTF verification. `run_pg17_codespaces_v44.sh` verifies V2.8–V4.4 immutable manifests, ensures no production flags, launches a new random localhost-only PostgreSQL 17 container, replays the **entire V4.3 PG17 suite**, then invokes the V4.4 cookie↔PG17 shadow gate. The Docker container and Python environment must be removed, even on failure.

The wrapper is fail-closed: a V4.3 failed gate prevents execution of V4.4. Source verification or missing runtime dependencies must never turn into PASS. No explicit user-side `git push`, PR creation, main merge, billable build or deployment is part of these commands. The launcher writes a disposable `pg17_v44_gate_result.txt` to its review worktree; it is not a production audit record.

## Verification status at authoring

| Gate | Status | Concrete evidence / limitation |
|---|---|---|
| 1. Code/environment | **PARTIAL** | New Python modules compile; Bash runner parses; no full private repository in authoring runtime. |
| 2. Feature and auth | **PARTIAL** | 42/42 local FastAPI TestClient/harness tests PASS for injected trusted cookie, RLS identity mapping, malformed and cross-tenant inputs, error handling and no content leaks. Real website cookie login is tested only by the pending PG17 live script. |
| 3. Regression/data integrity | **PARTIAL** | Unit tests establish nonempty parity, divergence/sequence tamper detection, fail-closed empty/over-limit/unsupported data; full 454+ project suite on V4.4 revision **NOT RUN**. |
| 4. UI/UX | **NOT RUN** | Browser not altered; Safari/desktop UX and file uploads/receipts not connected to PostgreSQL. |
| 5. Operational | **BLOCKED** | V4.4 real Codespaces PG17 execution **NOT RUN**; actual website migration and production approval blocked. |

**Data-scope warning:** This is bounded text-row parity, not full archival evidence parity. Cross-store snapshots are not atomic. The same message content with divergent attachment bytes, receipt state, edits, unsupported kinds or financial records can never authorize cutover. `text_row_parity` is *not* a whole-service correctness metric.

## Next necessary gate

After the V4.4 synthetic integration actually passes Codespaces, plan and validate an independently approved, provisioned PG auth session issuer with immutable site-principal mapping; a full schema migration with byte-exact attachments; public API/cookie/CSRF compatibility; immutable order evidence; parity across finance, receipts and edit histories; lock/resilience/load tests; backup/recovery and a reversible gradual rollout. Never switch `app.main` to PostgreSQL on the strength of the V4.4 shadow lab alone.

## Full-suite runner test import-cache failure (2026-10-20)

Owner Codespaces V4.4 regression: **493 passed, 3 failed, 1 skipped,
1 warning**. The three failures were solely in the *V4.4 wrapper unit
tests*. The synthetic fake V4.3 module was inserted into
`sys.modules`, but full-suite tests had already populated `scripts` package
attributes with the actual V4.3 module. Python `from scripts import ...`
continued to resolve the preloaded package attribute, causing the real V4.3
lab authorization gate to return 2 in a non-lab unit-test context.

The V4.4 test fixture now sets every historical lab flag expected by the
real disposable launcher and patches both `sys.modules` and the `scripts`
package attributes using pytest `monkeypatch` (automatically restored at
teardown). Extra regression tests inject a preloaded V4.3 package module,
prove its main function is *never called*, enforce prior-gate NOT RUN
propagation, and verify restoration after injected supervisor exceptions.
The actual V4.3 gate, V4.4 runtime supervisor, Docker runner, production
web application and all historical evidence remain **unchanged**.

Local V4.4 wrapper subset after repair: 9/9 PASS both in a fresh interpreter
and in a simulated preimported-module environment. The complete Codespaces
regression and real PG17 V4.4 test are still **NOT RUN** for the repaired
commit. Do not infer PG17 or cutover success from isolated mocked tests.

## V4.4 single SKIP elimination — Docker Node syntax checks (2026-10-20)

The owner's Codespaces run verified V4.4 PostgreSQL 17 integration and all
historical live database gates. One Python test remained skipped:
`tests/test_v43_manifest_and_runner.py::test_node_syntax_stdin_supported_by_real_node_when_available`.
It only looked for a native Node executable, while Codespaces already provided
a validated, isolated Docker `node:22-alpine`.

The V4.4 review preflight now supplies a private temporary `node` executable
only if native Node is absent. It supports precisely `node --check -` and
`node --check app/static/app.js`, and streams syntax input into the same
no-network, read-only, capability-free Docker image. No Docker-in-Docker path
mount is used. Failed syntax, missing Docker, failed image pull or failed
cleanup cannot produce PASS or an ignored SKIP. V4.3 files and all historical
SHA256 manifests are untouched.

Local deterministic tests: **5/5 PASS** (valid syntax, missing daemon,
engine failure, invalid JS, privilege/hash/scope guard). Additional local
Bash + real Node simulation: **4/4 PASS**. This is **not** evidence of 0 skips
in Codespaces until the owner executes the revised complete suite.
