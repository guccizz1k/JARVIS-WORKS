# JARVIS-WORKS V4.3 — Web ↔ PostgreSQL 17 deep connection review

**Date:** 2026-10-20. **State:** isolated review candidate / NOT PRODUCTION.
**Source baseline:** private `guccizz1k/JARVIS-WORKS`, `review/v42`, `8e6c56bd35da5eaa698a2f12081c11ac115eae94`.

## Actual scope

A separate FastAPI `TestClient` application uses the already-present V3.5 PostgreSQL adapter and V4.0 idempotent writer. On a correctly opted-in disposable Codespaces PG17 instance, it tests an HTTP request through the **real Psycopg/PG17 RLS database**. It is NOT mounted into the user's public `app/main.py`, which remains the existing SQLite web service, and does not accept its browser cookie session. A trusted website-cookie-to-PostgreSQL identity mapping is NOT IMPLEMENTED. No public listener, real customer, billing, migration, PR, GitHub write, or deployment was invoked in this work.

### Detailed HTTP and PostgreSQL failure contract

| Case | HTTP | Code | Notes |
|---|---:|---|---|
| First new message commit | 201 | — | Only after writer reports valid committed id / positive sequence |
| Same request_id, same tenant/actor/thread/body | 200 | — | Original id / sequence reused; not a second insert |
| No or malformed synthetic lab session | 401 | SESSION_REQUIRED | Never accept existing website cookie as lab auth |
| Revoked session / RLS denial / SQLSTATE P0001,42501 | 403 | TENANT_DENIED | No SQL, DSN or raw driver exception returned |
| Absent / nonmember / inactive thread | 404 | THREAD_NOT_FOUND | Denial does not reveal message count |
| Same key with changed body | 409 | IDEMPOTENCY_CONFLICT | Must never accept a duplicate as a new write |
| Unsupported, spoofed sender, malformed or blank input | 422 | INVALID_INPUT | Validation body does not echo user content |
| SQLSTATE 40001,40P01,55P03,57014,53300,57P03 | 503 | PG_RETRYABLE | Retry-After: 2; if retrying a POST, **same key and unchanged body** |
| SQLSTATE class 08, network disconnection | 503 | PG_CONNECTION_LOST | Retry-After: 5; same key if commit was uncertain |
| Database role or password configuration, 28000 / 28P01 | 503 | PG_CONFIGURATION | Backend outage, **not** user 403 |
| Unexpected 23505,23503,23514 or unknown SQL/driver failure | 503 | PG_UNAVAILABLE | Fail shut; do not manufacture a 409 or 403 |

Error JSON is deliberately `{ "detail": "human-readable text", "code": "STABLE_CODE" }` to fit the *existing* `app/static/app.js` exception toast, which displays `result.detail` as a string; using an object here would render `[object Object]`. All response paths set `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`; raw driver exceptions, secret tokens, passwords, source SQL, and DSNs are never returned. The new lab's protected URL prefix is `/lab43/...` and never collides with the web's `/api/...` routes.

### Integrity/recovery and tenant boundaries

1. Exact-once + replay checks retain **the existing PG database unique constraint**, not a Python cache; original `LabWriterV40` refuses mismatched identity, thread, and payload.
2. A separate verified transaction checks the thread participant before write; **authoritative RLS/trigger checks run again within the write transaction**, which mitigates change between preflight and commit.
3. PG reads bind session to a specific org and use database RLS; unaffiliated org C must receive a generic 404 on synthetic bilateral thread `chat_ab`.
4. New V4.3 real PostgreSQL runner additionally tests **two concurrent HTTP writes** with the same key, expecting [200, 201], identical row ID/sequence and one actual stored row.
5. The existing V4.1 test covers transactional rollback after injected failure, write retry exactly once, per-thread counter preservation, session revocation and app-factory recovery. The existing V4.2 tests cover synthetic logical restore/rollback/tamper. V4.3 wrapper **runs them first**, rather than replacing or claiming their evidence.
6. Lab flags and unsafe DSNs are rejected both at startup **and per request**. No arbitrary remote PG endpoint, superuser app connection, shared company DB, or production mode is accepted.
7. Only the known, validated message fields are returned, never extra keys unexpectedly included by a writer adapter. Read pagination is bounded and rejects negative or over-64-bit cursors.

### Immutable historical harness

The **V2.8–V4.2 existing runner and ALL versioned SHA256 manifests remain byte-for-byte unchanged**. Instead of rewriting old source integrity declarations, V4.3 adds a standalone runner wrapper:

- `scripts/run_postgres_isolation_ci_v43.py` temporarily wraps the original V4.2 callback in memory inside the disposable process, calls the unmodified V2.8 supervisor and restores the original function at exit.
- `scripts/run_pg17_codespaces_v43.sh` verifies **all 9 historical manifests** and its V4.3 manifest, provisions a new local-only postgres:17 Docker container and venv, executes prior gates then V4.3, and fails if teardown fails.
- `scripts/build_v43_manifest.py` generates only **new** `V4_3_PG_GATE_SHA256.txt`; it refuses wrong base SHA, tracked modifications, prior-manifest mismatch, existing V4.3 output, or missing new files. It never overwrites earlier manifest sources.
- `scripts/check_v43_review.sh` provides a single local code/JS/whole-repo unit-test pass after dependencies have been installed. **It does not run Docker or PostgreSQL.**

## Verification evidence, current session

| Gate | Result | Evidence |
|---|---|---|
| Gate 1 syntax/environment | **PARTIAL** | Python compileall of new Python modules and bash -n both PASS. No production runtime or psycopg installed here. |
| Gate 2 feature/error accuracy | **PARTIAL** | **77/77 PASS** with FastAPI TestClient and stubbed old-version interfaces, including 401/403/404/409/422/503 and SQLSTATE handling. |
| Gate 3 integrity/regression | **PARTIAL** | Local safe manifest builder tests, callback restoration on failure, no historical overwrite, replay and disclosure tests PASS. **Whole private repository regression NOT RUN**. |
| Gate 4 UI/UX | **PARTIAL (contract only)** | Original browser JavaScript was read on GitHub; `detail` string compatibility checked. Actual Chromium/iPhone Safari end-to-end **NOT RUN**. No UI source modified. |
| Gate 5 operations/production | **BLOCKED** | V4.3 real PG17 + Docker, public FastAPI identity/session mapping, full financial schema, security review and production go-live NOT RUN/NOT IMPLEMENTED. |

**Important scope statement:** V4.2 owner Codespaces screenshot reports V4.2 live PG17 PASS, **not V4.3**. There is no Docker CLI, PG17 server, or Psycopg installed in the current isolated file-production runtime. Running mocked HTTP tests cannot upgrade the real PostgreSQL gate to PASS. We did **not** obtain evidence of a complete full-project test run for V4.3.

## Steps for approved existing Codespaces environment

1. Start a detached worktree at the exact `review/v42` baseline SHA, protect current `main` and local changes. Add the kit's files to the existing repository at their matching paths; **never replace the repository with the kit**. Do not commit the new files before manifest preflight.
2. Run once: `python scripts/build_v43_manifest.py` → expect new `V4_3_PG_GATE_SHA256.txt` and a single PASS message. Any failure is BLOCKED and does not alter historic evidence.
3. After dependencies are present, run `bash scripts/check_v43_review.sh`. This checks all baseline manifests, new manifest, compilation, JavaScript syntax and the actual entire existing project's pytest suite. If this FAILs, do not run live PG or deploy.
4. Only with suitable free Codespaces Docker quota and explicit local testing approval, run `bash scripts/run_pg17_codespaces_v43.sh`. Expect **V4.3 real PG17 explicit PASS + historical gates PASS + Docker cleanup PASS + exit 0**. Failed or missing prerequisites are FAIL/NOT RUN, not PASS.
5. Review evidence, then consider **separately** authorized trusted session/identity mapping, production-grade migration/backup/rollout and system-level Safari verification. No operational migration until the safety and verification blockers are closed.

## Remaining known gaps, deliberately not hidden

- Original web API uses cookies, CSRF, `requestRef()` 32 lowercase hex keys, a rich `/messages/page?before=<id>` JSON envelope and returns `version` in its POST response. V4.3 uses a synthetic `X-JW-Lab-Session`, an `after=<sequence>` cursor, and a reduced response. **Front-end/API wiring is NOT compatible end-to-end yet**. Do not point the existing browser app directly at the V4.3 lab route.
- Existing website rate-limit (20 messages/minute per user), file/photos, edit window, receipts, order snapshots, directory, employee lifecycle, verified enrollment, all quote/order/invoice/payment transactions and their PostgreSQL migration are out of this lab gate.
- Operational transaction pooling, staged encrypted backups, independent PG dump/restore, network browser, WAL recovery, performance and service RTO/RPO need separate real test evidence.
- A POST committed before a connection failure must be retried with its **original idempotency key and identical body**. The current browser regenerates the key on a new button submission, so browser-side retry state persistence still requires an explicit reviewed enhancement **before any real migration**.
