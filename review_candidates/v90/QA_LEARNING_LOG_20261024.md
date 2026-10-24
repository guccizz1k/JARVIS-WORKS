# JARVIS WORKS V9.0 — evidence-led QA learning journal

Scope: isolated review candidates only; do not interpret this as model-weights training or production certification.
Cycle: **observe failing behavior → create reproducer → minimal root-cause change → adversarial counterexamples → full bounded regression → preserve evidence + blockers**.

## 2026-10-24 — browser messenger send integrity

### Baseline from connector
- Draft PR #1 base remains older `main`. V8.9 `a3783ef` and 565-test source remain inaccessible; existing V9.0 directory function is preserved.
- 38 isolated Python tests and 3 existing JavaScript tests passed before new changes.

### Reproduced failures BEFORE change
1. Three Enter sends during asynchronous FileReader led to **three HTTP send calls** from the same chat.
2. Successful HTTP response overwrote a **new text draft typed after the original send**.
3. Successful HTTP response wiped **a different file selected during the in-flight response**.

These failures were observed with `node --test test_ui_submission_integrity_v90.cjs`: three FAIL, one PASS. We then fixed the implementation and reran exactly those same tests.

### Root cause and smallest scoped fix
- Button disabled state does not block the text area's Enter event handler. Add a per-chat **in-flight token** guard set synchronously before awaiting FileReader or HTTP.
- Capture source chat and nonce. Abandon stale completion if company changed.
- Clear only the successfully sent draft/file if it is still the *same value/object* selected when sending began. Preserve any newer draft or replacement attachment.
- Do not let an earlier chat's delayed `finally` unlock the current chat's in-flight guard.
- Keep `pending.request_id` and original payload unchanged across a network retry; no new idempotency key.
- Disable composer during company selection while the chat-start API request is pending.

### Test evidence AFTER change
- `test_ui_submission_integrity_v90.cjs`: 6 PASS (three previously failing + retries + stale finalizer + original replay invariance).
- `test_stage_ui_race_v90.cjs`: 3 PASS.
- Existing isolated Python tests: 38 PASS.
- `stage_verify_v90.py`: reports **Python 38 PASS + Node 9 PASS = 47 cases**, syntax checks PASS, overall `LOCAL_STAGED_ONLY: PASS`.
- GitHub source blob exact-match checks: UI `42e0fc45aec4bfcf6b2d62f2f293db4c3ef4b85b`, new JS test `feaa59214a77cecf5f809f845555dc3d6c52408b` and runner `354fa8086629bff82c1ef5d6ec4aa3a1f0dd665e` matched local tested content.

### Knowledge transferred to future work
- Async UI handlers need **synchronous re-entry protection**, not just button disabled state.
- Completion handlers may only mutate UI state for **their originating chat and captured draft**.
- Retry keys must refer to **an immutable original payload**.
- Test old-code failure before patch, then run the same exact test on the modified source.
- Report test scope: local TestClient/VM stubs are **not** live Postgres/Chromium/565-suite evidence.

### Remaining gates — do not mark as passed
- V8.9 authoritative source + 565 historical regression: **BLOCKED / NOT RUN**.
- Draft `006_commit_order_cursor_guard_candidate.sql` real independent PostgreSQL connection test: **NOT RUN**, migration is **NOT APPLIED**.
- Two-user FastAPI live DB/WebSocket E2E and real Chromium UI: **BLOCKED / NOT RUN**.
- SQL migration history alignment, data cutover and recovery: **NOT RUN**.
- Remote GitHub Actions CI: **NOT RUN**; no workflow dispatched.
- No production deploy, no merge, no customer-data mutation, no paid infrastructure change.

**No claim of equivalence to Claude's internal learning process or capabilities is made.**
## 2026-10-24 — out-of-order edit replay & socket checkpoint invariants

### Reproductions against pre-patch source
- **4/4 FAIL**, followed by **7/7 PASS after patch**, in `test_client_edit_order_v90.cjs`:
  - Delayed v1 message snapshot overwrote already-applied v2 edit.
  - Out-of-order v2 edit downgraded already-applied v3.
  - Edit arriving before its base message was discarded forever.
  - Queued higher-version edits were not retained when the base arrived.
  - Additional positive counterexamples: equal-version idempotency, newer base superseding queued older edit, and 500-entry pending-edit memory cap.
- **3/4 FAIL**, followed by **4/4 PASS**, in `test_ws_cursor_guard_v90.cjs`:
  - Events delivered by superseded WS socket were accepted despite same chat nonce.
  - Edit replay checkpoint could move backward on delayed edit.
  - Equal timestamp but smaller edit ID could move checkpoint backward.
  - Positive case: strictly higher edit ID advances checkpoint.
- Fix: monotonic message version comparisons, bounded pending edit map, reset pending edits on company switch, drop events unless `st.socket === sock`, and compare normalized ISO edit timestamps + edit IDs before advancing checkpoint.
- The **local** `stage_verify_v90.py` observed Python **38 PASS**, JavaScript **20 PASS**, Python syntax PASS and inline JS syntax PASS, FAIL 0, SKIP 0. Repeated the complete suite **5 consecutive times** with the same 58/58 result.
- Exact committed GitHub blobs were compared with the locally executed files: HTML `a7cfa3188d954c1e493a332d02f4744fe34dfa50`, edit-order tests `3ff71a41b75fc7cfbcc9b8d856148a3fb2d69fe3`, WS cursor tests `49c22dd1258610605ebd9e45daa29125701d2c32`, harness `9a5868c4216413be1f411d94a50a6841a2fa8b01`.

### Remaining open gates (unchanged)
- The **real V8.9 source/565-test baseline** is missing. The old GitHub `main` is NOT equivalent to that baseline.
- The cursor-order SQL `006_commit_order_cursor_guard_candidate.sql` remains **not applied**; multi-connection Postgres conflict, commit inversion, isolation, rollback, throughput remain **NOT RUN**. The Supabase service role/NOLOGIN configuration has not been modified.
- Actual Chromium end-to-end, independent-tenant login/CSRF and load/performance, back-end/wire protocol E2E and production migration are **NOT RUN/BLOCKED**.
- No merge, deployment, database mutation or CI paid jobs performed.

**Scope of current PASS:** isolated browser-handler Node VM, FastAPI TestClient with stubs, synthetic concurrency model, and static syntax/contract validations. Not a live multiuser launch acceptance.

## 2026-10-24 — correcting a false-negative DB lock verification

- **Failure mechanism:** psycopg opens an implicit transaction for the privilege SELECT when `autocommit=False`; the next `connection.transaction()` can become a savepoint and will not commit or release transaction-scoped advisory locks. Therefore a correct DB would be reported as a lock failure.
- **Failing first evidence:** `test_pg_probe_transaction_scope_v90.py` failed 2/3 before the patch, passed 3/3 with the patch. Fake implementation emulates implicit-transaction and savepoint semantics; this is not a Postgres server test.
- **Minimal fix:** both independent fresh connections set `autocommit=True` before the first privilege SELECT, while each advisory lock acquisition still runs under an explicit `with conn.transaction():`.
- **Stage network evidence:** actual Uvicorn server opened a loopback HTTP port, real httpx HTTP requests and real websockets handshake exercised the isolated FastAPI routers. `test_loopback_smoke_v90.py`: 2 PASS and published; `test_loopback_transport_v90.py`: 6 PASS archive-only. Both use an explicit simulated backend and synthetic signed session; no real DB or V8.9 auth.
- **Acceptance proof:** 43 Python + 26 JS = 69 published-source cases PASS; 54 Python + 26 JS = 80 archive-complete local cases PASS. Focused 11 new/local Postgres-model + network cases repeated 3x PASS.
- **Never inflate coverage:** real PostgreSQL two-connection `pg_advisory_probe_v90.py` returns BLOCKED without approved isolated credentials; V8.9 565, browser Chromium, DB RLS E2E, remote CI are not verified.
