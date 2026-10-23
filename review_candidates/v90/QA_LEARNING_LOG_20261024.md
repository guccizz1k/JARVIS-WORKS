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