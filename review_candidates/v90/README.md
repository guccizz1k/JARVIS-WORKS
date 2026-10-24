# JARVIS WORKS V9.0 — DRAFT REVIEW ONLY (2026-10-23)

**Integration verdict: PARTIAL. Release: BLOCKED.** This branch has NOT been merged or deployed.

## Proven source and protected boundaries

- Live GitHub `main`: `4fe542b9c5676ae3ee5237504426a938e422cd42` (older than offline V8.8 source).
- V8.9 source archive `JARVIS_WORKS_V89_AUTH_INTEGRITY_REVIEW.zip` and local commit `a3783ef` were not accessible through connected GitHub or Library search. Never overwrite a newer V8.9 application with this old GitHub `main`.
- Existing `app/main.py`, authentication, business documents and SQLite routes are untouched by this PR.
- All changes remain under `review_candidates/v90/` and require explicit reconciliation before being wired into the application.

## Actual connected PostgreSQL staging work

- Supabase project `jarvis-works-dev`, PostgreSQL 17.11, schema `jw_dev`.
- Confirmed existing `search_messenger_companies_v90` directory function; do not recreate as a new feature. See `001_jw_dev_secure_messenger_directory.sql`.
- Added **6** existing-schema RPCs (stored in `002_jw_dev_messenger_rpc.sql`):
  - `v90_start_chat` — immediate active conversation; no approval requirement.
  - `v90_send_text` — transactionally sends text and optional one <=5MiB attachment; `(sender_org,request_id)` idempotency, payload collision guard.
  - `v90_mark_read` — monotonic organization read cursor.
  - `v90_edit_text` — original sender only, <=30-minute window, optimistic version lock and immutable edit history.
  - `v90_sync_messages` — cursor-paginated message snapshot and attachment metadata for reconnect.
  - `v90_sync_edits` — timestamp/edit-ID-paginated edit log for reconnect.
- Procedure execute permissions are revoked for `PUBLIC`, `anon`, `authenticated` and `service_role`; only `jw_app_dev` may execute them. The existing `NOLOGIN` restriction was **not changed**.
- No real tenant/customer data existed in `jw_dev` during testing. Synthetic A/B/C fixtures were executed in a SQL transaction and **ROLLED BACK**. A post-test count confirmed 0 organizations/users/sessions/conversations/messages/edits/attachments.
- 35 tables have FORCE RLS; 40 existing RLS policies confirmed. Existing immutable-history trigger prevented DELETE (SQLSTATE 23514). The first test harness erroneously anticipated SQLSTATE 42501 and was corrected; retest passed.
- Run `003_messenger_rpc_regression.sql` only on the dedicated development schema as a rollback-only test. Tests: A/B chat start, two sends including attachment, replay idempotency, collision, B sync, C isolation for messages + edits, invalid session, monotonic receipt, edit/version conflict, 31-minute expiration and DELETE prohibition.

## Isolated FastAPI review adapter

- `pg_messenger_bridge_v90.py`: opt-in router; **not mounted** in any operating app. PostgreSQL SQL is parameterized; each request uses a transaction-local `jw.session_hash` GUC. Explicit `VerifiedSession` dependency must be implemented by the genuine V8.9 login + CSRF middleware.
- `test_pg_messenger_bridge_v90.py`: **14 passed** locally using FastAPI TestClient and mocked connection/gateway. Source + test GitHub blobs were compared byte-for-byte with locally tested files.
- This is HTTP request/response and reconnect *polling* support, **not real-time WebSocket delivery**. Attachment input is base64 JSON, not final UI/multipart integration.
- **No actual PostgreSQL FastAPI HTTP E2E** is claimed. `jw_app_dev` and separate auth roles remain NOLOGIN; no independent app-user live DB connections were obtained. Live psycopg login and real WebSocket tests are BLOCKED or NOT RUN.

## Required blockers before release/integration

1. Recover authoritative V8.9 files and reconcile changed auth, routes, session hashing and tests. No assumptions about the V8.9 source.
2. Obtain appropriately approved non-superuser PostgreSQL connection infrastructure; never turn privileged `postgres` into the production app role. Validate SSL verify-full and separate tenant sessions.
3. Implement actual ASGI mounting, media storage/retention and content validation, WebSocket real-time fanout + reconnect replay, browser UI and per-company end-to-end testing.
4. Test independent PostgreSQL connections under message-send and payment contention. Existing synthetic serial transactions are not a substitute.
5. Prepare a source-aligned migration and data mapping/cutover rehearsal with backups, row counts, foreign keys, hashes and rollback. Development DB has **zero customer rows**; no production/customer migration occurred.
6. Run V8.9's exact 565-test regression, full FastAPI PostgreSQL E2E and browser scenarios. This turn did **not** rerun 565.
7. Supabase advisor: 7 auth/security tables have FORCE RLS without policies (intentional deny-by-default requires review); 36 unindexed FK notices require performance triage. No RLS/auth bypass or index-wide DDL was applied.
8. No GitHub main merge, production deployment, credentials enablement, customer-data mutation or paid new infrastructure.

## Validation gates

1. Syntax/SDK: **PASS** isolated bridge compile, GitHub blob integrity, 14 isolated TestClient tests.
2. DB function: **PASS** transaction-only staging A/B/C SQL regression.
3. Legacy 565 regression and new live PostgreSQL integration: **NOT RUN** (authoritative V8.9 source inaccessible).
4. User browser/real-time push UX: **NOT RUN**.
5. Security staging RLS/roles: **PARTIAL** (verified grants, FORCE RLS, synthetic isolation); operating SSL/tenant connections/concurrency/rollout: **BLOCKED**.

Do **NOT** merge until all missing gates receive independent evidence.

## V9.0 next-stage increment (2026-10-23, review-only)

### New in this increment
- **Actual Supabase dev RPC**: `v90_download_attachment(connection_id,message_id)`, restricted to the two verified active-chat companies, with a valid unexpired session; revoked to anon/authenticated/service_role/PUBLIC. Saved as `004_jw_dev_attachment_download.sql`.
- **Actual dev A/B/C test**: A and B download the same file, C cannot download, and an invalid session cannot download. `005_attachment_acl_regression.sql` was executed then ROLLED BACK.
- **FastAPI**: attachment download route with SHA-256 integrity verification, octet-stream disposition, no-store cache and nosniff. Prior API routes kept intact.
- **WebSocket**: new opt-in `pg_messenger_realtime_v90.py` (no production mount), server-side subscription authorization + exact Origin allowlist, cursor replay, edit replay, backpressure, periodic DB-based session rechecking, and forced close on revocation.
- **Korean desktop-oriented messenger UI**: `messenger_stage_v90.html` with directory search, immediate chat, file attachment, download, read receipts, WebSocket reconnection, and safe DOM rendering. **Not integrated into legacy app**.
- Local isolated FastAPI/ASGI WebSocket tests: **26 PASS, 0 FAIL, 0 SKIP**, using mocked gateway; JavaScript syntax parsed in Node. Exact local/GitHub blobs verified for Python and HTML stage files.
- Live PostgreSQL ACL tests: PASS with rollback. No persistent test rows. Latest database inventory **35 FORCE RLS, 40 policies, 45 user triggers, zero tenant/message/attachment rows**.
- Browser E2E: **BLOCKED**. Chromium launched, but loopback ASGI navigation failed with `net::ERR_BLOCKED_BY_ADMINISTRATOR`. No attempts to circumvent. HTML was *not* verified visually/through a real browser.
- Independent app-role PostgreSQL connections, V8.9 original archive `a3783ef`, full 565 regression, actual WebSocket-to-Postgres E2E, migrations/cutover and production release remain **BLOCKED/NOT RUN**.
- NOTE: websocket uses authorized periodic PostgreSQL reads over an ASGI WebSocket; this is **not** Supabase Realtime Broadcast configuration and does not prove real cross-process fanout or throughput.
- Supabase security advisor still reports 7 FORCE RLS auth/system tables with no SELECT policies; this is deny-by-default and must be reviewed against the V8.9 auth design before altering.
- CSP integration for inline UI JS, production attachment scanning and multi-process performance remain unresolved. Do not enable privileged credential workarounds.

**Integrate only after V8.9 authoritative source recovered and complete regressions pass. No merge, production deploy or paid resources.**


## 2026-10-23 continued staging work (subsequent turn)

**Source-integrity baseline:** Verified Draft PR remains open; authoritative V8.9 archive / local commit `a3783ef` is still inaccessible. Production application and GitHub `main` are untouched.

### Verified additions

- `messenger_stage_v90.html`: fixed asynchronous chat-change race (file-read and in-flight HTTP send) to prevent posting to or clearing the new conversation; fail-closed on WebSocket 1008 and stop reconnecting after 6 unsuccessful attempts. Manual reselect resets the retry budget. The browser UI remains an **isolated, unmounted staging artifact**.
- `test_stage_ui_race_v90.cjs`: Node VM directly executes the actual UI handler source. **3 PASS** covering chat switch before upload, chat switch during HTTP send response and WS denied/limited retries. `node --check` also passed.
- `migration_integrity_v90.py`: optional **read-only** SQLite vs `jw_dev` row-count/SHA-256 comparator, with explicit table whitelist, row cap, byte normalization and no row content in report. `test_migration_integrity_v90.py`: **8 PASS** (synthetic/mocked target only). An actual V8.9 data migration and read-only live PG comparison are NOT RUN. Optional psycopg dependency is not installed in the available local environment; never claim a live migration result.
- Existing local HTTP/WebSocket pytest contract regression **26 PASS**. Combined independent local stage checks: **34 pytest PASS + 3 Node PASS = 37 PASS**, **0 FAIL** on selected commands. This is NOT the missing V8.9 suite of 565 tests.
- SHA-1 Git blob comparisons confirm GitHub staging files exactly match locally executed source/tests.
- Chromium Playwright local-loopback navigation returned `ERR_BLOCKED_BY_ADMINISTRATOR` in the test environment. Three browser navigation attempts failed due to this environment restriction; it was NOT circumvented. Browser E2E remains **BLOCKED**, not PASS. The temporary isolated Playwright attempt is not part of the passing unit-test artifact.
- Supabase SQL query was independently **BLOCKED by tool safety review** on this continued turn; do not reroute or bypass the check. No additional live DB test can be claimed. The previous turn's attachment ACL and SQL synthetic transaction evidence remains the latest successful DB validation.

### Open launch-critical engineering risks

1. **Commit-order cursor risk:** `nextval()` yields a sequence before a message transaction commits; two independent concurrent writers could commit out of order and make a late-committing lower cursor invisible to cursor-only reconnect. Must validate and address with serialization/transactional committed ordering before launch. **CONCURRENCY TEST NOT RUN**.
2. A timestamp+edit-id edit cursor likewise needs independent-connection race review. **NOT RUN**.
3. WebSocket uses database polling (two queries every 300 ms/connection by default), not a measured scalable event-broadcast service. Load, recovery and latency NOT MEASURED.
4. PostgreSQL login roles remain `NOLOGIN`; genuine user/tenant sessions, SSL verification, payment collision tests and browser end-to-end integration remain BLOCKED/NOT RUN.
5. The genuine V8.9 archive, source files, 565-suite and data migration source are still absent. Do not merge or deploy this PR.

## 2026-10-23 22:08 KST — Cursor commit-order review candidate (THIS TURN)

### Direct implementation

- `006_commit_order_cursor_guard_candidate.sql` adds the same **transaction-scoped advisory lock per conversation** inside `v90_send_text` and `v90_edit_text`. Send acquires the lock before `nextval('jw_dev.messenger_seq_v90')` and message insertion; edit acquires it before update + immutable edit history insertion.
- To close timestamp tie-loss in the existing `(edited_at, edit_id)` cursor, the edit function computes `greatest(clock_timestamp(), max(previous chat edit timestamp) + interval '1 microsecond')` **under the conversation lock**. This avoids equal-time UUID ordering inversions even when system clock stalls; currently O(chat edit history), pending a performance benchmark/index redesign.
- The SQL file is a **staging review candidate only** and has NOT been executed against the connected Supabase database. The installed `jw_dev` functions retain the previous behavior until the approved, source-reconciled migration executes. The prior Supabase SQL safety-review restriction was respected.
- The extension is additive, schema-qualified and retains verified-company session checks, replay idempotency, <=30-minute edit window, immutable history, dedicated `jw_app_dev` grant, and restricted public-role execution.

### Evidence from this run

- `test_commit_order_model_v90.py`: **4 PASS**, deterministic concurrency simulator: reproduces original lower-cursor late-commit skip; per-chat lock prevents skip; distinct chats can progress independently; frozen-clock edit timestamps strictly advance. 5 separate repeats of the same four model tests passed.
- The full available *staged* local suite: **38 Python pytest PASS + 3 JavaScript Node tests PASS, 0 FAIL**, with Python compile PASS. The 38 include existing HTTP / WebSocket mock / data-migration comparator tests + four new concurrency-model tests. These are not live PostgreSQL independent-connection tests.
- Actual newly committed SQL was inspected via GitHub and passed **10 structural ordering/security invariants** (authorization before lock, advisory lock before sequence and writes, same namespace for send/edit, monotonically increasing edit timestamp, permissions preserved).
- Exact GitHub SHA-1 blob for the committed model test matches the tested local file: `1cf4bb893cb580d447badf6548e2b8c5da35bf3e`.
- PostgreSQL 17 official advisory-lock semantics were consulted. An actual SQL parser, SQL apply, independent two-connection execution and browser E2E **were NOT RUN**, so the new patch is not a production-verified fix.

### Blocking acceptance tests

1. Recover authoritative V8.9 commit/package and integrate without modifying older `main`.
2. Get an approved non-superuser PostgreSQL connection and run independent **two-transaction** A/B send/edit + rollback/idempotency/visibility tests; verify deadlocks and lock timeout handling. Do not bypass denied Supabase SQL operations.
3. Benchmark the O(edit history) max-timestamp query at realistic chat volumes; prefer an indexed per-chat edit ordinal if too slow.
4. Re-run historical 565 and all real API/browser E2E; operating deploy remains unapproved.

**Judgment: DRAFT PATCH + ISOLATED MODEL TESTS PASS; LIVE DATABASE CONCURRENCY BLOCKED; OPERATIONAL RELEASE BLOCKED.**


## 2026-10-24 — failing-first UI/send QA extension

- Found **three reproducible failures on the original staging HTML**: repeated Enter while reading a file issued three sends; a delayed successful response erased a newly typed draft; replacing a file during a request lost the newly chosen attachment. Initial failure proof: 3 FAIL / 1 PASS in a new adversarial test file.
- Applied scoped `messenger_stage_v90.html` changes: synchronous in-flight guard, captured chat nonce, immutable retry request key/payload, conditional clearing only of the original draft/file, and stale completion isolation when changing chats.
- Extended counterexamples for retries after timeout and an old chat's `finally` during a new chat send.
- **Actual local smoke proof:** Python pytest **38 PASS**, Node browser-handler VM tests **9 PASS**, FAIL 0. Python compile and inline JS `node --check` PASS. `stage_verify_v90.py` repeats those checks with a machine-readable result and keeps live DB / browser E2E / 565 historical tests explicitly NOT RUN.
- GitHub blobs for UI/new tests/runner match files tested locally, recorded in `QA_LEARNING_LOG_20261024.md`.
- **Important not done:** authoritative V8.9 source reconciliation, any SQL write/apply of the cursor guard, independent Postgres two-connection contention, live tenant API, actual Chromium, historical 565 regression, formal migration, production deployment. These gates remain BLOCKED/NOT RUN.

## 2026-10-24 — high-assurance replay/edit client integrity

- New UI bug class resolved in isolated `messenger_stage_v90.html`: stale message snapshots cannot downgrade edited text; edits received before base messages are queued and applied; pending edits are bounded to 500 and reset on chat switch. Current source hash: `a7cfa3188d954c1e493a332d02f4744fe34dfa50`.
- WebSocket guard rejects superseded socket deliveries even when chat nonce is unchanged, and normalizes edit timestamps before progressing the `(edited_at, edit_id)` reconnect cursor. Older/equal cursors cannot roll back the resume position.
- Failing-first evidence: 4 failing edit-order scenarios before changes, 3 failing WS cursor scenarios before changes. Post-change dedicated test files: **7 PASS + 4 PASS**. Existing 38 Python + 9 JS checks stayed passing.
- Local fail-closed stage harness: **38 Python + 20 JS = 58 PASS, 0 FAIL, 0 SKIP**, source syntax passes. **Five complete consecutive runs** returned the same result. GitHub blobs of the actual files match locally verified sources. Tests are Node VM / FastAPI stub + synthetic model, not real-browser/live-DB E2E.
- All deployment gates unchanged: V8.9 latest commit/archive unavailable, historical 565 tests not run, `006` SQL concurrency guard unapplied, multi-connection PostgreSQL and Chromium end-to-end blocked/not run, remote GitHub CI results unavailable. No merge, deployment, or customer-data mutation.

See `QA_LEARNING_LOG_20261024.md` for detailed root-cause evidence.


## 2026-10-24 — reconnect lifecycle and isolated DB acceptance gate

### Demonstrated failure and patch
- Actual previous staging HTML was tested with `test_ws_reconnect_lifecycle_v90.cjs`: **5 FAIL / 1 PASS**. The stale socket `onclose` scheduled duplicate reconnects; stale `onopen` reset retry state; open-then-immediate-close reset retry attempts indefinitely; stale `onerror` displayed misleading user notices.
- `messenger_stage_v90.html` now checks `st.socket === sock` alongside chat nonce on open, close, error and delayed timers. It resets the reconnect budget only after a received server heartbeat rather than TCP/WebSocket open. Same six tests **6/6 PASS**, and previous policy-closure test adapted to represent the current socket.
- Original local regression suite with these changes: **38 Python + 26 Node = 64 PASS / 0 FAIL**, syntax checks PASS; all four changed source/test Git blobs match locally verified file hashes.

### Next operational gate prepared
- New `pg_advisory_probe_v90.py` (GitHub blob matches locally tested file) is a **read-only-in-terms-of-table-data**, opt-in check for transaction-scoped Postgres advisory locks using **two independent DB connections**. It denies superuser/BYPASSRLS roles, verifies competing chat lock, unrelated chat progress, and release after commit. Requires `JW_V90_ISOLATED_PG_APPROVED=yes` plus an approved isolated `JW_V90_ISOLATED_PG_DSN` and psycopg; does **not** test messenger RPCs end-to-end.
- Its five local fake-driver contract tests passed. Source archive contains test file, but the GitHub upload of that test file was **blocked by a tool safety gate** and is **NOT published to this PR**. Consequently this PR's existing `stage_verify_v90.py` runs the 64 available tests, not the full 69-case local candidate suite.
- Local full candidate suite including unpublished probe tests: **43 Python + 26 Node = 69 PASS / 0 FAIL**, repeated three times. The actual DB probe terminated with `BLOCKED / NOT RUN` (no approved isolated DSN and no psycopg driver).
- PostgreSQL server package was not installed and the local package repository update timed out. No remote SQL mutation, remote permission change, bypass or production connection was attempted.

### Unresolved launch blockers
V8.9 original commit/archive and 565 historical tests missing; actual independent Postgres messenger-RPC concurrency A/B/C E2E NOT RUN; `006_commit_order_cursor_guard_candidate.sql` UNAPPLIED; Chromium browser E2E blocked; GitHub remote CI statuses absent; no merge, deployment or real customer changes. **PARTIAL / NOT RELEASE-READY**.

## 2026-10-24 — NOT RUN gate triage and actual socket-level evidence

### Defect found, reproduced, fixed, published
- `pg_advisory_probe_v90.py` previously queried current-user privileges before entering `connection.transaction()` on a default psycopg connection. That first SELECT begins an implicit outer transaction; subsequent transaction context becomes a SAVEPOINT, which fails to release transaction-scoped advisory locks when the context exits. The probe could falsely report an unlock failure against a correct PostgreSQL server.
- New `test_pg_probe_transaction_scope_v90.py` models psycopg's implicit-transaction/savepoint behavior. **Before patch: 2 FAIL / 1 PASS. After patch: 3 PASS.**
- Fix sets `a.autocommit = b.autocommit = True` on the fresh DB sessions **before** the privilege SELECT. The actual lock assertions remain inside explicit `with conn.transaction():` blocks; nonprivileged-role check and no-customer-data policy retained.
- Published source and new regression test Git blob SHA-1 match files executed locally: probe `a6065ec499b8418d616f29fae8502bbce8f8adb7`, test `fe30ea9789cc01cccf1f1b0cd395d27b8c4607ac`.

### Previously NOT RUN network transport gate: partially unblocked
- Added `test_loopback_smoke_v90.py`. Executed an actual **Uvicorn HTTP TCP server on 127.0.0.1**, `httpx` real HTTP requests and `websockets.sync.client` real WebSocket upgrades.
- Synthetic signed session-cookie validation, CSRF failures, A/B authorized delivery, C denied, WebSocket reception and reconnect replay: **2/2 network smoke cases PASS** in the published GitHub source.
- Also ran a **local archive-only extended suite** `test_loopback_transport_v90.py` with **6/6 PASS** including attachment bytes, session forgery, websocket Origin checks and cursor replay. Extended suite was not published on GitHub, but is preserved in the review ZIP.
- These use an in-memory **simulated gateway**; they do NOT establish genuine Supabase PostgreSQL RLS, actual V8.9 authentication, independent Postgres connections or full real-browser E2E.

### Repeatable results, separated by source location
- GitHub-publication-equivalent staging runner executed locally against published source set: **43 Python + 26 Node = 69 PASS**, syntax PASS. (PR contains the published smoke and implicit-transaction tests.)
- Full local review pack additionally includes 5 previous fake-driver tests and 6 extended loopback cases: **54 Python + 26 Node = 80 PASS**, syntax PASS, 0 FAIL, 0 SKIP.
- Focused 11-case transaction-scope + HTTP/WebSocket suite repeated **3 complete times**, each **11 PASS**.

### Still unresolved / cannot safely label PASS
- `pg_advisory_probe_v90.py` actual two-connection run returned **BLOCKED / NOT RUN** because `JW_V90_ISOLATED_PG_DSN` and required explicit isolated-stage approval were absent; psycopg not installed. No privileged login, database mutation, bypass or deployment attempted.
- The `006_commit_order_cursor_guard_candidate.sql` patch remains **UNAPPLIED** and its live independent-connection transaction ordering/tenant isolation is **NOT RUN**.
- V8.9 authoritative local commit `a3783ef` and its archive were **NOT FOUND** in currently accessible GitHub/Library; historical 565 regressions NOT RUN.
- Actual Chromium browser E2E remains BLOCKED by environment administrator policy; no workaround attempted.
- GitHub Actions remote CI does not report statuses; no Actions workflow/paid job has been started.
- **Disposition remains DRAFT / PARTIAL.** Existing `main`, production, users and customer data remain unchanged.


## 2026-10-24 — Browser UI gate partially unblocked and UUID compatibility fix

- Current local V9 stage harness rerun: **54 Python PASS + 26 Node PASS = 80 PASS**, no failures. Historical 565-suite has NOT been recovered or run.
- **Real headless Chromium 144** rendered the exact standalone `messenger_stage_v90.html` via `page.set_content` without navigating to restricted localhost URLs. Browser API and WS were **synthetic stubs**. Expanded **9 Chromium DOM tests PASS**: search/layout, click-to-chat, text send, Enter duplicate prevention, company-switch stale event protection, edit-before-base ordering, PDF file-data encoding, HTML injection rendered as text, mobile horizontal overflow. Separate published compact `test_chromium_gate_v90.py`: **4 PASS** (a subset); opt-in runner: `python -m pytest -q test_chromium_gate_v90.py`.
- Reproduced a browser-only exception in a non-secure context (about:blank) when send called `crypto.randomUUID()`. After three failing targeted checks, added **CSPRNG-backed UUID v4 fallback using `crypto.getRandomValues`**. Chromium test no longer polyfills `randomUUID`; all 9 UI cases PASS. The change preserves the original `randomUUID` path on HTTPS.
- Exact GitHub HTML SHA-1 blob `6580beec7b493d980421a495eb8e971f6c2b3f46` matches the locally executed HTML, and published compact browser test blob `f1fdbd546aa79dabd3a49646c8293b433d7ca74e` matches the locally executed test file.
- Screenshot of real DOM rendering was captured with **synthetic chat data**; it is not evidence of a deployed application.
- **Status classification:** Chromium DOM/JS behavior **PASS with mocked services**; actual deployed server navigation and browser-to-FastAPI-to-independent-PostgreSQL E2E remain **BLOCKED / NOT RUN**. No administrator policy bypass, no auth-role change, no SQL migrations, no production deployment and no merge.

## 2026-10-24 — Real dev DB catalog gate / concurrency SQL review

**Independent direct Supabase dev PostgreSQL catalog SELECTs performed, with no database writes or role changes.**
- PostgreSQL 17; **35 tables FORCE RLS**; **7 V9 functions installed**.
- `jw_app_dev` and `jw_auth_stage_v85` are both **NOLOGIN** (by design).
- **ZERO** nonprivileged LOGIN roles currently have the ability to `SET ROLE jw_app_dev`: the V8.9/V9.0 server's real database login path is not configured.
- Installed `jw_dev.v90_send_text` still calls `nextval` **without** a transaction-scoped advisory lock, and `jw_dev.v90_edit_text` likewise has **no** advisory lock. They remain vulnerable to commit/cursor-order inversion under parallel transactions. NO migration has been applied.
- `anon` and `authenticated` have **no EXECUTE** on the two RPCs; `jw_app_dev` has EXECUTE. Real independent A/B/C role probes are STILL NOT RUN.
- Existing messenger edit table lacks a chat/timestamp retrieval index; performance/scale evaluation is outstanding.
- Supabase advisors: security INFO `rls_enabled_no_policy` (7); performance INFO `unindexed_foreign_keys` (36), `unused_index` (2). These are advisories, not a substitute for tenant attack testing.

### Code-only remediation in this draft (NOT APPLIED)
- `006_commit_order_cursor_guard_candidate.sql` revised to require **per-conversation transaction lock BEFORE row `FOR UPDATE`** in the edit function. The send function locks before `nextval`. Both functions revalidate the PG session and active conversation AFTER waiting on the lock before writing; edit performs its authorized `FOR UPDATE` after lock acquisition.
- **12/12 read-only static assertions** passed against the actual GitHub SQL candidate text: lock order, post-wait session rechecks, owner/status rechecks, grant/revoke, and version/cursor ordering. These are not a Postgres parser result and do not certify runtime deadlock freedom.
- `catalog_gate_v90.py` + `test_catalog_gate_v90.py`: **6/6 synthetic failure-mode tests PASS**. A real metadata export (with no credentials) in `db_catalog_observed_20261024.json` yields the correct **BLOCKED** verdict for four gates: absent safe login, missing send/edit locks, and absent independent-session E2E.
- **Local isolated stage regression in assembled artifact:** 60 Python PASS + 26 JavaScript PASS = **86 PASS** (includes catalog contract tests). Actual restored V8.9/V9 source integration test rerun 16 PASS. The remote PR staged runner deliberately excludes old archive-only files, so its local-equivalent test inventory is 49 Python + 26 JS; do not conflate the two inventories. Historical integrated full-suite 581 PASS from previous step, NOT repeated in this exact step.
- No DB DDL, privileged bypass, password reset, direct customer query, merge, CI dispatch or deployment performed.

**Launch status: BLOCKED**. Next actual proving step requires an explicitly approved isolated, non-superuser, SSL-verified PG gateway login with `SET ROLE jw_app_dev`, separate auth-stage role, then actual two-connection SQL contention/RLS/revoke/rollback tests before candidate migration and production rollout.
