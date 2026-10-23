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
