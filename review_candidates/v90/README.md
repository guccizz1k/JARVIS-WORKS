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
