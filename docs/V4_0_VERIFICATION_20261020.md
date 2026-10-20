# JARVIS WORKS V4.0 — Verified idempotent PG17 write candidate

**Date:** 2026-10-20 KST
**Status:** REVIEW ONLY / PRODUCTION SWITCH BLOCKED / V4.0 LIVE POSTGRESQL NOT RUN

## Baseline and review boundaries
- Source: V3.9 review branch `review/v39` (expected commit `3d81bcc629da2d266ef6db6d543a3103c64314f2`). No modifications to business-facing SQLite endpoints or `main`.
- V3.9 **isolated real PostgreSQL 17 PASS** was observed in the owner's Codespaces screenshot. It tested PG driver session binding, rollback, role/tenant isolation, revocation and ephemeral cleanup. This **does not verify V4.0**.
- V4.0 does not publish an endpoint, touch production data, merge a branch, migrate data, buy services, or send marketing material.

## Incremental implementation
- Reuse trusted `MessengerReviewAdapter` and V2.7 PG17 RLS/sequence trigger.
- `LabWriterV40` compares request ID + org + sender + original body/thread and creates at most one message per idempotency key in the disposable database. An exact replay returns the original `id/message_seq`; mismatching content/actor/thread is rejected.
- In cross-worker races, only PostgreSQL `23505` on `messenger_messages_sender_org_request_id_key` triggers a verified transaction that rechecks the winning row. All other exceptions fail shut; no automatic unbounded retries.
- A private TestClient-only FastAPI POST endpoint validates strict payloads; 201 means new, 200 means exact retry, 409 means idempotency conflict. Error messages hide credentials, SQL and customer details.
- Add a real PG17 A/B/C attack test covering concurrent duplicate requests, distinct requests, third-company denial, revocation, exact DB row counts, and cleanup. The test is **not executable in the assistant's current environment**, pending isolated Codespaces PG17.

## Five gates
| Gate | Status | Evidence |
|---|---|---|
| 1 Syntax / dependency / source integrity | PASS locally | Python compileall, shell syntax, V2.8–V4.0 (7) SHA-256 manifests validated |
| 2 Feature and negative paths | PASS locally | V4.0 idempotency, bad input, strict origin/actor/thread, specific PG constraint retry and API errors tested |
| 3 Existing regression | PASS | Final `python -m pytest -q tests/`: **323/323 PASS**, 138.84 s, exit 0 |
| 4 UX / accessibility | NOT RUN | No user-facing UI changes; no PC/mobile browser run |
| 5 Production / real PG17 | NOT RUN | No Docker/psycopg in assistant's local execution environment. V4.0 real PG17 Codespaces attack suite required |

## Run instruction (only if free Codespaces quota confirmed)
Already in Codespaces: `git fetch origin review/v40:v40` then `git switch v40`, and `bash scripts/*v40.sh`. For mobile use a one-line abbreviated command when ready.

## Remaining release blockers
Real app is SQLite. The V3.7 operational semantics compatibility schema was read-only. V4.0 writes only an *isolated synthetic legacy PG17 messenger table*, not the full live business order and attachment model. Production employee provisioning, file handling, real migration/rollback, backup/restore, security and concurrency stress tests, and authorized main merge/deployment remain BLOCKED / NOT RUN.

## Final local test evidence
- First full suite 321/321 PASS, followed by two additional race/uniqueness negative tests and final full **323/323 PASS**.
- New V4.0 test module **19/19 PASS**, targeted PG/RLS suite **78/78 PASS** before the two added tests; later full suite contains all 19.
- 7 SHA-256 manifests and `python -m compileall`, `bash -n` PASS.
- `scripts.test_postgres_writer_v40.run()` with no lab flags returned code **2 (NOT RUN)** as expected. No Docker/psycopg locally; **V4.0 real PG17 is NOT RUN**.
- GitHub staging and hash verification will be recorded after remote upload, not preclaimed.
