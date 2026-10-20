# JARVIS WORKS V4.1 — Disposable PostgreSQL 17 recovery / replay drill

**REVIEW ONLY · synthetic sessions/records · no production migration · no network listener.**

## Baseline

- Based on reviewed V4.0.2 source commit `010846ff1b5d739d05c37281d38d0a0ee68430a6` (`review/v401`).
- Prior evidence: owner-provided Codespaces screenshot on 2026-10-20 showed V4.0 PG17 idempotent writes, parallel sequence uniqueness, tenant RLS, revocation and disposable cleanup PASS. V4.1 is an *additional* drill and does not inherit a real-DB PASS until independently executed.

## Scope and threat model

Reuses `app.pg_write_api_v40.create_lab_app`, `MessengerReviewAdapter`, V2.7 counter trigger and tenant RLS. Nothing new is wired into `app.main`, no new SQL schema or production credentials. Runner only works in the existing random `jw_v20_test_<12hex>` database on loopback, with explicit ephemeral flags; inherited Docker launcher destroys it.

The new test verifies:

1. A synthetic company's first committed message returns HTTP 201, with server-chosen sequence.
2. Destroy that TestClient instance; create a **new app instance and new DB connections**. A replay with the same nonce/payload returns 200 and the identical ID and sequence, not a duplicate insert. **This is an app-factory recreation, not a real OS/server restart or durability against disk failure.**
3. Reusing the nonce with altered content must return HTTP 409. The partner can read the one committed row; a third organization cannot.
4. Administrator readback confirms exactly one row with identical ID, sequence, sender, key, and message body.
5. **Inside an uncommitted transaction** insert a fresh message, then inject an exception. The adapter must roll back both the row and per-thread sequence counter; their exact absence/unchanged value is checked in a distinct administrator transaction.
6. Retry the interrupted message. It must commit once (201), receive the immediately next sequence, and subsequent retry must return 200 with the same ID.
7. Revoke one synthetic MFA session, then create a fresh app instance. Requests using the revoked token must return 403 without exposing the DSN/token. Unaffected partner remains authorized.

## Concurrency/cost/release boundaries

- V4.0 already covered two concurrent writes and DB-enforced idempotency; V4.1 deliberately **does not duplicate** that suite.
- No PG pool, real company accounts, actual deployment, SQL data migration, multi-process failover, physical backup, persistent storage RTO/RPO or SLA is implemented/tested. Those require separate environment, plan, consent and tests.
- The reviewer must run `bash scripts/run_pg17_codespaces_v41.sh` in an existing Codespace with an available free usage allotment; this is *not* a mandate to upgrade a plan or incur charges.
- The V4.1 runner inherits V2.7/V2.8/V3.5–V4.0 gates and the strong random Docker/Postgres supervisor preflight. Any new gate error results in FAIL/NOT RUN with redacted stage/type.
- Do not auto-run paid GitHub Actions, push to main, create PR, merge, deploy, touch live DB, or invoke real customers.

## Completion acceptance

- Source integrity checks for all versioned manifests PASS.
- Python/Bash compile and unit tests PASS.
- Full existing application regression PASS.
- **Codespaces live PostgreSQL 17 V4.1 gate is required for actual V4.1 real DB PASS.** Never substitute local mocks or previous V4.0 screenshots.
