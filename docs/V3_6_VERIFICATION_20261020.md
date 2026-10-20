# JARVIS WORKS V3.6 — synthetic SQLite→PostgreSQL shadow and rollback verification

Date: 2026-10-20 · Review candidate; **NOT PRODUCTION**

## Source / preservation
- Baseline: V3.5 PG17 FastAPI review branch (`review/v3-5-postgres-api-lab-20261020`, HEAD `e074fe5577bea112bfc16a58b166f2e28a9a53a2`), associated Library ZIP.
- New private review branch: `review/v3-6-migration-shadow-20261020`, commit `36de767bd87c796e796647072172258754c2ec16`. All 10 transferred Git blobs matched their locally validated Git hashes (10/10 PASS); previous V3.5 and `main` heads unchanged.
- No existing FastAPI route, SQLite live schema, company messaging UI, payment/order workflow, live enterprise data or `main` changes.
- New isolated modules: `app/pg_migration_shadow_v36.py`, `scripts/v36_synthetic_fixture.py`, `scripts/test_postgres_migration_v36.py`, `tests/test_pg_migration_shadow_v36.py`, `scripts/run_pg17_codespaces_v36.sh`, `docs/V3_6_MIGRATION_SHADOW_LAB.md`, `V3_6_PG_GATE_SHA256.txt`.
- Existing runner `scripts/run_postgres_isolation_ci_v28.py` receives opt-in V3.6 gate only, and existing V2.8/V3.5 live gate hashes are refreshed. V3.5 gate remains unchanged when V3.6 flag is unset.

## Actual work
1. Consistent SQLite snapshot via `Connection.backup(:memory:)`, DB integrity + FK checks; canonical typed encoding of seven messaging tables, including binary attachments, unicode names, edit history, read watermarks and order snapshots; explicit PK and SHA-256 for each row.
2. Restricted disposable PG17 **shadow** table in a schema inaccessible to the app role; atomic, transaction-scoped copy with PostgreSQL byte digest constraint, exact byte-level read-back and hash/row verification.
3. Inject failure after row 2 to prove rollback of entire schema creation and inserts; retest clean insertion, verify `jw_app` forbidden, byte tampering blocked, then drop shadow.
4. Fail-closed *operational cutover blocker report*: PG operational schema cannot yet represent all SQLite order snapshots, text+attachment semantics, and receipt metadata. **No user data or actual operational data migration occurs**. The shadow archive is test-only, not a production storage backend.

## 5-Gate results
| Gate | Result | Evidence |
|---|---|---|
| 1 Syntax / integrity | PASS | `python -m compileall`, JS `node --check`, `bash -n`, all 3 SHA256 gate manifests validated |
| 2 Feature | PASS | New 12/12 synthetic records and negative/fault-path tests; 45/45 focused suite |
| 3 Regression | PASS | Full Python suite **274 passed in 151.51s**; `proof_v36_full_pytest.log` |
| 4 UI/UX | NOT RUN in this step | No UI/runtime source changes; previous V3.5 UI evidence remains separate |
| 5 Live PG17 operation | NOT RUN | Docker unavailable in current sandbox; live runner exits code 2, `proof_v36_pg17_attempt.log` |

No capacity, RPO/RTO, PG throughput or production cutover claim is made.

## Verified code publication scope

No PR, merge, paid GitHub Actions, managed PostgreSQL instance, production deployment or external company data access. The isolated PG17 live V3.6 test has not been executed; prior V3.5 live PASS is not substituted for V3.6.

## Next step
In the already-authorized private V3.6 review branch, run `bash scripts/run_pg17_codespaces_v36.sh` from a Codespace after verifying free quota. Expect both the V3.6 live shadow/rollback PASS and final PG17 clean teardown PASS. Any failure must be investigated and retested. `main`, production DB and deployments are protected.