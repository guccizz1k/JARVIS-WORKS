# JARVIS WORKS V4.2 — PostgreSQL 17 synthetic logical restore consistency gate

**REVIEW ONLY. This is NOT a physical backup, independent server restore, customer migration or disaster-recovery SLA.**

## Verified baseline

The owner's Codespaces screenshot dated 2026-10-20 confirms the V4.1 app-factory recovery and tenant RLS gate on an isolated, disposable PG17 instance completed PASS. The review evidence is appended to `docs/V4_1_VERIFICATION_20261020.md`. Earlier V3.6 shadow-copy and V3.7 typed legacy semantic/archive checks remain in use.

## Why V4.2 is not the same as V3.6/V3.7/V4.1

V3.6 covered a SQLite synthetic shadow archive; V3.7 covered typed read-only SQLite legacy semantics; V4.1 covered replay across app factory recreation and uncommitted transaction rollback. V4.2 exercises **an independently created PostgreSQL logical mirror of committed public messenger message rows and the protected sequence counters** in the same disposable DB. It verifies transactional create/copy rollback, exact row and counter SHA-256 reconciliation, tamper detection followed by rollback, tenant app role inability to read the mirror, original source preservation and isolated schema destruction.

## Isolation

The mirror schema is a hard-coded `jw_restore_v42`, owned solely by the disposable `postgres` supervisor. It is created in a random `jw_v20_test_<12 hex>` database after existing RLS gates under both V4.2 and ephemeral authorization flags. Schema grants are revoked; `jw_app` does not receive access. It is cleaned up unconditionally if successfully created; the inherited PG17 runner then deletes its entire disposable DB and container. No production DB URLs, customer records, existing SQLite file or FastAPI `app.main` are accepted.

The mirror uses `CREATE TABLE ... LIKE ... INCLUDING ALL` and `INSERT SELECT` while preserving row bytes and server-issued sequence counters. This deliberately does not claim to capture untested application schema tables, WAL, encryption, authentication store, OS process persistence, real restore tooling, RTO/RPO or high availability. A future explicitly authorized staging backup/restore with `pg_dump`/`pg_restore`, independent credentials and a real backup threat model is needed before business go-live.

## Acceptance

- Unit tests validate stable SHA-256, missing/extra/tampered messages, nonce/sequence duplication, counter rollback and malformed values; no live database for mocks.
- Local whole-app regression and SHA-256 manifest checks PASS, if actually executed.
- Explicit **V4.2 real PostgreSQL 17 PASS** requires owner-run isolated Codespaces gate. Previous V4.1 live result does not substitute.
- Inherited mandatory cleanup PASS; fail-stage never prints SQL credentials or source messages.
- No GitHub main merge, PR, deployment, cloud billing or production migration without separate owner permission.
