# JARVIS WORKS V2.7 — PostgreSQL messenger isolation gate

**LOCAL REVIEW ONLY. Do not use with production credentials or real company data.**

## Current state

The running FastAPI app remains SQLite-based, and still refuses production mode. V2.7 provides a **separate disposable PostgreSQL 17 integration candidate**, not a live app migration. No PostgreSQL server/driver or Docker daemon was available during the 2026-10-19 local inspection. Accordingly, **real PostgreSQL RLS enforcement = NOT RUN**.

## Evidence architecture

The V2.0 legacy SQL authenticates each request via MFA-verified signed tenant claim (`jw_guard.bind_session`), binds the transaction, and revalidates session revocation. V2.7 adds:

1. Directory (only company name/org ID is selected by app role; company registry writes are privileged).
2. Bilateral threads, with `org_a`/`org_b` immutable because app role lacks UPDATE and DELETE.
3. Messages visible only in active participant threads, inserted only with matching signed **company and user** identity (`jw_guard.current_actor`). This blocks an employee impersonating other company members.
4. Evidence reads controlled by parent message visibility. App role has no DELETE or UPDATE on raw messages, attachment data, edits or receipts. An audited text-editing service remains to be designed on PostgreSQL.
5. Per-thread counter updated under the database row lock in the same insert transaction; app role cannot allocate its own message sequence, and `message_seq` is never client-selected.
6. Read-position INSERT/UPDATE restricted to tenant's thread and constrained against future/retrograde marks by trusted triggers. PostgreSQL session enforcement, table owner, roles and catalog must be audited live.

PostgreSQL RLS does **not** cover `TRUNCATE` or `REFERENCES`; owners and `BYPASSRLS` roles may bypass policies. Hence the separate least-privilege audit is mandatory. `FORCE ROW LEVEL SECURITY` and function ownership need a real DB inspection. See https://www.postgresql.org/docs/17/ddl-rowsecurity.html.

## Gate steps (must be performed with explicit approval for remote execution)

1. Review private branch candidate and the original V2.6 checksum; confirm no customer datasets or secrets.
2. On an **ephemeral, fresh** PostgreSQL 17 runner only, run manually: `.github/workflows/pg-rls-attack-gate.yml`, or `scripts/run_pg17_codespaces.sh` in a disposable container-enabled environment.
3. The guarded runner creates its own DB named `jw_v20_test_<random hex>`, installs legacy schema/policies, runs the original attack suite, installs `security/postgres_messenger_rls_v27.sql`, then audits real catalog and executes synthetic tenant A/B/C messenger attacks, 16 concurrent writes, and message sequence checks.
4. Expected denials need precise SQLSTATE and must not count SQL syntax errors, lack of connectivity, or missing privileges from an unrelated object as a security PASS.
5. Destroy the isolated DB/role and verify cleanup. Save PG server version, tested source hashes, all test logs and CI run ID. Nonzero runner exit or incomplete cleanup is not a PASS.
6. Never connect the generated PostgreSQL test fixture to the actual company app. Production integration requires a verified schema migration, tenant-scoped connection pool, transactional session binding, real user identity, attachments via encrypted object store, customer migration/rollback, legal retention policy, load tests, monitoring and external security review.

**Important:** SQL uses static schema and trusted trigger functions for a proposed PG model. It is not feature parity with V2.6: no production edit/revision writer, upload antivirus/CDR, live subscription transport, customer enrollment workflow or PG FastAPI adapter is included. These remain blockers.

## Repeatable offline checks

```bash
python -m compileall -q app scripts
node --check app/static/app.js
PYTHONPATH=. pytest -q
sha256sum -c V2_7_PG_GATE_SHA256.txt
PYTHONPATH=. python tests/browser_messenger_v25.py
```

`python -m scripts.test_postgres_messenger_v27` without the **two dedicated temporary test DSNs and guard variable** returns **NOT RUN / exit 2**, not success. Avoid passing existing or company database credentials.
