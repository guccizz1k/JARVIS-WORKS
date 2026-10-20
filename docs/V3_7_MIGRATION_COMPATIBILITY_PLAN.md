# JARVIS WORKS V3.7 — Operational-shape compatibility rehearsal

**Status:** REVIEW CANDIDATE; **not a production migration**, not a public API or service release.

## Verified starting evidence

The owner-provided Codespaces terminal screenshot for V3.6 displayed `PASS: V3.6 real PG17 synthetic SQLite shadow copy, exact SHA-256, cross-role denial, forced rollback and cleanup`. That result verifies an isolated archive, not operational schema compatibility. V3.5 independently verified the disposable FastAPI TestClient ↔ PG17 lab, while the deployed app still uses SQLite. Keep all previous proof separate; do not erase or rewrite previous reports.

## First principles and assumptions (`/FIRSTPRINCIPLES`, `/ASSUMPTION`, `/SKEPTIC`)

Legacy SQLite messaging has seven evidence tables: company verification, bilateral connections, message/order snapshot, edit history, attachment byte payload, read watermarks and signed receipts. V2.7 PG test tables use a different attachment kind, lack full historical order snapshots and receipt descriptions. Direct inserts into the current `public.messenger_*` tables would **lose business meaning or reject records**. A generic SHA-256 shadow archive proves bytes survived but not whether PostgreSQL can represent the same business operations.

## Implementation: bounded typed compatibility schema

New isolated module `app/pg_migration_compat_v37.py` and disposable test `scripts/test_postgres_migration_v37.py`:

1. Take a **synthetic in-memory SQLite snapshot**, then require exact columns and all seven explicit semantics before generating SQL. Any future/unknown column, missing PK, forgery, missing document snapshot, edited attachment, incomplete edit history, invalid read cursor, illegal receipt or checksum mismatch blocks instead of silently normalizing.
2. In a fresh `jw_v20_test_*` PostgreSQL 17 DB, create `jw_migration_v37` with **seven relational tables**, structural FKs, constraints and byte-for-byte preserving text/JSON fields, with original `kind='text'` plus attachment and `kind='order'` plus immutable order snapshot. The original public PG test tables and FastAPI/SQLite runtime are untouched.
3. Force RLS on seven tables. Permit `jw_app` **SELECT only** for a bound verified tenant; both businesses see their shared thread but outsider C sees nothing. Business-number source verification is not exposed via directory queries.
4. Reject writes/edits/deletes from `jw_app`. PostgreSQL CHECK recalculates SHA-256 over actual attachment bytes and enforces the stored size. Force a failure mid-copy and prove schema creation + inserts roll back atomically.
5. Read all typed rows from PostgreSQL and independently reconstruct the original canonical SQLite bytes; compare **complete rows + SHA-256 seals**, not only counts. Drop compatibility schema, then destroy the parent disposable database using the existing PG17 harness.

Scripts reuse the 3.5/3.6 gate pipeline and the previous integrity manifests; new `V3_7_PG_GATE_SHA256.txt` hashes only the V3.7 delta and modified gate files. Missing PostgreSQL/Docker/DSN gives `NOT RUN` (exit 2), never PASS.

## Independent counterarguments and boundaries (`/COUNTER`, `/WORSTCASE`, `/SECURE`)

- **Not** a full PostgreSQL cutover: no real customer DB, no connection-string switch, no data deletion, no actual employee/enterprise verification, no client-side encrypted object storage, no backfill of historical auth beyond a synthetic fixture.
- `jw_migration_v37` is **a read-only lab compatibility schema**, not a live writable PG implementation of the existing send/edit/download/acknowledge endpoints.
- A successful dummy tenant A/B/C RLS test is not evidence of pentest certification, actual scale, legal compliance or zero defects.
- Only the primary business fields in the seven messenger tables are covered. Production `organizations`, `users`, `orders`, `customers`, counters, trigger correctness on writable PG APIs and genuine backup/recovery remain outside this scope.
- If any PG test fails, hold the review branch; never update the production website or merge `main`. `GRANT SELECT` to `jw_app` is only for synthetic schema, and must not be used to bypass any existing production access check.

## Five gates and release criteria (`/TESTIT`, `/VERIFY`, `/FINALCHECK`)

| Gate | Proof needed for release of review candidate | Actual status |
|---|---|---|
| 1 Code/dependencies | Python syntax, shell syntax, Python 3.12+ runtime constraints and 4 sets of hashes | Run and record locally |
| 2 Feature | Both correct and adversarial legacy records; exact typed read-back | Local unit tests run; real PG pending |
| 3 Regression | Entire legacy pytest suite; protected source hashes | Run and record |
| 4 UX | Existing UI unchanged; real mobile integration still requires later tests | NOT RUN in V3.7 |
| 5 Operations | Actual isolated PG17 DB RLS/rollback/cleanup, then separate real service cutover test | NOT RUN until Codespaces |

## Growth and content integration (`/PERSONA`, `/HOOK`, `/MARKET`, `/KPI`)

Target hypothesis: Korean purchasing/sales clerks exchanging quotations, purchase orders and files lose context between spreadsheets, email and business chat. **Not verified by customer interviews.** Future *permissioned* interviews should test three angles: searchable suppliers, attached order context, and message accountability. Do not market as launched, secure-certified or '국내 1위'. Define pilot metrics **task completion** and **verified bilateral order context**, not just website visits. No ads, scraping, posting or customer outreach is performed by this gate.

## Mobile execution after source review

On an existing **free-quota** Codespace only, switch to the new review branch, then run:

`bash scripts/run_pg17_codespaces_v37.sh`

Full inherited V2.7 → V2.8 → V3.5 → V3.6 → V3.7 synthetic suites run sequentially and clean up. An actual PASS requires an owner-provided terminal result for V3.7 (not only V3.6 output).
