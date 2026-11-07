# V22.3 Track B (issue #140) — dev-DB DR / migration preparation and independent QA: work report

**Branch (local, not pushed):** `review/jw-v223-p0-db-dr-claude-20261107` · **base SHA:** `fdf2bd25fde75f7a41edaeb54358e8d60fb433b7`
**Date:** 2026-11-07 · **Status words:** PASS / PARTIAL / BLOCKED / NOT RUN as defined in `AGENTS.md`.
**Nothing was applied to Supabase.** No role, table, constraint, grant or data was changed; no push, merge, PR or deploy.
Track A files, `app/main.py`, the CINEMA HTML/bridges, `main` and PR #139 were not touched.

요약(한국어): 기존 SQL 제안·롤백·백업 도구를 재사용해 읽기 전용으로 검토했고, 실제 개발 DB에는 **조회만** 했습니다.
새로 만든 것은 (1) 조회 전용 preflight SQL, (2) 이를 시험하는 게이트와 정적 테스트, (3) PG17 CI 워크플로(실행 전)입니다.
PG17 실행은 이 환경에서 불가능해 **NOT RUN**이며, PG16.15 일회용 서버의 결과는 보조 증거일 뿐 PG17 PASS가 아닙니다.
개발 DB 변경(역할 생성·제약·부속 테이블)은 모두 사용자의 별도 승인이 필요합니다.

## 1. Files added (4 new + 1 workflow; no existing file edited)
| file | purpose |
|---|---|
| `scripts/review/cinema_pg_v223_preflight_readonly.sql` | ONE read-only SELECT → one JSON document (names, booleans, counts only) |
| `scripts/ci_cinema_pg_v223_preflight_gate.py` | psql-only gate on a disposable server (19 checks) |
| `tests/test_cinema_pg_v223_preflight_readonly.py` | static guards: single SELECT, no write/DDL verbs, rule names equal the backup tool's |
| `.github/workflows/jw-cinema-pg-v223-preflight-gate.yml` | the same gates on PG17 — **NOT RUN** (no push) |
| this report | |

## 2. Evidence (what actually ran, where)
Environment: PostgreSQL **16.15** server binaries from the OS, disposable cluster (unix socket trust, and again TCP + SCRAM
password auth to mimic CI). No PG17 binary, the docker daemon is not running, `psycopg` and `fastapi` are not installed and
package installs are blocked. Raw logs were kept outside the repository (public repo).

| item | status | evidence |
|---|---|---|
| Engine SQL gate (unchanged engine) | **PASS on PG16.15** (PG17: NOT RUN) | `scripts.ci_cinema_pg_sql_gate`: 222/222, socket and TCP+SCRAM |
| Terms side tables + two-person constraint gate | **PASS on PG16.15** (PG17: NOT RUN) | `scripts.ci_cinema_pg_terms_gate_v223`: 60 checks, 0 failed |
| New preflight gate | **PASS on PG16.15** (PG17: NOT RUN) | 19/19, socket and TCP+SCRAM; 2 injected defects were caught by exactly PF.14 and PF.17 |
| New static tests + related existing tests | **PASS** | 113 passed (`--noconftest`; `tests/conftest.py` needs fastapi) |
| Backup/migration unit tests already in the repo | **PASS** | 131 passed (`--noconftest`) |
| `ci_cinema_pg_v223_migration_gate` (needs PG17 or `--allow-pg16-local`, and psycopg) | **BLOCKED** | psycopg missing, installs blocked |
| `ci_cinema_pg_v223_backup_synthetic` / `pg_backup_v223 run` (backup → encrypt → isolated restore → signature diff) | **BLOCKED** | needs psycopg and `pg_dump`/`pg_restore` ≥ 17 (the tool refuses 16 by design) |
| Full pytest suite | **NOT RUN** | fastapi missing |
| PG17 CI workflows (existing and the new one) | **NOT RUN** | nothing pushed |
| `ci_cinema_pg_guard.py` | **NOT RUN** | shallow clone lacks the pinned baseline; the new paths were checked against its `classify_path` whitelist and are allowed |

## 3. Independent QA findings
1. **Apply-order trap (measured, PF.20/PF.21).** `GRANT SELECT ON ALL TABLES` covers only tables that exist at that moment. If
   `jw_backup_ro` is created **before** the terms migration, the 3 new side tables are unreadable to it and the backup tool
   refuses the role (`tables_unreadable`). The proposal document expects "62 readable" and does not state the order.
   **Fix without changing any file:** apply the terms migration first, then the backup-role proposal; or, if the role already
   exists, re-run the grant step under the same temporary membership (verified: it clears the violation and restores the
   admin-only membership):
   `BEGIN; GRANT jw_cinema_owner TO CURRENT_USER WITH ADMIN FALSE, INHERIT TRUE, SET FALSE; GRANT SELECT ON ALL TABLES IN SCHEMA jw_dev TO jw_backup_ro; REVOKE jw_cinema_owner FROM CURRENT_USER GRANTED BY CURRENT_USER; COMMIT;`
2. **"Zero rows" can hide "unreadable" (fixed in the preflight).** BYPASSRLS does not grant table privileges. The first draft
   called a BYPASSRLS session "complete"; a role without a route to `jw_cinema_owner`'s tables silently skipped them.
   `data.row_visibility_complete` now also requires every table to be readable, and `data.unreadable_tables` names the rest.
3. **SQL mirror cannot drift unnoticed.** The preflight's `violations` use the backup tool's rule names; PF.13/PF.14 compare them
   with `pg_backup_v223.evaluate_source_privileges` run on the tool's own `ROLE_SQL` for an accepted role (`jw_backup_ro`) and a
   rejected one (simulated admin). Limits: PG16, not the Supabase project.
4. The existing proposals behave as documented under psql on PG16: two-person constraint `NOT VALID` and requiring a non-NULL
   approver (PF.08), side tables FORCE RLS + policies (PF.09), functions SECURITY DEFINER with pinned `search_path` and no PUBLIC
   execute (PF.10), role accepted by the tool's check (PF.11), rollback removes the role and leaves the constraint (PF.16).

## 4. Real development project — SELECT only (project `rvymwwzclagvljnofyss`, PG 17.11, 2026-11-07)
Run with the preflight SQL as `postgres`; `row_visibility_complete = true` (62/62 tables readable, via `pg_read_all_data`).
| fact | value |
|---|---|
| `jw_dev` | 62 tables, 2 sequences, 61 FORCE RLS; no PUBLIC privileges; `anon` / `authenticated` / `service_role` hold 0 privileges on those tables |
| `jw_backup_ro` | does not exist |
| quote two-person constraint | not present |
| terms tables (3) and functions (3) | none exist |
| login + BYPASSRLS non-superusers | `postgres`, `supabase_etl_admin`, `supabase_read_only_user` |
| `postgres` → `jw_cinema_owner` | ADMIN only (INHERIT false, SET false), grantor `supabase_admin` |
| rows | 22 in total, all in `cinema_pg_transitions`, which equals the 22 rows the engine SQL seeds (entity/from/to). Every business table, including organizations, users, sessions, quotes, orders, invoices and payments, has 0 rows |
| existing self-approved / approver-less quotes | 0 (there are no quotes) |
| `postgres` against the backup tool's check | 8 violations (`createrole`, `createdb`, `replication`, `database_create`, `schema_create`, `settable_other_roles`, `tables_writable`, `sequences_writable`): it cannot be the backup role |

Supabase advisors (INFO level, unchanged from the issue): RLS enabled/no policy **9**, unindexed foreign keys **49**, unused
indexes **3**. Measured basis for the judgement the issue asks for — **recommendation only, nothing was changed:**
* the 9 policy-less tables are deny-all twice over: FORCE RLS with no policy, and zero privileges for PUBLIC and the three API
  roles on every `jw_dev` table. Adding policies is not needed and would widen what is reachable.
* the 3 "unused" indexes and the 49 FK indexes cannot be judged on an empty database (no scans have ever happened). Decide after
  a measured load; do not drop or add now.

## 5. Approval package (no step below has been executed)
| change | files | impact | rollback |
|---|---|---|---|
| A. quote two-person constraint (`NOT VALID`) | `cinema_pg_v223_quote_two_person_proposal.sql` | one CHECK on `cinema_pg_quotes`; today 0 rows, so no existing row conflicts | `..._rollback.sql` |
| B. order/invoice/payment side tables + 3 functions | `cinema_pg_v223_terms_proposal.sql` | 3 tables, 3 functions; empty at start | `..._terms_rollback.sql` (refuses if rows exist; use `_disable.sql`) |
| C. `jw_backup_ro` (option B, schema-scoped) | `cinema_pg_v223_backup_role_proposal.sql` (+ `valid_until`) | new LOGIN + BYPASSRLS read-only role, one temporary membership removed in the same transaction; **apply after B** | `..._backup_role_rollback.sql` |
Before C is used: the owner sets the password locally (`\password jw_backup_ro`), then the preflight is re-run as `jw_backup_ro`
(expect `violations: []`, `tables_unreadable: 0`). Backup, encryption, isolated restore and signature comparison on the owner's
PC need PG17 client tools and psycopg; nothing real was backed up and no data left the project.

## 6. Still blocked / not proven
PG17 behaviour of all gates; the migration gate and the synthetic backup/restore run in this environment; the real Supabase
effect of C (`CREATE ROLE ... BYPASSRLS` by `postgres` is inferred from the PG16+ rule, not tested there); any HTTP route, UI
or full-service E2E. Release stays NO-GO as the issue requires.
