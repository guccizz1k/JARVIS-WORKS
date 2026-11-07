# V22.3 Track B (issue #140) — dev-DB DR / migration preparation and independent QA: work report

**Branch (pushed, review only):** `review/jw-v223-p0-db-dr-claude-20261107` · **base SHA:** `fdf2bd25fde75f7a41edaeb54358e8d60fb433b7` · the integration branch `review/jw-v223-two-track-integration-20261107` (`7018e131`) contains `a1e3364` of this branch; this report's section 6 (re-run of 2026-11-07 afternoon) is on top of it.
**Date:** 2026-11-07 · **Status words:** PASS / PARTIAL / BLOCKED / NOT RUN as defined in `AGENTS.md`.
**Nothing was applied to Supabase.** No role, table, constraint, grant or data was changed; no merge, PR or deploy; the only push is this review branch (`main` untouched).
Track A files, `app/main.py`, the CINEMA HTML/bridges, `main` and PR #139 were not touched.

요약(한국어): 기존 SQL 제안·롤백·백업 도구를 재사용해 읽기 전용으로 검토했고, 실제 개발 DB에는 **조회만** 했습니다.
새로 만든 것은 (1) 조회 전용 preflight SQL, (2) 이를 시험하는 게이트와 정적 테스트, (3) PG17 CI 워크플로입니다.
이 환경에는 PG17이 없어 로컬 결과는 PG16.15 보조 증거입니다. GitHub Actions의 PG17.11 결과(엔진 222/222, preflight 19/19, terms 게이트, 합성 백업 복원)가 PG17 증거이며, 통합 SHA `7018e131`에서 9개 워크플로가 모두 success입니다. 단, 합성 데이터의 복원은 **실제 개발 DB 복원이 아닙니다**(6절 참조).
개발 DB 변경(역할 생성·제약·부속 테이블)은 모두 사용자의 별도 승인이 필요합니다.

## 1. Files added (4 new + 1 workflow; no existing file edited)
| file | purpose |
|---|---|
| `scripts/review/cinema_pg_v223_preflight_readonly.sql` | ONE read-only SELECT → one JSON document (names, booleans, counts only) |
| `scripts/ci_cinema_pg_v223_preflight_gate.py` | psql-only gate on a disposable server (19 checks) |
| `tests/test_cinema_pg_v223_preflight_readonly.py` | static guards: single SELECT, no write/DDL verbs, rule names equal the backup tool's |
| `.github/workflows/jw-cinema-pg-v223-preflight-gate.yml` | the same gates on PG17 — **PASS on PG17.11** (Actions run 42324804761 at `d6954d9`) |
| this report | |

## 2. Evidence (what actually ran, where)
Environment: PostgreSQL **16.15** server binaries from the OS, disposable cluster (unix socket trust, and again TCP + SCRAM
password auth to mimic CI). No PG17 binary, the docker daemon is not running, `psycopg` and `fastapi` are not installed and
package installs are blocked. Raw logs were kept outside the repository (public repo).

| item | status | evidence |
|---|---|---|
| Engine SQL gate (unchanged engine) | **PASS on PG16.15 and PG17.11** | `scripts.ci_cinema_pg_sql_gate`: 222/222 (PG16: socket and TCP+SCRAM; PG17.11: Actions run 42324804761) |
| Terms side tables + two-person constraint gate | **PASS on PG16.15 and PG17** | `scripts.ci_cinema_pg_terms_gate_v223`: 60 checks, 0 failed (PG16 local); PG17 job success in Actions run 42330382640 at `7018e131` (job-level result; log not read) |
| New preflight gate | **PASS on PG16.15 and PG17.11** | 19/19 (PG16: socket and TCP+SCRAM; PG17.11: Actions run 42324804761); 2 injected defects were caught by exactly PF.14 and PF.17 |
| New static tests + related existing tests | **PASS** | 113 passed (`--noconftest`; `tests/conftest.py` needs fastapi) |
| Backup/migration unit tests already in the repo | **PASS** | 131 passed (`--noconftest`) |
| `ci_cinema_pg_v223_migration_gate` (needs PG17 or `--allow-pg16-local`, and psycopg) | **BLOCKED** | psycopg missing, installs blocked |
| `ci_cinema_pg_v223_backup_synthetic` / `pg_backup_v223 run` (backup → encrypt → isolated restore → signature diff) | **BLOCKED** | needs psycopg and `pg_dump`/`pg_restore` ≥ 17 (the tool refuses 16 by design) |
| Full pytest suite | **NOT RUN** | fastapi missing |
| New workflow on PG17.11 | **PASS** | run 42324804761 (`d6954d9`): guard, static tests, engine gate 222/222, preflight gate 19/19 |
| Existing PG17 workflows (terms, migration, backup QA, ...) | **NOT RUN** | they trigger on other branches or manual dispatch; none was dispatched |
| `ci_cinema_pg_guard.py` | **PASS in CI** (locally NOT RUN) | passed in Actions run 42324804761 with full history; the shallow local clone lacks the pinned baseline |

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

## 6. Re-run for the V22.3 Track B priority order (2026-11-07 afternoon, KST)
Remote state re-read first, nothing assumed from the earlier report: `origin/main` = `9760dad`; `origin/review/jw-v223-p0-db-dr-claude-20261107` = `a1e3364` (ancestor of the integration HEAD `7018e131`, which is not in `main`);
Track A = `5177cc8`. At `7018e131` all 9 Actions workflows are `completed/success` (run ids 42330382508 ... 42330382703, read with the public GitHub API), among them
the preflight gate (42330382590), the terms side tables on PG17 (42330382640) and the P0-1 *synthetic* backup restore on two real PG17 clusters (42330382525).
That synthetic run proves the tool's mechanics (encrypt, decrypt, restore, signature compare, wrong key, bit flip, truncation, partial dump, wrong target, privilege rules)
on invented data. Its own verdict is `NOT_P0_1_PASS` by design and it is **not** a restore of the development database.

**New defect found by independent QA (fixed): `has_sequence_privilege` on a non-sequence.** While judging three existing login roles with the preflight's rules on the live
project, the statement failed with `"v201_pending_source_unique" is not a sequence`. Cause: `FROM seq q WHERE has_sequence_privilege(r.oid, q.oid, ...)` — the qual can be
planned before the `relkind = 'S'` filter of the inlined `seq` CTE, and the function raises for any other relation. The backup tool's own `ROLE_SQL` is safe (the call is an aggregate
`FILTER` that only sees rows that passed `WHERE relkind = 'S'`). Fix: the preflight now uses `count(*) FILTER (WHERE has_sequence_privilege(...)) FROM seq`.
Evidence: the same live query with the fix returned (read-only); a new static test fails on the old text and passes on the new one (negative control run); engine gate 222/222 and preflight gate 19/19
were re-run from scratch on a fresh disposable PG16.15 cluster after the fix (PG17: see the Actions run for this commit).

**Existing accounts against the backup tool's rules (live, SELECT only).** None of them can be the backup source today:
| role | login / BYPASSRLS | reads all 62 tables | violations |
|---|---|---|---|
| `postgres` | yes / yes | yes (`pg_read_all_data`) | 8: createrole, createdb, replication, database_create, schema_create, settable_other_roles, tables_writable (45), sequences_writable |
| `supabase_etl_admin` | yes / yes | yes | 3: replication, database_create, settable_other_roles |
| `supabase_read_only_user` | yes / yes | yes, no write privilege | 1: `settable_other_roles` (it may `SET ROLE` to its built-in memberships `pg_monitor`, `pg_read_all_data`) |
`supabase_read_only_user` is one membership option away from passing, but it is a Supabase-managed role: changing its grants and resetting its password is a change to the project's managed credentials,
and Supabase may overwrite it. Not recommended; `jw_backup_ro` (change C) remains the proposed route. Nothing was changed.

**Baseline before any change (read-only signature, no row values, no secrets).** Taken 2026-11-07 05:08 UTC from the live project and stored outside the repository:
schema `jw_dev` 62 tables / 517 columns / 378 constraints / 159 indexes / 99 policies / 71 triggers / 69 functions / 2 sequences, 31 migrations (last `20261105021324`), database size 16.9 MB of which `jw_dev` relations 3.0 MB.
Per-group md5 values (columns `c60b13dc...`, constraints `d73dca90...`, indexes `f2864e71...`, policies `cae9a187...`, triggers `51723a35...`, functions `16e5f024...`, tables/RLS/owner/ACL `a0b60503...`, the 22 seed rows `b2f53161...`) let the owner prove after A/B/C
that only the intended objects changed and the 22 existing rows are byte-identical. This is a **fingerprint, not a restorable copy**, so it does not satisfy P0-1; it makes the later "existing data lossless" check possible.
A safe restorable copy of the current state: not possible through any route available here (no connection string, no PG17 client, no psycopg, no docker daemon, outbound access limited to package registries and GitHub).
The data is only schema plus 22 seed rows that equal the engine SQL's seed, so the loss risk of the changes below is low, but that is a judgement, not a proof.

**Revised apply order (needs the owner's separate approval; nothing executed).** The priority order asks for a recoverable copy before any business-schema change, and a backup needs `jw_backup_ro`, so the role comes first:
1. **C** `jw_backup_ro` on the existing 62 tables (no business-schema change; one temporary membership removed in the same transaction). Owner sets the password locally. Preflight as `jw_backup_ro` must show `violations: []`, `tables_unreadable: 0`.
2. **P0-1 on the real development database** by the owner's PC (PG17 client tools + psycopg): encrypted dump, decrypt check, isolated PG17 restore, signature comparison. Only a PASS here unlocks step 3.
3. **A** and **B** with VERIFY → REPEAT → ROLLBACK → RE-APPLY.
4. Re-run the grant remedy from finding 1 (PF.21: clears `tables_unreadable` for the 3 new tables and restores the admin-only membership), then a second backup + restore. The earlier recommendation "B before C" stays valid for a single-pass apply; this order trades one extra grant for having a backup before A/B.

## 7. Still blocked / not proven
The real backup, encrypted restore and signature comparison of the development database (P0-1, BLOCKED: no `jw_backup_ro`, and this environment has no connection string, psycopg, PG17 client or docker daemon; the synthetic run on PG17 is not evidence for it);
SQL application A/B/C (BLOCKED: no approval); the migration gate in this environment (needs psycopg; its Actions run at `7018e131` is green); the real Supabase
effect of C (`CREATE ROLE ... BYPASSRLS` by `postgres` is inferred from the PG16+ rule, not tested there); any HTTP route, UI
or full-service E2E. Release stays NO-GO as the issue requires.

## 8. Change C alone — conditional-approval package (2026-11-07 evening, KST)
Status words: PASS / PARTIAL / FAIL / BLOCKED / NOT RUN / NOT MEASURED. **Nothing in this section was applied to Supabase. C is NOT applied.**

### 8.1 What was proven before touching the real project
`scripts/ci_cinema_pg_v223_backup_role_c_gate.py` (new, 16 checks, TCP + SCRAM, the Supabase privilege model: admin = LOGIN CREATEROLE BYPASSRLS NOSUPERUSER, owner of the tables
`jw_cinema_owner` does not own, ADMIN-only member of `jw_cinema_owner`). Local PostgreSQL 16.15: **16/16 PASS**. PostgreSQL 17 (Actions run `42345026853`, commit `a2f3e48`, `postgres:17` service; the workflow's version step refuses anything but 17.x and the C gate step requires `PASS: 16 checks, 0 failed`): **all steps success**. The PG17 job log itself was not opened, only the step conclusions via the public API.
| Check | Result |
|---|---|
| CG.02/03 C commits in one transaction; role = LOGIN, BYPASSRLS, no SUPERUSER/CREATEDB/CREATEROLE/REPLICATION, CONNECTION LIMIT 2, `default_transaction_read_only=on`, VALID UNTIL in the future, no password, no membership; the admin's temporary INHERIT membership is gone, its original ADMIN-only membership unchanged; the admin receives ADMIN-only on the new role | PASS (PG16, PG17) |
| CG.04 the backup tool's own rules (`pb.ROLE_SQL` + `evaluate_source_privileges`) and the read-only preflight report `violations: []`; SELECT on every table and sequence | PASS (PG16, PG17) |
| CG.05 no login without a password (SCRAM refuses); login after the owner sets one; writes denied even after `SET default_transaction_read_only = off` | PASS (PG16, PG17) |
| CG.06/07 expiry blocks login and renewal restores it; a third concurrent session is refused (`too many connections`) | PASS (PG16, PG17) |
| CG.08/10 rollback SQL returns the database to the pre-C fingerprint (catalog, ACL, roles, memberships, row counts), is idempotent, and a second apply/rollback cycle also ends pre-C | PASS (PG16, PG17) |
| CG.09 apply twice fails cleanly (`already exists`) with no side effect | PASS (PG16, PG17) |
| CG.11 an error injected AFTER the temporary grant rolls everything back (with and without `ON_ERROR_STOP`) | PASS (PG16, PG17) |
| CG.12–14 an admin without ADMIN on `jw_cinema_owner`, without CREATEROLE, or without BYPASSRLS cannot apply C, and leaves nothing behind (the last one is exactly the PG rule that a creator must itself hold BYPASSRLS) | PASS (PG16, PG17) |
| CG.15 C with `COMMIT` replaced by `ROLLBACK` shows the effect inside the transaction and leaves nothing (a dry run is possible) | PASS (PG16, PG17) |
| CG.16 the SQL contains no password, DSN or secret; the expiry is a variable | PASS (PG16, PG17) |
Negative controls: deleting the final `REVOKE jw_cinema_owner ...` line fails CG.03 and CG.09; making the role `SUPERUSER` fails CG.02/CG.03. Both were reverted (`git diff` clean).
**Measured side effect of the rollback:** the 2 sequences that had no ACL (NULL) keep an explicit owner-only ACL afterwards (semantically identical, `pg_dump` prints no GRANT for it). The fingerprint in the gate normalises this; a raw ACL-text comparison would show it.

### 8.2 Exact SQL for C alone
Files, unchanged since the earlier review: `scripts/review/cinema_pg_v223_backup_role_proposal.sql` (apply) and `scripts/review/cinema_pg_v223_backup_role_rollback.sql` (undo). Applied by the project admin role, one transaction:
```sql
BEGIN;
CREATE ROLE jw_backup_ro LOGIN BYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION CONNECTION LIMIT 2 VALID UNTIL :'valid_until';
ALTER ROLE jw_backup_ro SET default_transaction_read_only = on;
GRANT jw_cinema_owner TO CURRENT_USER WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;   -- temporary: needed to grant on the 17 tables jw_cinema_owner owns
GRANT USAGE ON SCHEMA jw_dev TO jw_backup_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA jw_dev TO jw_backup_ro;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA jw_dev TO jw_backup_ro;
REVOKE jw_cinema_owner FROM CURRENT_USER GRANTED BY CURRENT_USER;                    -- the temporary membership never survives the commit
COMMIT;
```
Run: `psql "<admin DSN, sslmode=verify-full>" -v ON_ERROR_STOP=1 -v valid_until='2026-11-09 00:00:00+09' -f cinema_pg_v223_backup_role_proposal.sql`, then, on the owner's own terminal only,
`\password jw_backup_ro` with a random value of 32+ characters. **The password must never be typed into this conversation or passed through any tool I use.** If the SQL is run through the Supabase management tool instead, the expiry has to be inlined as a literal and
whether that tool wraps the script in its own transaction is NOT VERIFIED; the owner's `psql` is the route that matches the gate.

### 8.3 Read-only pre-checks already done on the real project (2026-11-07; SELECT only, nothing changed)
Project `rvymwwzclagvljnofyss` (`jarvis-works-dev`, ap-northeast-2, ACTIVE_HEALTHY), PG 17.11, SSL on, `max_connections` 60 with 8 sessions in use, database `postgres`, admin role `postgres`.
`jw_backup_ro` does not exist. `jw_dev`: 62 tables (61 FORCE RLS), 69 functions, 71 triggers, 22 rows in `cinema_pg_transitions`; only two table owners exist (`jw_cinema_owner` 17 tables + 1 sequence, `postgres` 45 + 1), so the single temporary membership is both needed and sufficient.
No object outside `jw_dev` is readable by PUBLIC except 2 views in `extensions`, so a new BYPASSRLS login role with only `jw_dev` SELECT can read nothing else. `log_statement = ddl`; event triggers `pgrst_ddl_watch`, `ensure_rls`; no default ACLs in `jw_dev`.
Schema fingerprint the backup tool expects (`IDENTITY_SQL` for `jw_dev`, taken through the management channel, independent of any DSN): `afd89e64e80ecbc8216af114e0682ee7` (tables 62, force_rls 61, functions 69, triggers 71). It is valid only while A and B are NOT applied; after A/B it must be recomputed.
Other expectations for the tool: host `db.rvymwwzclagvljnofyss.supabase.co` (direct; IPv6-only reachability NOT verified, a session-mode pooler login `jw_backup_ro.rvymwwzclagvljnofyss` may be needed), port 5432, project ref `rvymwwzclagvljnofyss`, database `postgres`, role `jw_backup_ro`.

### 8.4 Risks of applying C
1. `log_statement = ddl`: the CREATE ROLE / GRANT statements are logged. A `\password` verifier can reach the log, so use a long random password and drop the role (rollback SQL) when the backups are done. (The password is never in the SQL file.)
2. The role has BYPASSRLS: it reads every row of every `jw_dev` table. That is the reason for the 2-connection limit, the expiry, `default_transaction_read_only = on` and the absence of any write privilege (CG.05). It is not a substitute for keeping the DSN secret.
3. Ordering trap: after A/B create new tables the role cannot read them until the documented re-grant (PF.20/PF.21) is run; the tool then refuses the role (`tables_unreadable`). Plan the re-grant before the second backup.
4. DDL on the real project fires `pgrst_ddl_watch` (a PostgREST schema-cache reload notification for the GRANTs). Expected to be harmless; NOT MEASURED on the real project.
5. The real effect of `CREATE ROLE ... BYPASSRLS` by the Supabase `postgres` role is proven by the gate for the same attribute set (CG.14 shows the rule), not yet on Supabase itself. The first real attempt is therefore the proof; it is atomic (CG.11–13), so a refusal leaves nothing behind.
6. Supabase may restrict role management in ways a plain PostgreSQL does not; if the statement is refused, do not switch to a more privileged route without a new decision.

### 8.5 Recovery
* Failure during C: the transaction aborts; nothing remains (verified CG.11–14). Re-run the read-only preflight to confirm `backup_role: {"exists": false}` and an unchanged membership list.
* After a successful C that must be undone: `cinema_pg_v223_backup_role_rollback.sql` (idempotent, one transaction; CG.08). Residual: 2 sequences carry an explicit owner-only ACL (no behavioural difference).
* Credentials: if the password or DSN may have leaked, run `ALTER ROLE jw_backup_ro NOLOGIN` or the rollback immediately.
* Before C there is no restorable copy of the development database (only the fingerprint). The data is schema + 22 seed rows equal to the engine SQL seed, so C itself (no business-data change) puts nothing at risk.

### 8.6 Where the backup and the independent restore can run (assessment)
| Environment | Verdict | Reason |
|---|---|---|
| This workspace | BLOCKED | no connection string, no psycopg, no PG17 client, no Docker daemon, no package installs, outbound limited; also a DSN/key would sit in a cloud session it should not be in |
| Owner's PC (Docker + Python + `psycopg`, PG17 client) | READY once the owner supplies them | matches `docs/ops/V223_PG_BACKUP_RESTORE.md`: secrets stay local, restore target is a local PG17 container marked with `mark-target` |
| GitHub Actions on the public repository | PARTIAL / not recommended as the default | possible only with an Environment holding the secrets behind a required reviewer, a session pooler (runners are IPv4), the Supabase CA file, `workflow_dispatch` from the review branch only and a non-public artifact policy; logs are public and the owner would have to create the secrets. NOT VERIFIED; no workflow was added |
| Another approved isolated cloud (private runner / VM) | NOT MEASURED | needs the owner's decision; no new paid service was created |

### 8.7 Conditions for the actual run, and current feasibility
Approval needed from the owner, explicitly: (1) apply C alone to `jarvis-works-dev` (not production) with a stated expiry date; (2) who sets the password (owner, locally); (3) which environment runs the backup/restore.
Current feasibility: C itself — **ready to run after approval**; the real backup → independent PG17 restore → comparison — **BLOCKED until the owner supplies the DSN/password/CA file in an environment from 8.6**; A/B — **NOT RUN and must not run before a real restore PASS**. P0-1 therefore remains BLOCKED, Gate 4 NOT RUN, Gate 5 BLOCKED.
