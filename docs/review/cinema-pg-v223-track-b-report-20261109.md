# V22.3 Track B (issue #140) — 2026-11-09 re-run on the post-A/B/C live state: B1 package, B4 QA, B2/B3 blockers

**Branch (review only):** `review/jw-v223-p0-db-dr-claude-20261107` · **base of this session:** `f6994a2` · **code commit:** `64f9879a83eae8b2ffb1044711b30fd19340b427`
**Time of the live measurements:** 2026-11-09 00:52–00:57 UTC (09:52–09:57 KST) · **Status words:** PASS / PARTIAL / FAIL / BLOCKED / NOT RUN / NOT MEASURED.
**Nothing was applied to Supabase in this session.** Only SELECT statements and the read-only advisor calls ran against project `rvymwwzclagvljnofyss`.
No role, grant, expiry, constraint or data was changed; no merge, PR or deploy; `main`, PR #139, Render, Track A files and `app/` were not touched.

요약(한국어): 이슈 #140의 2026-11-09 댓글 기준으로 실DB 최신 상태를 읽기 전용으로 다시 확인했습니다. A/B/C는 11-07에 이미 적용되어 있고(65테이블, FORCE RLS 64, 마이그레이션 36),
`jw_backup_ro`는 존재하지만 11-09 00:00 KST에 **만료**됐습니다. 이번 세션 산출물은 B1(만료 역할 갱신·철회 제안과 일회용 DB 시험 8/8), B4(보안 QA 실측)입니다.
**B2(실DB 암호화 백업)·B3(독립 PG17 복원)은 실행하지 못했고 BLOCKED**입니다: 이 환경에 실DB 접속 정보, PG17 클라이언트, psycopg, 도커 데몬이 없고,
역할 갱신과 실데이터 반출에는 사용자의 별도 승인이 필요합니다. 따라서 실제 백업·복원 PASS는 아직 없습니다.

## 1. Live state, re-read first (no 62-table baseline, no "A/B/C not applied" assumption)
| fact | value |
|---|---|
| server / schema | PG 17.11, `jw_dev`: 65 tables, 2 sequences, 72 functions, 74 triggers, FORCE RLS 64 (the only table without RLS is `cinema_pg_transitions`, the fixed seed), 36 migrations |
| A/B/C history | `20261107134048` quote two-person constraint; `134136` order/invoice/payment side tables; `134332` PUBLIC EXECUTE ACL repair; `134439` backup role SELECT on the new side tables; `134539` constraint validation. The ACL-repair migration is the fix for a PUBLIC EXECUTE left on the new functions: today 0 functions have PUBLIC execute |
| two-person constraint | `cinema_pg_quote_two_person` present, **validated**, requires non-NULL submitter and approver and `approved_by IS DISTINCT FROM submitted_by` |
| `jw_backup_ro` | LOGIN, BYPASSRLS, not superuser/createdb/createrole/replication, CONNECTION LIMIT 2, `default_transaction_read_only=on`, no memberships, a password verifier exists, **`VALID UNTIL 2026-11-08 15:00:00+00` = expired** (now 2026-11-09 00:52 UTC) |
| `jw_backup_ro` privileges | SELECT on 65/65 tables and 2/2 sequences (67 ACL entries, all SELECT), 0 write, no default ACLs in `jw_dev`; the read-only preflight (run as `postgres`) evaluates the role from the catalog with the backup tool's rules: `backup_role.violations = []`, `tables_unreadable = 0`, `tables_writable = 0`, `sequences_writable = 0`. The role itself was not logged in as (it is expired and no password may be used here) |
| rows | 22 in total, all in `cinema_pg_transitions`; every business table (organizations, users, sessions, quotes, orders, invoices, payments, the three terms tables) has 0 rows; self-approved or approver-less quotes: 0 |
| size | database 17,036,979 bytes; `jw_dev` relations 3,186,688 bytes |
| schema fingerprint the backup tool expects now | tables 65, force_rls 64, functions 72, triggers 74 → `d3e6284dfbd277b43041052ea8f927ca` (taken through the management channel with the tool's own `IDENTITY_SQL`; the pre-A/B value `afd89e64…` is obsolete) |
| `postgres` against the backup tool's rules | still 8 violations (createrole, createdb, replication, database_create, schema_create, settable_other_roles, tables_writable 45, sequences_writable): it can never be the backup role |

## 2. B1 — safe renewal of the expired `jw_backup_ro` (PROPOSAL, NOT APPLIED)
Files (new): `scripts/review/cinema_pg_v223_backup_role_renew_proposal.sql`, `scripts/review/cinema_pg_v223_backup_role_revoke.sql`, gate `scripts/ci_cinema_pg_v223_backup_role_renew_gate.py`, tests `tests/test_cinema_pg_v223_backup_role_renew_gate.py`.

**Exact diff against the live role** (one attribute; everything else is byte-identical, proven by RN.03):
```
-  VALID UNTIL 2026-11-08 15:00:00+00
+  VALID UNTIL <owner-approved value, after now() and at most 7 days ahead>
```
```sql
BEGIN;
-- guard (refuses: role missing / window not in the future / window over 7 days / missing variable)
ALTER ROLE jw_backup_ro VALID UNTIL :'valid_until';
COMMIT;
```
Run by the project admin from the owner's own terminal: `psql "<admin DSN, sslmode=verify-full>" -X -v ON_ERROR_STOP=1 -v valid_until='<value>' -f scripts/review/cinema_pg_v223_backup_role_renew_proposal.sql`.
* **Password:** none changes. A verifier already exists and is kept. If the owner wants a rotation (recommended if the old one was ever pasted anywhere), set it only with `\password jw_backup_ro` in the owner's own `psql`, 32+ random characters; it must never be typed into this conversation or passed through a tool I use. `log_statement = ddl` logs DDL statements, so a rotation must not be done through a statement that carries a cleartext password.
* **Privileges / GRANT:** no change needed (65/65 and 2/2 SELECT already). If a later migration adds tables, the documented re-grant (PF.20/PF.21) is a separate change.
* **Window:** only as long as B2/B3 need, e.g. 24 hours from approval. The guard caps it at 7 days; the role reads every row (BYPASSRLS), so keep the window short.
* **Revocation:** `cinema_pg_v223_backup_role_revoke.sql` — `ALTER ROLE jw_backup_ro NOLOGIN` at once, then ends open sessions (needs `pg_signal_backend`, which the observed admin has). It drops and re-enables nothing; renewal does not undo it (RN.07). After the backups are verified, remove the role with the existing `cinema_pg_v223_backup_role_rollback.sql`. If the DSN or password may have leaked: revoke first, then rotate.
* **Rollback of a renewal:** `ALTER ROLE jw_backup_ro VALID UNTIL '<past time>'` or the revoke file; the existing rollback SQL removes the role completely (RN.08).
* **Not allowed and not proposed:** using `postgres`, `supabase_read_only_user` or any managed account as the backup source; weakening the backup tool's F2 checks.

Evidence (disposable servers only; Supabase untouched):
| gate | PG16.15 (this session, local) | PG17 (Actions) |
|---|---|---|
| renew/revoke gate RN.01–RN.08 | **PASS 8/8** (log sha256 `b5c5f8b8b7942165…`) | **PASS 8/8** — Actions run `42543004274` at `64f9879`, PostgreSQL 17.11 (result lines read from the job log) |
| 3 negative controls | renewal also changing CONNECTION LIMIT fails RN.03 and RN.04; removing the guard fails RN.05; adding `LOGIN` to the renew SQL fails the static test. All reverted; clean re-run 8/8 | — |
| change C gate CG.01–CG.16 | PASS 16/16 (`103ab3612bf4e967…`) | PASS 16/16 — same run (result line read from the job log) |
| preflight gate PF 19 checks | PASS 19/19 (`fcfdaa72374d907a…`) | PASS 19/19 — same run (result line read from the job log) |
| engine SQL gate | PASS 222/222 (`816d3f97282f958b…`) | step `Engine SQL gate (… must stay 222/222)` concluded success in the same run (its result line was not read) |
| terms side tables + two-person gate | PASS 60/60 (`26f99e39c0577537…`) | job-level result only, from earlier runs |
| static + existing backup/migration unit tests | 16 new/related passed; 131 existing passed (`--noconftest`) | static-guard step concluded success in the same run; the 131 existing unit tests were not part of that workflow |

**Defect found and fixed in my own gate (root cause, not a product bug):** the first renew-gate run failed RN.08 with the role correctly removed (`left=0`). The test had granted `pg_signal_backend` to the simulated admin for the revoke check and left it in place; the pre-C fingerprint covers memberships, so it differed. The grant is now revoked as soon as the revoke check ends, before the rollback comparison. A related weakness found in review: my first static test had an `or` that made one assertion always true; it is now unconditional and a negative control shows it fails on a weakened file.

## 3. B4 — tenant, privilege and security QA on the live project (SELECT only, 2026-11-09 ~00:55 UTC)
| check | result |
|---|---|
| `SECURITY DEFINER` functions | 54 of 72; **0** without a pinned `search_path`; **0** executable by PUBLIC, `anon`, `authenticated` or `service_role`; **0** functions with PUBLIC execute at all |
| API roles on `jw_dev` | `anon`/`authenticated`/`service_role`/PUBLIC: no schema USAGE and 0 table privileges |
| tenant boundary | 45 tables carry `org_id`; all 45 FORCE RLS; 42 have at least one policy and each of those 42 references the organisation; 0 permissive `true` policies |
| the 9 "RLS enabled, no policy" tables (`login_failures`, `mfa_credentials`, `mfa_recovery_codes`, `review_signup_nonces_v151`, `review_signup_requests_v151`, `security_events`, `sessions`, `staff_disabled`, `users`) | deny-all twice over: FORCE RLS with no policy, and no privilege for PUBLIC or the three API roles. Adding policies would widen what is reachable; **recommendation: leave unchanged**. The three of them that carry `org_id` are the gap between 45 and 42 above |
| role reach | only `postgres` is a member of `jw_cinema_owner`, ADMIN only (INHERIT false, SET false, grantor `supabase_admin`): it cannot `SET ROLE` to the owner or read its tables directly. Login roles: the four app gateway/stage roles (NOINHERIT, no BYPASSRLS), `postgres`, `supabase_etl_admin`, `supabase_read_only_user` (BYPASSRLS, Supabase-managed), `jw_backup_ro` (BYPASSRLS, **currently expired = no usable login**) |
| logging / transport | `log_statement = ddl`, `log_connections = off`, `ssl = on`, `password_encryption = scram-sha-256`. The statements of this session were SELECT only and carried no secret by construction; the server log itself was NOT read |
| advisors | security: 9 INFO `rls_enabled_no_policy` (above); performance: 49 INFO unindexed foreign keys, 3 INFO unused indexes (`v201_receipts_org_fk_idx`, `v201_receipts_actor_fk_idx`, `jw_v173_idx_draft_item_quote_fk`). Counts unchanged since 2026-11-07. **Not changed:** with 22 seed rows and zero business rows no index has ever been scanned, so neither the 49 nor the 3 can be judged yet; decide after a measured load |
| double approval / constraints / concurrency | live: the CHECK is present and validated (0 quotes). Behaviour (self-approval refused, NULL approver refused, concurrent approvals, rollback) is proven on **disposable** servers by the terms/quote gates and the 222-check engine gate, not on the live database (it has no quotes) |
Findings: no new defect on the live project. Residual risk worth the owner's attention: `jw_backup_ro` and `supabase_read_only_user`/`supabase_etl_admin` can read every row once rows exist (BYPASSRLS by design); keep the backup role expired or dropped outside backup windows.

## 4. B2 / B3 — real development-database encrypted backup and independent PG17 restore: **BLOCKED / NOT RUN**
Why it cannot run here (measured in this session): no source DSN or password (and none may be placed in this cloud session), `pg_dump`/`pg_restore` are 16.15 and the tool refuses < 17, `psycopg` is not installed and installs are blocked, the Docker daemon is not running, and outbound access is limited to the package registries and GitHub.
The renewal in section 2 is also a precondition: the role is expired today, so even with a DSN the tool could not log in.
Isolated synthetic evidence exists and is **not** a substitute for the real database. Read-only check of the runs the issue comment cites: Actions `42426049085` at `8fde97a` ("P0-1 synthetic backup real PG17 restore verification") completed success; `42426639966` at `c0aaf68` ("Codespaces DR preparation safety tests") completed success. I did not open their logs and I did not change either branch.

Preconditions the owner must provide (none done):
1. Approve the renewal of `jw_backup_ro` with a concrete `valid_until` (section 2). Nothing was applied.
2. Approve an isolated execution environment (owner's PC with Docker + Python + `psycopg` + PG17 client, or the approved Codespace using `scripts/ci_cinema_pg_v223_codespace_bootstrap.py --prepare`, which refuses outside a Codespace and never touches a database). Public Actions, artifacts and logs must not carry the DSN, key or any real row.
3. Approve exporting the real data (17 MB, 22 seed rows) to that environment, encrypted, the key kept apart from the file.
Run (on that environment, following `docs/ops/V223_PG_BACKUP_RESTORE.md`) with the expectations that are valid today:
`JW_PG_EXPECT_SCHEMA_FINGERPRINT=d3e6284dfbd277b43041052ea8f927ca`, `JW_PG_EXPECT_PROJECT_REF=rvymwwzclagvljnofyss`, `JW_PG_EXPECT_DBNAME=postgres`, `JW_PG_EXPECT_ROLE=jw_backup_ro`, `JW_PG_EXPECT_SCHEMA=jw_dev`, host and port from the dashboard (a session-mode pooler login may be required if the direct host is IPv6-only; not verified).
Expected comparison: 65 tables, 64 FORCE RLS, 72 functions, 74 triggers, the 22 seed rows, policies and ACLs equal between source and restored copy; wrong key, bit flip, truncation, partial dump and a non-disposable target must each fail. **No PASS may be recorded without that run.**

## 5. 5-Gate verdict (this SHA, strict)
| gate | verdict | basis |
|---|---|---|
| 1 Code | PASS for the new files: static tests 4/4 and 16/16 related, negative controls caught; PG17.11 run `42543004274` at `64f9879`: all steps success | disposable only |
| 2 Function | PARTIAL: renewal/revocation SQL PASS on disposable PG16 (8/8) and PG17.11 (8/8, run `42543004274`); real-DB renewal NOT RUN (approval), real backup/restore NOT RUN | |
| 3 Regression | PASS on disposable PG16 (engine 222, preflight 19, C 16, terms 60, unit 131) and PG17.11 run `42543004274` for the code commit | not a full-service regression; full pytest NOT RUN here (fastapi missing) |
| 4 UI | not applicable (no UI file touched) | |
| 5 Operations | **BLOCKED**: expired backup role, no real encrypted backup, no independent restore, no approval for role change or data export | release stays NO-GO |

## 6. Approvals needed from the owner
(1) the exact `valid_until` for renewing `jw_backup_ro` (and whether to rotate the password locally); (2) the isolated environment for B2/B3; (3) exporting the real development data into it, encrypted. Merging this branch, opening a PR, and any change to the advisor items (49 FK indexes, 3 unused indexes, 9 policy-less tables) are **not** requested.
