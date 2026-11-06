# V22.3 P0-1 — dedicated read-only backup role: PROPOSAL (NOT EXECUTED, needs separate approval)

**Status:** nothing in this document has been run against the Supabase development project.
Everything about the project below comes from `SELECT`-only catalog queries made on 2026-11-06
(project `jarvis-works-dev`, ref `rvymwwzclagvljnofyss`, PostgreSQL 17.11). Creating the role is a
change to the development database and waits for explicit approval from the project owner.

요약(한국어): 지금 개발 DB에는 백업 도구의 최소권한 검사(F2/F6)를 통과하는 기존 역할이 없습니다.
관리자 계정(`postgres`)으로 검사를 우회하지 않고, 전용 읽기 전용 로그인 역할 `jw_backup_ro`를
새로 만드는 구성안입니다. 승인 전에는 실행하지 않습니다. 비밀번호는 사용자 PC에서만 설정합니다.

## 1. What was observed (SELECT only)
| fact | value |
|---|---|
| existing LOGIN + BYPASSRLS non-superuser roles | `postgres`, `supabase_etl_admin`, `supabase_read_only_user` |
| why none of them qualifies | `postgres` is the owner/admin account (create-role, create-db, replication, can write); `supabase_read_only_user` and `supabase_etl_admin` are Supabase-managed and hold `SET` on other roles (`pg_read_all_data`, `pg_monitor`), which the F6 check refuses |
| `jw_dev` | 62 tables, 2 sequences, 0 enum/domain types; schema owner `postgres`; no `PUBLIC` privileges |
| table owners | 45 tables + 1 sequence owned by `postgres`; **17 tables + 1 sequence owned by `jw_cinema_owner`** |
| `postgres` ↔ `jw_cinema_owner` | member with `ADMIN` only (`INHERIT false`, `SET false`), so `postgres` cannot `GRANT` on those 17 tables as things stand |
| `postgres` ↔ `pg_read_all_data` | member with `ADMIN`, `INHERIT`, `SET` |
| `postgres` attributes | `CREATEROLE`, `BYPASSRLS`, not superuser |
| TLS | `ssl = on`; the tool additionally demands `sslmode=verify-full` |

## 2. Proposed role
* Name `jw_backup_ro`, `LOGIN`, `BYPASSRLS`, **no** `SUPERUSER/CREATEDB/CREATEROLE/REPLICATION`.
* `BYPASSRLS` is required, not a convenience: 61 of the 62 tables use FORCE ROW LEVEL SECURITY, so
  without it both `pg_dump` and the row digests would see only part of the data.
* `default_transaction_read_only = on`, `CONNECTION LIMIT 2`, `VALID UNTIL` one week out.
* Privileges: `USAGE` on schema `jw_dev`, `SELECT` on its tables and sequences. Nothing else. It is a
  member of no role (so `settable_other_roles` stays false).

Feasibility of `CREATE ROLE ... BYPASSRLS` by `postgres`: from PostgreSQL 16 a `CREATEROLE` role may
only hand out attributes it holds itself, and `postgres` holds `BYPASSRLS`. **This is inferred from the
rule and from the catalog, not tested on this project.** If it is refused, stop and ask; do not
loosen the check.

## 3. Recommended recipe (option B, schema-scoped; run by the project owner as `postgres`)
```sql
-- 1. the role (no password in this file; see step 6)
CREATE ROLE jw_backup_ro LOGIN BYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
  CONNECTION LIMIT 2 VALID UNTIL '2026-11-13 00:00:00+09';
ALTER ROLE jw_backup_ro SET default_transaction_read_only = on;

-- 2. TEMPORARY: let postgres use jw_cinema_owner's grant rights (its own grant row only;
--    the same pattern already exists for jw_app_dev). SET stays false.
GRANT jw_cinema_owner TO postgres WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;

-- 3. read-only privileges on jw_dev only
GRANT USAGE ON SCHEMA jw_dev TO jw_backup_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA jw_dev TO jw_backup_ro;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA jw_dev TO jw_backup_ro;

-- 4. remove the temporary row again (the original ADMIN-only membership remains)
REVOKE jw_cinema_owner FROM postgres GRANTED BY postgres;
```
6. Password: set it on your own PC only, never in chat, a file or a log: connect as `postgres` with
   `psql` and run `\password jw_backup_ro` (the client hashes it). Keep it in a password manager.

**Trap:** `GRANT SELECT ON ALL TABLES` only prints a `WARNING: no privileges were granted for "<t>"`
when the grantor lacks the right; the statement still "succeeds". Skip step 4 until step 5's check
shows 62 readable tables and 0 writable.

### Verification (step 5; SELECT only, run as `jw_backup_ro`, or let the tool do it)
The backup tool already refuses a run unless the live role passes F2/F6, so the real test is simply
`python -m scripts.pg_backup_v223 run` with `JW_PG_EXPECT_ROLE=jw_backup_ro`. The same query can be
read by hand:
```sql
SELECT count(*) FILTER (WHERE has_table_privilege(c.oid,'SELECT'))                       AS readable,
       count(*) FILTER (WHERE has_table_privilege(c.oid,'INSERT') OR has_table_privilege(c.oid,'UPDATE')
                           OR has_table_privilege(c.oid,'DELETE') OR has_table_privilege(c.oid,'TRUNCATE')) AS writable
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='jw_dev' AND c.relkind IN ('r','p');            -- expect 62 / 0
SELECT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname<>current_user
               AND pg_has_role(current_user, r.oid, 'SET'));      -- expect false
```

## 4. Alternative (option A) and why it is not the recommendation
`GRANT pg_read_all_data TO jw_backup_ro WITH INHERIT TRUE, SET FALSE;` is a one-liner that `postgres`
can already issue, and it needs no temporary membership change. But it lets the role read **every**
schema (including Supabase `auth`), not just `jw_dev`. If the backup password leaked, far more data
would be exposed. Use A only if the temporary `jw_cinema_owner` step in B is not acceptable to you.

## 5. What was tested without touching Supabase
The recipe was replayed on a throw-away PostgreSQL **16** cluster that imitates the observed shape
(an admin role with CREATEROLE+BYPASSRLS and ADMIN-only membership of an owner role, FORCE-RLS table
owned by that owner). Results:
1. Without step 2, `GRANT SELECT` on the owner's table silently granted nothing (WARNING only).
2. With the recipe the new role read the FORCE-RLS table, could not INSERT or CREATE TABLE, and
   `pg_dump --schema=jw_dev` ran and listed both tables' data.
3. The tool's role check returned **ACCEPTED** for it; adding `GRANT <writer> ... SET TRUE` made it
   return `settable_other_roles` (the F6 case).
4. After step 4 the admin role's membership in the owner role was back to ADMIN-only.
This is PG16 evidence for the SQL and the check, not PG17 and not this Supabase project.

## 6. Lifetime, rollback, and what stays forbidden
* One-time use: after the backup run, `ALTER ROLE jw_backup_ro NOLOGIN;` (or drop it).
* Rollback: `REVOKE jw_cinema_owner FROM postgres GRANTED BY postgres;` (idempotent),
  `DROP OWNED BY jw_backup_ro; DROP ROLE jw_backup_ro;`.
* No existing role is altered; no table, policy, function or data is touched.
* Still forbidden without a further approval: using `postgres` (or any admin role) as the backup
  role, weakening a check in the backup tool, putting the DSN or password in GitHub or this chat.
* The backup itself runs on your PC (public repository: no credentials in Actions).

## 7. Approval checklist
- [ ] Owner approves creating `jw_backup_ro` on the development project (option B, or A).
- [ ] Owner will run the SQL (or approves an agent to apply it with no password in the statement).
- [ ] Owner sets the password locally and confirms the `VALID UNTIL` date.
- [ ] Verification result (62 readable / 0 writable / not settable) recorded before the first dump.
