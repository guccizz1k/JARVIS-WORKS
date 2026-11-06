# V22.3 — PG17 backup / isolated restore (P0-1 tooling)

Status of this document: tooling instructions. It is **not** evidence that a real backup
was restored. P0-1 stays `BLOCKED` until `verdict` prints `PASS` for the real
development database (`JW_PG_REAL_SOURCE=1`).

## What the tool does
1. Reads the source (SELECT + `pg_dump` only) in an exported PostgreSQL repeatable-read,
   read-only snapshot and records a
   signature: per-table row count + digest, RLS / FORCE RLS flags, policies, functions,
   triggers, indexes, constraints, table ACLs.
2. `pg_dump --format=custom --schema=jw_dev`, then encrypts with chunked AES-256-GCM
   (truncation, reordering, tampering and wrong key all fail; plaintext dump is deleted).
3. Negative tests on the encrypted copy: bit-flip, truncation, wrong key, half-written dump.
4. Decrypts, restores into a **new database on a local disposable PG17**, then compares
   signatures. Any difference is reported by name only and the verdict becomes `FAIL`.
   A truncated archive is tested with a second REAL restore attempt, not `pg_restore --list`.
   Missing restore, snapshot, source-identity or decrypt evidence prevents `PASS`.
5. Records dump time and restore time (RTO). RPO is by definition the gap since the
   snapshot; the tool does not claim zero.

## Safety rules enforced in code
- Source must be `sslmode=verify-full` with `sslrootcert`. For a real source ALL of these must
  agree with operator-supplied expectations, and are checked BEFORE `pg_dump` (a database that
  fails is neither scanned in full nor dumped; only the names of failed checks are printed): host, port, Supabase
  project ref (derived from the DSN: `db.<ref>.supabase.co` or pooler login `<role>.<ref>`),
  database name and role (from the DSN AND the live session), server major >= 17, and a
  schema-shape fingerprint of the live database (`IDENTITY_SQL` in the tool). A blank
  expectation never matches, even against a blank value.
- **Source role is least privilege (F2)**, checked from the live session right after the
  identity check and before any table scan or dump. Refused (by name) when the role is
  SUPERUSER / CREATEROLE / CREATEDB / REPLICATION, a member of `pg_write_all_data`,
  `pg_execute_server_program`, `pg_read_server_files` or `pg_write_server_files`, can CREATE in
  the database or in the schema, holds INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER on any
  schema table or UPDATE on any sequence, cannot SELECT every table, has switched role
  (`current_user != session_user`), **can SET ROLE to any other role even when
  its permissions are not inherited**, or has no USAGE on the schema. `BYPASSRLS` is the one deliberate allowance and
  is REQUIRED when the schema has RLS tables: with FORCE RLS a role without it silently sees
  only some rows, so both the dump and the digests would be incomplete. A matching role *name*
  such as `postgres` therefore no longer passes.
- **Restore target proves it is disposable (F1)**, before the source is even contacted and
  before any CREATE/DROP. `localhost` plus `JW_PG_CI_ALLOW` is only the first screen. The target
  must additionally: be PG17+ and not a replica; be reached through database `postgres`;
  carry the marker database `jw_ephemeral_marker` whose comment equals
  `JW_EPHEMERAL_V1:<token>` for the token in `JW_PG_TARGET_EPHEMERAL_TOKEN` (>= 16 chars,
  compared in constant time); hold no database other than `postgres`, the marker and our own
  `jw_v223_<10 hex>[_truncated]` leftovers; and contain no relations in `postgres`. A tunnel to
  a real database fails because it is not marked, is not empty, or both.
  The marker is planted by whoever creates the disposable cluster (`mark-target`, below), and
  the command refuses to mark a cluster that is not empty, so it cannot label a populated one.
- **Signature size is bounded by exact counts, not statistics (F5).** Per-table cap
  `MAX_TABLE_ROWS` (2,000,000) and total cap `MAX_SIGNATURE_ROWS` (5,000,000) are enforced with
  bounded `count(*)` queries before any row is hashed; the planner estimate `n_live_tup` is no
  longer used. Row digests are streamed on the server (per-row md5, 64-bit halves summed:
  constant memory, independent of row order, any changed value changes the digest) instead of
  one `string_agg` over the whole table, and every signature query runs under a
  transaction-local `statement_timeout` of 300 s. Over-cap or timeout stops with a stable
  `BLOCKED_V223_*` code; only a sanitised, truncated table label is printed.
- `pg_dump`/`pg_restore` must be major version 17 or newer (PG16 clients are refused).
- Output contains counts, digests and timings only; passwords are redacted from errors.

## Recommended way to run the real-DB check (no GitHub secrets)
This repository is public, so do not put database credentials in ordinary repository
secrets or in public Actions logs/artifacts. Run it on your own PC instead:

```bash
docker run -d --name jw-pg17 -e POSTGRES_PASSWORD=localpw -p 127.0.0.1:55432:5432 postgres:17
export JW_PG_TARGET_EPHEMERAL_TOKEN="$(python -c 'import secrets;print(secrets.token_hex(16))')"
export JW_PG_SOURCE_DSN='postgresql://<restricted-read-role>:<pw>@<host>:5432/postgres?sslmode=verify-full&sslrootcert=/path/to/supabase-ca.crt'
export JW_PG_TARGET_ADMIN_DSN='postgresql://postgres:localpw@127.0.0.1:55432/postgres'
export JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE
export JW_PG_BACKUP_KEY="$(python -c 'import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
export JW_PG_REAL_SOURCE=1
export JW_PG_EXPECT_SOURCE_HOST='<host-confirmed-in-supabase-dashboard>'
export JW_PG_EXPECT_SOURCE_PORT='5432'
export JW_PG_EXPECT_PROJECT_REF='<20-letter-project-ref-from-dashboard>'
export JW_PG_EXPECT_DBNAME='postgres'
export JW_PG_EXPECT_ROLE='<restricted-read-role>'
export JW_PG_EXPECT_SCHEMA_FINGERPRINT='<see below>'
python -m scripts.pg_backup_v223 mark-target  # once per fresh container: plants the marker (refuses a non-empty cluster)
python -m scripts.pg_backup_v223 run          # needs pg_dump/pg_restore 17 on PATH
```

`JW_PG_EXPECT_SCHEMA_FINGERPRINT` should come from a different channel than the DSN, e.g. run
`IDENTITY_SQL` (replace `%(s)s` with `'jw_dev'`) through the Supabase management plane for the
approved project and copy its last column. A database with a different shape, a different
project ref, database or role fails before any dump is taken. Limits: a restored COPY of the
real database has the same shape, so the project ref and host checks are what exclude it;
and all expectations are still supplied by the operator, so they are only as independent as
the channel they came from.
A synthetic database cannot be accepted as the real development database solely by setting
`JW_PG_REAL_SOURCE=1` or by copying its own values into the expectations.

The source role is now REQUIRED to be a dedicated read-only role (see F2 above): `LOGIN`,
`BYPASSRLS`, `USAGE` on `jw_dev`, `SELECT` on its tables and sequences, nothing else.
**Open question, not verified here:** whether the Supabase `postgres` role is allowed to create a
`BYPASSRLS` login role on this project. If it is not, a dump that sees every row is impossible
without a more privileged role and this check will (correctly) refuse to continue; do not weaken
the check, decide on another approved route instead. Creating that role is a change to the
development database and needs your separate approval.
The Supabase direct connection host may be IPv6-only on the Free plan, so a session-mode pooler
address may be needed for IPv4 networks (verify in the Supabase dashboard; not verified here).
Keep `JW_PG_BACKUP_KEY` somewhere other than the backup file.

## What has and has not been executed
- Executed: `tests/test_v223_pg_backup.py` — DB-free logic, 88 tests, no skips (encryption,
  guards, redaction, signature diff, strict verdict rules, source identity, identifier quoting,
  F1 target proof, F2 least privilege, F5 bounded streamed signature). Ten deliberate
  weakenings of the new controls were each caught by at least one test.
- Executed on a throw-away **PostgreSQL 16** (the only server available to the author; NOT
  PG17): the F1/F2/F5 SQL against real catalogs. Roles `postgres`, read-only, read-only+BYPASSRLS,
  read-write and schema-creator received exactly the expected verdicts, and a clean, a marked, a
  wrong-token, a foreign-database and a non-empty target cluster were classified as expected.
  This validates the SQL text, not the PG17 path.
- NOT RUN: the dump -> restore -> signature path and `scripts/ci_cinema_pg_v223_backup_synthetic.py`
  (which now also exercises F1/F2/F5 on two real PG17 clusters) against any PostgreSQL 17 (no
  Docker daemon, no PG17 client and no `psycopg` in the authoring environment). First run must
  happen on disposable PG17 (CI workflow `jw-cinema-pg-v223-backup-qa.yml`); only then against the
  real development DB.
