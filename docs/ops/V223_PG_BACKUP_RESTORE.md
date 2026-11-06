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
  fails is never dumped; only the names of failed checks are printed): host, port, Supabase
  project ref (derived from the DSN: `db.<ref>.supabase.co` or pooler login `<role>.<ref>`),
  database name and role (from the DSN AND the live session), server major >= 17, and a
  schema-shape fingerprint of the live database (`IDENTITY_SQL` in the tool). A blank
  expectation never matches, even against a blank value;
  target must be `localhost`,
  declared `JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE`, and not equal to the source.
- `pg_dump`/`pg_restore` must be major version 17 or newer (PG16 clients are refused).
- Output contains counts, digests and timings only; passwords are redacted from errors.

## Recommended way to run the real-DB check (no GitHub secrets)
This repository is public, so do not put database credentials in ordinary repository
secrets or in public Actions logs/artifacts. Run it on your own PC instead:

```bash
docker run -d --name jw-pg17 -e POSTGRES_PASSWORD=localpw -p 127.0.0.1:55432:5432 postgres:17
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

Use a read-only database role for the source if one can be created; the Supabase direct
connection host may be IPv6-only on the Free plan, so a session-mode pooler address may be
needed for IPv4 networks (verify in the Supabase dashboard; not verified here).
Keep `JW_PG_BACKUP_KEY` somewhere other than the backup file.

## What has and has not been executed
- Executed: `tests/test_v223_pg_backup.py` (encryption, guards, redaction, signature diff,
  strict verdict rules, independent source identity) — DB-free logic only (35/35 PASS locally).
- NOT RUN: the dump → restore → signature path against any PostgreSQL 17 (no Docker daemon,
  no PG17 client and no `psycopg` in the authoring environment). First run must happen on a
  disposable PG17 with a synthetic source; only then against the real development DB.
