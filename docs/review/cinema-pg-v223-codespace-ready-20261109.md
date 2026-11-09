# JARVIS-WORKS V22.3 — Codespace-ready Track B candidate (issue #140, 2026-11-09)

Scope: review branch `review/jw-v223-codespace-ready-b-20261109` only. `main`, PR #139, Render, the production database, real data and JARVIS Track A files are untouched. Nothing here has been applied to Supabase. **B2 (real backup) and B3 (independent restore) are NOT RUN until the owner runs the procedure below and it prints `B2_B3_PASS`.**

## Why this branch exists (three defects found by JARVIS, fixed here)

1. **Renewal SQL expiry.** The renewal example said `2026-11-10 12:00:00+09` and the file only capped the window at 7 days. The approval is `<= 24 hours` and an absolute limit of `2026-11-10 09:00:00+09`. `cinema_pg_v223_backup_role_renew_proposal.sql` now carries that limit as a hard-coded literal (never a variable), refuses any execution at or after it ("approval ended, ask again", never extended), refuses a window beyond 24 hours or beyond the limit, and every documented example uses `09:00:00+09`.
2. **Mixed commits.** `c0aaf68` (Codespace preparation) and `25e73fe` (Track B) pin different backup-tool and test blobs in `scripts/ci_cinema_pg_guard.py`. This branch is `25e73fe` plus only the files that exist solely on `c0aaf68` (Codespace bootstrap/check, restore-target scripts, their tests, preparation workflow and notes). The backup tool, its test, the guard and both role SQL files are exactly the `25e73fe` blobs; nothing was checked out file by file.
3. **No automatic access.** Creating a Codespace does not give a Claude Code session access to it; the session's GitHub API 403 is a permission boundary. The owner runs the procedure inside the Codespace. `scripts/ci_cinema_pg_v223_codespace_run.py` is that single protected procedure.

Also fixed: `scripts/ci_cinema_pg_u.py` expected 62 `jw_dev` tables; the live schema has 65, so the live login check would have blocked.

## What the procedure checks before any database action

Exact commit SHA (reported in issue #140) and a clean work tree; every pinned file (backup tool, its test, guard, renew/revoke SQL, Codespace scripts) byte-identical to the commit and the backup tool/test to the guard's pins; the guard itself; the renewal SQL still carries the approved limit once and no `7 days`; PostgreSQL 17 `pg_dump`/`pg_restore`/`psql`, a running Docker daemon, `psycopg` and `cryptography`; the approval window (blocked at or after 2026-11-10 09:00 KST); and, by NAME only, the private inputs. Missing or unsafe inputs stop the run with no database contact.

Private inputs (never pasted into chat, issues or CI):

| Where | Name | Notes |
|---|---|---|
| Codespaces secret | `JW_PG_ADMIN_DSN` | project admin, `sslmode=verify-full` and `sslrootcert=/home/codespace/.local/share/jw-v223-restore/prod-ca-2021.crt`; delete the secret after the run |
| Codespaces secret | `JW_PG_BACKUP_KEY` | the encryption key; keep a copy outside the Codespace |
| Codespaces secret (optional) | `JW_PG_EXPECT_SCHEMA_FINGERPRINT` | default is `POSTAB_FINGERPRINT` from `ci_cinema_pg_w.py`; a wrong value stops the tool before any dump |
| files in the existing Codespace | `~/.local/share/jw-v223-restore/backup_role_auth.json`, `prod-ca-2021.crt`, `restore.sh` | must already exist, mode 0600; use the SAME Codespace that created them, a new one has none of them |

## Owner steps (iPhone Safari)

1. Cost check first: GitHub → profile → Settings → Billing and plans → Codespaces. Continue only if usage is inside the free included amount and the spending limit is $0. If this cannot be confirmed, stop; nothing has been charged by this branch.
2. Open the repository → Code → Codespaces → open your EXISTING Codespace (2-core machine type). Do not create a new one.
3. Terminal, three commands (the SHA is the one in issue #140):

```
git fetch origin review/jw-v223-codespace-ready-b-20261109 && git checkout -B review/jw-v223-codespace-ready-b-20261109 FETCH_HEAD
python3 -m scripts.ci_cinema_pg_v223_codespace_bootstrap --prepare
python3 -m scripts.ci_cinema_pg_v223_codespace_run verify --expect-sha <SHA>
```

4. Settings → Codespaces → Secrets → New secret: `JW_PG_ADMIN_DSN` and `JW_PG_BACKUP_KEY`, repository access limited to JARVIS-WORKS. Restart the Codespace (secrets are not visible before a restart).
5. Only if `verify` printed `VERIFY_ONLY_PASS` and the approval time has not passed, run once:

```
docker start jw-v223-restore 2>/dev/null; python3 -m scripts.ci_cinema_pg_v223_codespace_run all --expect-sha <SHA> --confirm-approval 6729950127 --confirm-no-charge
```

The last line is `B2_B3_PASS` or `B2_B3_BLOCKED_OR_FAIL`. The summary (stage names, statuses, counts, digests; no secret, no row data) is also in `~/.local/share/jw-v223-restore/last_run_summary.json`; report only that. Delete the `JW_PG_ADMIN_DSN` secret afterwards. The encrypted archive stays in `~/.local/share/jw-v223-restore/backups`; moving it to permanent off-Codespace storage is a separate acceptance item.

## Stages of `all` (fixed order)

verify → restore target up, marked and empty → renew `VALID UNTIL` (expiry only, at most 23 hours and never after the limit) → restricted login and 65-table read-only privilege check → encrypted backup, negative tests, isolated PG17 restore, signature comparison (row counts and digests, RLS/FORCE RLS, policies, functions, triggers, constraints, ACLs) → revoke (`NOLOGIN`, sessions ended) → measured proof: a new login is refused, `rolcanlogin` is false, active sessions are 0. Once the privileged renewal command has been STARTED the revoke stage always runs, even when the backup failed, even when the renewal command reports failure or times out (the server can commit while the client reports an error), and even when the revoke itself needs retries (3 attempts). Only a failure before that command (for example no window left before the limit) leaves the database untouched and skips the revoke.

### Safety rules added after the JARVIS review of the previous candidate (issue #140 comment 6732300737)
1. **Revoke is unconditional after an attempted renewal.** The launcher marks the attempt before the privileged `psql` starts; a non-zero exit, timeout or crash afterwards is treated as "state unknown" and the role is closed and measured.
2. **Network/TLS failures are not a login refusal.** `new_login_refused` is recorded only when the server itself answers with an authentication refusal (a `FATAL:` message such as *not permitted to log in*, or SQLSTATE class 28). DNS, refused connection, TLS/certificate problems, timeouts and anything unrecognised end the run with `new_login_refusal_not_verified` (BLOCKED). The role may then look closed from the admin side, but the run is **not** a PASS: re-run only the closure proof later or check the role by hand.
3. **Child-process output never reaches the report.** The backup subprocess's stdout/stderr are never copied into the summary, the console or the stage text. A failed backup reports only its exit code and a pointer to `~/.local/share/jw-v223-restore/last_backup_error.log`: owner-only (0600), with every known secret, URL credential and `password=`/`key=` setting scrubbed. Do not paste that file anywhere without reading it first.


## Not claimed here

Absolute counts 64 FORCE RLS / 72 functions / 74 triggers / 22 static rows are covered only through source-versus-restore signature equality; the engine summary does not expose them and the engine is pinned. Codespaces billing cannot be measured from a Claude Code session. After 2026-11-10 09:00 KST the procedure refuses by design and a new approval is required.
