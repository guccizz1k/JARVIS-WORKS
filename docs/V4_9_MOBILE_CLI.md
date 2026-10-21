# V4.9 — JARVIS-WORKS iPhone-friendly Codespaces runner

**Status:** review-only mobile workflow, not a PostgreSQL cutover or a live business-data migration.

## Goal

A one-time user-local installation converts the 200-character Codespaces test command into `jw 49`, `jw 50`, ... without editing `main` or guessing which review branch is current.

## One-time installation

From anywhere in Codespaces, enter once:

```bash
cd /workspaces/JARVIS-WORKS && git fetch origin review/v49 && git show FETCH_HEAD:scripts/install_jw.sh | bash
```

Installation validates the exact GitHub repository and fetched `review/v49` ref, extracts `scripts/jw.sh` from that immutable fetched Git commit, validates its SHA-256 against `V4_9_PG_GATE_SHA256.txt`, syntax-checks it, and installs a user-owned standalone binary in `~/.local/bin/jw`. It does not require `sudo`. If that directory is absent from `PATH`, the installer adds one idempotent line to the user's `~/.bashrc`; open a new Codespaces terminal before using `jw 49` (or use `~/.local/bin/jw 49` immediately). An unrelated existing `jw` executable is never replaced.

## Subsequent runs

```bash
jw 49
jw last
```

`jw 49` fetches precisely `review/v49`, validates the remote repository, creates a detached worktree under `/tmp`, runs `check_v49_review.sh` and then `run_pg17_codespaces_v49.sh` **only if all previous gates succeed**. The V4.9 PostgreSQL script does not claim new DB coverage; it reruns the unchanged V4.8 full PostgreSQL 17 real-cluster chain. All V4.8 and older manifests remain enforced by the historical scripts. The worktree is removed in a mandatory cleanup trap; cleanup failure converts any prospective PASS into FAIL. The user's main branch is never checked out, committed, merged or pushed.

`jw last` prints the last 35 lines of the most recent log to reduce mobile scrolling. Logs are user-local, mode 0600, in `~/.local/state/jarvis-works`. They can include test diagnostics; do not publish them if they contain secrets. The launcher does not upload logs, credentials or business data.

## Fail-closed response

- **PASS (0)**: source checks, full historical suite and Docker/PG17 gate succeeded, cleanup succeeded.
- **FAIL (1)**: verification, logging, worktree checkout or cleanup failed; NEVER report PASS.
- **NOT RUN (2)**: production environment, wrong origin, invalid input, missing branch, missing tooling or missing scripts.
- Exit 130/143: user interruption or termination; cleanup attempted, not PASS.

No automated main merge, production deployment, migration, approval or feature-flag switch occurs. This launcher is only an orchestration improvement.

## Five validation gates

1. Syntax/source: Bash parsing, SHA256 manifest; reviewed Git commit.
2. Functions: local Git end-to-end command, version selection, log recall.
3. Regression/rollback: historical v48 checker and PG17 supervisor, failure propagation, mandatory worktree cleanup.
4. UX: two-token version command; one-time setup, easy last-log view. Actual iPhone screen not tested.
5. Operations: remote allow-list, production refusal, no sudo, no write to real business data, no remote Git push/merge. Actual Codespaces V4.9 runner is **NOT RUN** until user executes it.
