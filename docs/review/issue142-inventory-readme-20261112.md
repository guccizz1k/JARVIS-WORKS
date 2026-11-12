# JARVIS-WORKS Issue #142 — offline Codespaces inventory

## Purpose

Inventory Git and file metadata in the owner's existing Codespace without opening backup contents, evidence JSON, recovery keys, certificate bodies, environment-variable values, credentials or database rows. This is not a backup/restore test and cannot establish B2/B3 PASS.

## Protect the original worktree

Owner screenshot: local branch `review/jw-142-backup-reverify-20261111`, local HEAD `11d860a`, and many untracked files including `.github/supabase-root-2021.cer` and `docs/review/issue142-*`. Do not run `git reset --hard`, `git clean`, `git add .`, or switch/checkout branches in this worktree.

The older `scripts/ci_cinema_pg_go.py` requires branch `jwb` and a strict untracked allowlist. This diagnostic does NOT relax that guard and cannot activate the backup role.

## Run without branch checkout

From the existing Codespaces repository root, use the single command:

```bash
git fetch origin review/jw-142-readonly-inventory-20261112 && git show FETCH_HEAD:scripts/issue142_local_inventory.py | python3 -
```

Fetching updates Git fetch metadata but does not checkout or modify tracked worktree files. The scanner disables Git optional locks and only prints aggregate metadata and commit/branch identifiers; it does not print file paths or contents, connect to the network or DB, alter files or stage changes.

## Synthetic test command

```bash
python3 -m unittest discover -s tests -p 'test_issue142_local_inventory_20261112.py' -v
```

Eight tests cover unchanged Git index and worktree, strict prior launcher compatibility, untracked counts, symlinks and permissions, malformed Git status, NUL/rename parsing, commit identifiers and absence of synthetic secret leakage.

## Acceptance boundary

- New isolated branch contains ONLY the three diagnostic/code/test/documentation additions relative to the approved source SHA.
- Local synthetic tests PASS; Codespaces real execution remains NOT RUN until actually run in the owner's Codespace.
- No new approval here for ciphertext/key transfers, privileged DB-role reactivation, a Render deploy, a PR/merge, main changes or production changes.
- Actual private backup, independent restore, offsite ciphertext storage and external recovery-key custody remain unverified pending private evidence and separate authorization.
