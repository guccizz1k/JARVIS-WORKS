# V22.3 — independent owner-only existing vault archive recovery

## Scope / provenance
This supplementary B3 procedure deliberately DOES NOT create another source
backup, log into Supabase, renew the `jw_backup_ro` role, modify an existing
business database, or contact Render. It consumes **an already preserved encrypted
archive** from the owner's private vault in an **owner-controlled Codespace**.
There is no archive/key embedded in this public repository, and the GitHub Actions
job exercises *only generated disposable synthetic data*.

This route can isolate and validate an archived snapshot without restarting B2,
but it cannot establish source-backup completeness, the original source's
same-snapshot row signatures, source role provenance or production DR readiness.
The latter still require independently protected metadata/receipts and review.

## Operator prerequisites — all inside the owner's secure Codespace
- PostgreSQL **17** client `pg_restore` and a **new empty disposable local PG17 cluster**;
  NOT the live dev DB, Render DB, SSH tunnel into an unknown DB, or production.
- The target must have a previously operator-created marker bound to
  `JW_PG_TARGET_EPHEMERAL_TOKEN` via
  `scripts.pg_backup_v223 mark-target`. The script checks the exact marker,
  absence of unrelated user databases/relations and target server version before
  restoring anything.
- `JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE`, plus
  `JW_PG_TARGET_ADMIN_DSN` restricted to loopback and database `postgres`.
  Verify all targets are disposable before setting the marker.
- `JW_PG_EXISTING_ARCHIVE`: an **absolute owner-private path** to a downloaded
  `.jwpgbk` archive; never place this ciphertext or a plaintext dump in the
  public JARVIS-WORKS repository.
- `JW_PG_EXPECT_ARCHIVE_GIT_SHA`: **40-hex blob object ID obtained separately**
  from the owner's authenticated private vault Git metadata. The script
  compares the local ciphertext with that exact Git blob before decryption.
  Git SHA-1 provenance is not an encryption signature; authenticated AES-256-GCM
  validates ciphertext after key access.
- `JW_PG_BACKUP_KEY`: the **existing** 32-byte backup secret, supplied as a
  Codespaces secret via environment, never printed, pasted into chat or committed.
  A newly generated key **cannot** decrypt previous vault artifacts.
- Never put these values into a public GitHub Actions secret/log or issue body.

One explicit launch from the existing secured Codespace after prerequisites:
`python -m scripts.ci_v223_vault_offline_restore`

## Enforced gates
1. Refuse relative path, symlink, unknown extension, wrong object ID or truncated
   ciphertext; no private archive name, key, target DSN or customer row logged.
2. Require PostgreSQL17 tools; require only a marker-proven, empty local PG17
   restore target. No source DB connection or changes.
3. Authenticate ciphertext and final GCM frame; reject changed bytes, truncation
   and wrong key. Decrypted PostgreSQL custom-format archive must start `PGDMP`.
4. Use `pg_restore --no-owner --no-privileges --exit-on-error`; compare readable
   restored `jw_dev` schema/table/policy/function/trigger/row signatures locally.
   **ACL source parity is NOT VERIFIED** because original PG roles/privileges are
   deliberately not recreated; original-source same-snapshot signature parity
   is also **NOT VERIFIED** without a separately signed receipt.
5. Always delete plaintext temporary files and test database; return
   `b3_existing_archive_restore=PASS` only after actual restore/re-query and
   negative tests. `b2_live_backup=NOT_RUN`, `release_gate=BLOCKED`.

## Safe acceptance
The offline route's specific B3 artifact-restore PASS can support recovery
decisions, **but may never be substituted** for the production-level B2/B3 gate.
Full B2/B3 requires source provenance/permissions, fresh approved source snapshot
with repeatable read and dump, independent PG17 restore, exact schema/RLS/ACL/
trigger and row signature parity, real RTO/RPO, owner key custody and revocation
of any temporary privileged login. No real execution is claimed until evidence
from the owner's secure environment is independently read and validated.
