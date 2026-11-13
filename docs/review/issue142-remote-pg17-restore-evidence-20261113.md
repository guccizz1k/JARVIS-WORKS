# JARVIS-WORKS Issue #142 — remote encrypted PG17 restore evidence (2026-11-13)

## Scope and provenance
- This is an evidence **record**, not an operational release approval.
- Source: user-supplied Codespaces terminal screenshots from `review/jw-142-backup-reverify-20261111`. The assistant cannot directly inspect the user's running Codespaces terminal.
- Verifier branch: `review/jw-remote-pg17-v1`, tested commit `05a6175950ddaafa951ca5a0aecab0430af78b7f`.
- Archive stored in owner-controlled private repository `guccizz1k/jw-backup-vault-261111`, path `archives/2026-11-13/jw-v223-rotated-757ea54caec464bf.jwpgbk`.
- Cipher SHA-256: `84304f6d785b2f49f16c826118fac8580b8bcfe5ec30290f625b9a3e70661d7e`. Source plaintext expected SHA-256: `c9566b8bd2202e822ad520c706b4dd7023eaa95610ec81eb7e01c30efef39da3`.
- The GitHub connector separately confirmed private-file existence and recalculated its full SHA-256 from the remote bytes at this turn.

## Observed codespace execution, successful run
```text
NEW_REMOTE_PG17_REAL_RESTORE_PASS
RESTORE_COUNTS_PASS: tables=65 force_rls=64 rows=22 functions=72 triggers=74
EXISTING_DB_AND_VOLUMES_UNTOUCHED
TEMP_AND_CONTAINER_CLEANED
HISTORICAL_RESTORED_FULL_SCHEMA_ROW_DIGEST_PASS
SOURCE_RAW_SIGNATURE_EQUIVALENCE_NOT_REASSERTED
```

**Verified scope:** new remotely stored encrypted archive read/decrypt, disposable isolated PG17 restore, counts, and the full restored catalog/row-signature compared against the prior independently recorded restored signature `dc048c8e7e1dd1525cd637aa5e167a9c6a92db699491a178be3392fccf184dc0`. The verifier uses `--network none`, only new tmpfs PGDATA, no external bind/named volumes; the script's self-report is not itself independent proof of source-environment access controls.

## Repair log
1. Initial failure `COMMAND_FAILED: docker exec` at version probe: script queried `restore` DB **before** creating it; fixed by probing `postgres` DB first (commit `b7362734`).
2. Full-signature probe failed `ValueError: expected 3, got 2`: JSON object silently collapsed duplicate SQL column names; fixed with ordered `object_pairs_hook`, retaining duplicate values and adding a small regression assertion (commit `05a61759`). Latest screenshot confirms success.

## Remaining gates
- **NOT RUN:** fresh independent live-source raw signature comparison in this run; historical single V151-equivalent constraint difference was previously documented, but current run deliberately does not reassert it. Do not label current source-to-restore equality PASS.
- **NOT VERIFIED:** independent recoverability of the **new** decryption key outside Codespaces; old-key iCloud notes are not proof for the new key. Current new-key temp file under `/dev/shm` is ephemeral.
- **RISK / UNRESOLVED:** screenshots exposed portions of both old/new keys. User elected to continue using the new archive; that does not eliminate confidentiality risk. Do not publish any key, plaintext dump, DSN, credentials, or screenshot containing them.
- **NOT VERIFIED:** backup retention/deletion protection and resilience beyond one GitHub private repository.
- **BLOCKED:** full product release/HTTPS E2E and independent QA not covered by this backup test.

## Safety boundary
Retain both old and rotated encrypted archives and all existing source DBs and volumes. Never delete or rotate the last viable recovery keys until replacement's remote recovery is independently tested and securely escrowed. Do not merge, deploy, publish private backup content to public repository, or claim launch PASS from this report.
