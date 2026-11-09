# JARVIS-WORKS V22.3 — Codespaces DR preparation (NO DB WRITE)

> **Superseded 2026-11-09:** do not use the branch named below. Use `review/jw-v223-codespace-ready-b-20261109` and `docs/review/cinema-pg-v223-codespace-ready-20261109.md` (one consistent commit set; corrected renewal limit).

Owner approval: development-project change C (temporary backup role) and GitHub Codespaces environment, account expiry **2026-11-09 00:00 KST**. C must not be executed before the secure backup and isolated restore environment has been checked. A/B, production, main and Render changes are prohibited.

## Exact branch and safe actions

- Base: Claude Track B HEAD f6994a256dec7314804ad8e9a572852b8b6b8de1.
- Isolated branch: review/jw-v223-codespaces-dr-prep-20261107.
- Existing .devcontainer/devcontainer.json: Python 3.12 + Docker-in-Docker; unchanged.
- Bootstrap installs PG17 client tooling and the existing psycopg requirements only; never connects to Supabase or creates any database roles.
- The repository is PUBLIC. Never commit, print or send passwords, DSNs, private certificates, keys, or plaintext dumps.

## iPhone Safari: minimum steps

1. Open https://github.com/guccizz1k/JARVIS-WORKS/tree/review/jw-v223-codespaces-dr-prep-20261107
2. Tap **Code → Codespaces → Create codespace on this branch**. Check free allowance and stop before any unapproved paid usage.
3. In the Codespace terminal run:

    python3 -m scripts.ci_cinema_pg_v223_codespace_bootstrap --prepare

4. Report only the PASS/BLOCKED summary. Even when everything passes, it prints TOOLS_READY_ONLY — NOT a real backup PASS.

## Live-connection prerequisites (not done by the bootstrap)

- The approved Supabase project is rvymwwzclagvljnofyss, PG17.11.
- The new restricted role jw_backup_ro **does not exist** until C is independently applied.
- Acquire the correct Session-pooler hostname/role name, CA certificate and TLS validation settings from the Supabase dashboard. The backup tool requires sslmode=verify-full with sslrootcert. Never downgrade TLS to get a connection.
- Place temporary credentials and encryption keys in personal repository-scoped **Codespaces secrets**, never public GitHub Actions or this chat. GitHub: Settings → Codespaces → Codespaces secrets → New secret → restrict repository access to JARVIS-WORKS.
- Codespaces secrets are not available during image build; restart Codespaces when secrets are added.
- Verify an empty disposable PG17 Docker target and source identity before the C change.
- After the exact C transaction and its ACL/postflight checks, run the existing scripts.pg_backup_v223 mark-target and run workflow, including independent restore and negative controls. Only a real-source PASS unlocks later A/B consideration.
- Save the encrypted archive outside the ephemeral Codespace in a private access-controlled location, and preserve the encryption key separately. An archive left only inside a Codespace is not DR.
- Once the restore is complete, revoke/destroy the temporary BYPASSRLS role as approved. Full Supabase Auth/Storage disaster recovery remains a separate gate.

## Status

PG17.11 C gate 16/16 PASS (Actions 42345168180). Live Supabase C NOT APPLIED. Live backup/restore BLOCKED. This preparation branch alone never unlocks C.
