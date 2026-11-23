# JARVIS-WORKS V22.3 — staging-compatible P1 review candidate

## Purpose
Add the already-proven P1/B2/B3 encrypted backup and local PG17 restore verification tooling to the existing Render QA *code baseline* without editing any existing app/ or static UI file. This branch is review-only, not the deployed service.

- Protected legacy QA baseline: `16b06a8da738de1129382cafc10e2b4b5004c424`.
- Existing Draft PR #148 P1 backup verification source: `5ecfaf4990b302d306c5c0dacaf65e0a14ff1809`.
- Only the thirteen P1 workflow/scripts/tests files are imported; the `pg_backup_v223.py` backup engine version is updated with V1 decryption compatibility, V2 encryption and conservative security checks.
- Existing `app/owner_review_app_v223.py`, the public Basic authentication barrier, `app.main`, and all user-approved V22.3 UI assets are preserved byte-for-byte from the QA baseline.
- Pinned UI hash smoke and QA adapter middleware smoke plus real disposable PostgreSQL17 synthetic restores must be PASS on **this exact SHA** before any staging deployment attempt.
- No customer backups, source DB passwords, Supabase keys or QA Basic credentials are included. No remote storage operation is authorized by this branch.
- Render service branch configuration, runtime environment, start command and deployed SHA remain unchanged. Deploy only with explicit scoped approval, isolated dummy data, independently verified no prod keys, and independent HTTPS + session/CSRF/tenant tests.
- A compatible code tree and CI do NOT by themselves constitute a live HTTPS E2E PASS or launch approval.
- Historical immutable archive provenance, independently confirmed offsite storage/retrieval, and owner final production launch approval remain independently BLOCKED until evidenced.
