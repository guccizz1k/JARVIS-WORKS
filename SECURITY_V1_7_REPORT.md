# JARVIS WORKS V1.7 — Security hardening candidate

## Baseline and limits

Based on immutable V1.6 ZIP, **no GitHub changes, deployment or live client data**.

### Changes implemented

- DB `INSERT`/`UPDATE` triggers to reject foreign-tenant relational references between customers, quotes, orders, invoices, payments, imports, audit and events; item lineage checks. **Not read RLS.** Tenant-scoped API reads remain vital. An attacker who controls unrestricted SQLite can still read everything.
- Per-user optional authenticator TOTP with secret encrypted by Fernet (`JW_DATA_KEY`), password reauthentication to enroll, confirmation before enable, immediate existing-session revocation and replay-resistant codes. Failed codes consume login lockout attempts. UI includes OTP input and self-enrollment access in admin Security Center. **Recovery codes / account recovery, staff administration and credential lifecycle are NOT implemented.** MFA onboarding is a dev/test candidate only.
- Upload analysis moved to a dedicated subprocess with 18-second deadline and RLIMIT_CPU/AS/FSIZE, bounded file / output; failures create no preview records. **Subprocess has no OS network or filesystem sandbox**. Linux container isolation must be provided before production.
- Optional ClamAV (`JW_UPLOAD_SCAN=clamav`) using a fixed executable argument array, 15-second limit and fail-closed on unavailable/malicious/failed scan. Development defaults to `off` and does **not** scan for malware. Production requires scanner, but is still hard-blocked by missing RLS.
- When `JW_DATA_KEY` is configured, newly stored extracted import JSON and source-document metadata are encrypted as `ENC1:` Fernet envelopes. Legacy/plain records remain readable until an explicit offline migration. `scripts/migrate_evidence_encryption.py` makes an SQLite backup and verifies it before in-place encryption. **Remaining business data and DB/backup storage are not encrypted; volume-level encryption and key rotation remain outstanding.**
- Business-fact duplicate guard prevents re-uploading a logically identical quote whose XLSX ZIP creation timestamp differs.
- `JW_ENV=production` fails closed while true tenant data-layer access control, MFA provisioning/recovery, scanning and external security audits are unfinished.

### Tests and release status

Unit/regression results and test coverage are recorded in tests and the accompanying verification file. `JW_DATA_KEY` is intentionally never included in the package. **Do not use on customer data.**

### Explicitly outstanding

PostgreSQL RLS with tenant-bound connection identity, complete staff RBAC and MFA recovery, file worker with network egress blocked, production secrets/rotation/backup encryption, malicious document AV signature update monitoring, DAST/penetration tests, measured real organizational document recognition, hosting and incident response.

## Verification evidence (2026-10-18)

- Gate 1: `python -m py_compile app/*.py`, `node --check app/static/app.js`: PASS.
- Gate 2: 128/128 automated tests PASS; distributed groups (27+20+59+22) to avoid repeated-run timeouts; additional negative tests cover MFA replay, tenant relation writes, worker timeout, encrypted evidence and migration.
- Gate 3: baseline quote/order/invoice/payment tests, import confirmation/idempotency, legacy schemas PASS in above tests.
- Gate 4: `tests/browser_smoke.py` PC+mobile Chromium PASS; `tests/browser_quote_import.py`, `tests/browser_smart_import.py`, `tests/browser_import_supplement.py` PASS against FastAPI. Real enterprise PC browser and load tests NOT RUN.
- Gate 5: **PARTIAL / BLOCKED for production**. No PostgreSQL RLS, full storage encryption, MFA recovery, tested malware scanner signatures, network-isolated parsing container, penetration test, or deployed production.

GitHub security check had blocked V1.6 tree publication in an earlier turn; this report does not interpret or bypass that block. No remote publish attempted for V1.7.
