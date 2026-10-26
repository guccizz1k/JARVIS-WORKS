# JARVIS WORKS V2.8 — isolated PostgreSQL 17 security gate

**Review/test environment only. Not an application migration or deployment. Never use customer data.**

## Purpose

V2.7's synthetic PostgreSQL policy established initial company/actor-scoped RLS. Review found that the evidence table accepted arbitrary `content_hash` strings and allowed insertion into an employee's message without verifying the message kind at the database layer. The database also granted direct writes to `messenger_read_positions.updated_at`. V2.8 adds a strictly separate upgrade and live adversarial test to examine these failure modes.

- `security/postgres_messenger_rls_v28_hardening.sql`: disposable DB-only preflight, verified binary SHA-256 constraint, original sender+attachment-kind trigger, server-owned read timestamp.
- `scripts/test_postgres_messenger_v28.py`: synthetic same-company-different-employee attempts, bogus hash denial, text-message attachment denial, valid matching-hash roundtrip, read-time forgery rejection, original cursor/ordering preservation.
- `scripts/run_postgres_isolation_ci_v28.py`: creates random throwaway `jw_v20_test_*`, runs legacy tests and V2.7 messenger live attacks, normalizes **only the known synthetic V2.7 fixture**, applies V2.8 upgrade, runs V2.8 attacks, then drops test database and role. Failure or incomplete cleanup cannot report PASS.
- `scripts/run_pg17_codespaces_v28.sh`: disposable PostgreSQL 17 Docker launcher in a private Codespace; checks V2.8 SHA-256 manifest.
- `.github/workflows/pg-rls-v28-gate.yml`: manually triggered, isolated GitHub Actions job; neither push nor schedule triggers the job.

**Why synthetic fixture correction is necessary:** the historic V2.7 test placed a fake `sha256-demo` digest on a plain text message. The V2.8 preflight correctly rejects such legacy rows. The new runner corrects this *known fictional test row only* before running the new gate. This is NOT a migration procedure for actual records. With real data, any digest/type mismatch must stop migration and require separate evidence-preserving audit.

## Run only after permitted code publication in a private review branch

In a disposable Codespace with Docker, ensure the candidate source and `V2_8_PG_GATE_SHA256.txt` are intact. Run `bash scripts/run_pg17_codespaces_v28.sh`. Alternately manually dispatch `.github/workflows/pg-rls-v28-gate.yml` on the reviewed branch, after appropriate approval. No public port or external customer database is required.

Exit statuses: `0` = isolated live PostgreSQL gate PASS with cleanup confirmed; `1` = FAIL; `2` = NOT RUN / prerequisites missing. A successful static pytest run does not substitute for exit `0` from the real PG17 test. Avoid granting `jw_app` superuser, `BYPASSRLS`, schema-owner or unrestricted table privileges.

## Remaining release blockers

- A real PostgreSQL 17 install/driver/container and execution of both live RLS suites.
- RLS catalog/privilege/trigger audit under the actual deployed role and transactional load; data migration plan, checksum remediation, encryption, key rotation and recovery drills.
- Fully integrated PostgreSQL app persistence API (currently SQLite), real corporate identity verification and employee onboarding/offboarding, malware/CDR pipeline, object storage and retention/erasure policy.
- Physical device/customer UAT, measured production load/concurrency, infrastructure hardening, privacy/legal review, and approved deployment.

## Why RLS is not a security guarantee by itself

PostgreSQL 17's RLS may be bypassed by superusers or roles with `BYPASSRLS`; referential integrity and `TRUNCATE` are outside normal row policies. SHA-256 consistency proves the stored bytes agree with the stored digest at check time, not that privileged DB owners or original senders cannot replace both. The audit must validate actual privileges and historical evidence handling.
