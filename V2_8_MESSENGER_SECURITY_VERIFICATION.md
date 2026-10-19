# JARVIS WORKS V2.8 — PostgreSQL attachment/read integrity review candidate

**2026-10-19 KST · Local synthetic test evidence · NOT FOR PRODUCTION**

## Goal and source protection

Source: preserved `JARVIS-WORKS-V2.7-POSTGRES-MESSENGER-RLS-REVIEW-CANDIDATE.zip`; original SHA-256 `3a484475992a7c2c7a1146fa2d364473014a5d2b86231543688c1b62f3126f52`.

The running FastAPI app remains **SQLite-based demo/MVP**, unchanged from V2.7. Earlier V2.7 PostgreSQL SQL, original scripts, historical manifests, UI assets, customer/trading APIs, message content, attachments, quote/order/invoice flow and tests are preserved. Only the copy's `README.md` is changed among baseline source files. New V2.8 additions do **not** rewrite the existing database or publish code to GitHub.

## Findings and actual changes

1. **Attachment hash field was not constrained:** the V2.7 demonstration inserts fake `sha256-demo`, which the table accepted. New `security/postgres_messenger_rls_v28_hardening.sql` checks a 64-digit lowercase SHA-256 against `pgcrypto.digest(data,'sha256')` and rejects any historical mismatch before applying the candidate patch.
2. **File-to-message binding insufficient:** any employee in a company could potentially add binary evidence to a message created by a different employee, and to a plain text message. A SECURITY DEFINER `BEFORE INSERT` trigger now requires the same verified sender user/org as the original message and a message kind of `attachment`.
3. **Read timestamp forgeable:** the app role was granted column `UPDATE(updated_at)`. The V2.8 patch revokes that permission and sets `updated_at` using the DB server clock while retaining monotonicity and upper bound checks on read positions.
4. **Historical fixture semantics:** V2.7 attack tests fabricated a mismatched checksum and a non-attachment message. In the **isolated test database only**, a new runner corrects that exact synthetic row before applying V2.8. Real evidence with a mismatch must be separately investigated and must never be silently rewritten.
5. **New isolated live test candidate:** `scripts/test_postgres_messenger_v28.py`, `scripts/run_postgres_isolation_ci_v28.py`, `scripts/run_pg17_codespaces_v28.sh`, and a manual-only `.github/workflows/pg-rls-v28-gate.yml`. They verify real PG catalog constraints and cover same-company-different-employee injection, hash mismatch, incorrect kind, read time forgery, legitimate attachments and old message-order invariants — **only when a real PostgreSQL 17 environment is available**.
6. **Local synthetic SQLite benchmark:** `scripts/benchmark_messenger_sqlite_v28.py` runs in a temporary local file-backed demo DB with bounded writer count, denies production mode and leaves the configured persistent DB untouched.

## 5-Gate verification

| Gate | Result | Evidence and qualification |
|---|---|---|
| 1. Syntax / runtime | PASS for Python, JS, shell and SHA files. PG parser **NOT RUN** | `python -m compileall -q app scripts tests`, `node --check app/static/app.js`, `bash -n scripts/run_pg17_codespaces_v28.sh`, `sha256sum -c V2_7_PG_GATE_SHA256.txt`, `sha256sum -c V2_8_PG_GATE_SHA256.txt`. No local PostgreSQL 17 parser/server. |
| 2. Correctness | PASS for offline tests and SQLite app; new SQL **NOT RUN** | New offline RLS/attack guard tests check policy and trigger declarations, denial SQLSTATE matching, manual-only workflow, bounded benchmark. Not proof that PG accepts SQL or enforces constraints. |
| 3. Stability / regression | PASS for all local pytest tests | `proof/v28_pytest_final.log`, no user/production DB opened. Historic V2.7 manifest unchanged. |
| 4. UI/UX | PASS on Chromium desktop and mobile simulation | `proof/v28_browser.log` and `proof/v28_messenger_1440px.png`, `proof/v28_messenger_390px.png`. Real FastAPI via Playwright TestClient bridge; not a public HTTP server or physical phone. Front-end code unchanged. |
| 5. Security / operation | **BLOCKED / NOT RUN** for PG live RLS and deploy | `proof/v28_pg_not_run.log`: exit 2, Docker CLI unavailable. Real RLS, migration, persistent PG adapter, enterprise security, data governance, production throughput, iPhone Safari and deployment remain unverified. |

## Workload smoke (not a service SLO)

`proof/v28_sqlite_smoke.json`: 8 concurrent writer tasks, 160 synthetic messages, 0 missing, strictly increasing 1..160 sequence, `PRAGMA integrity_check=ok`; 0.741 sec measured total, ~215.8 writes/sec and ~41 ms p95 per-write latency in this single local run. These numbers have no statistical confidence bounds and **must not be extrapolated to PostgreSQL, public Internet, multi-tenant load or capacity planning**.

## Release gates remaining

- Execute the *manual* isolated PostgreSQL 17 live gate from the reviewed private source in a disposable Docker-enabled environment. Confirm exit code 0, catalog grants, same-company employee isolation and teardown; a missing environment must continue to return exit 2 (NOT RUN).
- Complete and verify the actual FastAPI-to-PostgreSQL adapter, production-safe DB migration/rollback, existing binary evidence audit, object storage with encryption and malware scanning, retention/erasure mechanisms, account identity and membership lifecycle.
- Run full integration, adversarial, recovery and authorized deployment tests on approved infrastructure before any real company data.

## Boundaries

No actual PostgreSQL server was provisioned, no live SQL executed, no live enterprise user verified, no GitHub branch/push/PR, no CI dispatch and no production deployment. This is a review candidate, not enterprise security certification. SHA-256 consistency alone is not a cryptographic signature or privileged-administrator tamper-proofing.
