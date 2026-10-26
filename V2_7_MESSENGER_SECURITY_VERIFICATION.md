# JARVIS WORKS V2.7 — Messenger PostgreSQL RLS Threat Gate / Verification

**2026-10-19 (KST)** · **ISOLATED LOCAL REVIEW CANDIDATE; NEVER ENTER REAL CUSTOMER DATA**

## 1. Source and preservation

- Source baseline: original `JARVIS-WORKS-V2.6-STABLE-SEQUENCE-REVIEW-CANDIDATE.zip` (SHA-256: `8677bbfe9ea20ae5b6e0d7f781678f6670e1552144b6476e306aa4519eb2d39`). Original archive, project folders and private GitHub repository were not modified.
- The V2.6 FastAPI/SQLite runtime is intentionally **unchanged**. Messaging UI, company directory, texts, attachments, order snapshots, read-state, pagination/SSE, quotes, order/invoice/payment workflows, security and audit features remain in place.
- Modified historical source files: `README.md`, `scripts/run_postgres_isolation_ci.py`, `scripts/run_pg17_codespaces.sh` (3 only). New SQL policy and attack tests are separate files.
- Existing V2.1 SHA manifests remain archival and are not rewritten; a new `V2_7_PG_GATE_SHA256.txt` checks only current PG live-gate executables. Historic test artifacts also retained.
- GitHub push/PR/merge, remote CI, production DB migration and deployment: **NOT RUN**.

## 2. V2.7 changes

- `security/postgres_messenger_rls_v27.sql`: **isolated, test-database-only** schema for verified company directory, bilateral messaging, message history, attachments, read positions, immutable edits/receipts. `ENABLE` + `FORCE ROW LEVEL SECURITY` on all seven messenger-related tables. Only two thread participants may read a thread and its messages; another company sees no rows. Company enrollment and evidence modification are withheld from unprivileged role.
- `jw_guard.current_actor()` uses the verified, revocable signed-session context from the original V2.0 RLS gate: sender/company agreement and per-company employee identity checked rather than trusting the submitted `sender_user`.
- Privileged per-thread counter allocates a strictly increasing `message_seq` while a row lock is held through transaction commit, avoiding out-of-commit-order global sequence allocations. The app role cannot choose a sequence or access counters.
- Read watermarks reject rollback and future message positions; read cursors are limited to a verified participant's thread.
- `scripts/test_postgres_messenger_v27.py`: optional **live** synthetic A/B/C RLS attacks covering third-company denial, sender forgery, attachment confidentiality, access without a bound session, GUC spoofing, attempts to edit/delete evidence, read cursor abuse and 16 parallel message inserts. Exact expected SQLSTATE is enforced for failed attacks; unexpected SQL/runtime failure is **FAIL**, not PASS.
- Integrated this optional test into existing isolated PG17 manually dispatched `scripts/run_postgres_isolation_ci.py` after the original legacy attacks. Cleanup logic and network/empty-cluster guard remain in effect.
- New offline regression contract tests: `tests/test_pg_messenger_v27.py` (8).

**Architecture boundary:** New SQL is **not integrated with the running FastAPI SQLite app**. The PostgreSQL schema is a security contract/test fixture, **not a deployed persistent messaging backend**. The verified code does not yet deliver production-grade storage, real company verification or security compliance.

## 3. Five-Gate verification

| Gate | Status | Actual evidence / limits |
|---|---|---|
| 1 — Syntax / environment | PASS for Python/JavaScript/Shell, **NOT RUN** for PostgreSQL SQL parse | `python -m compileall -q app scripts`, `node --check app/static/app.js`, `bash -n scripts/run_pg17_codespaces.sh`. `psycopg`, PostgreSQL 17 server and Docker were unavailable; SQL was **not parsed by PG**. |
| 2 — Feature correctness | PASS — offline static contracts / prior SQLite functions | 8/8 V2.7 tests check RLS policy presence, role grants, actor binding, cursor/transaction design, runner fail-close and artifact integrity. They **do not establish actual PG policy behavior**. |
| 3 — Regression / data preservation | PASS — local Python | **222/222 PASS**, log at `proof/v27_pytest_222.log` (222 tests in 106.05 s). Existing V2.6 database/API tests re-run, including 80 parallel SQLite writes, VACUUM/backups/cursors, business documents and tenant endpoints. Original app code unchanged. |
| 4 — UI/UX | PASS — Chromium simulation only | Existing `tests/browser_messenger_v25.py` run against V2.7 unchanged app: 1440×900 desktop and 390×844 mobile; page history, plus menu, new messages, draft and scroll preservation. `proof/v27_messenger_1440px.png`, `proof/v27_messenger_390px.png`, `proof/v27_browser.log`. Not a physical client browser nor a live deployment. |
| 5 — Security / operational release | **BLOCKED / NOT RUN** for real RLS | Standalone runner exited **2 (NOT RUN)** without dedicated PG test DSNs; true PostgreSQL RLS attacks, PG server startup, SQL execution, concurrency throughput, connection pooling, restore drill, customer onboarding, remote CI and deployment never took place. |

### Security caveats and blockers

- Official PostgreSQL documentation states that RLS is bypassed for superusers/`BYPASSRLS`; table owners ordinarily bypass unless `FORCE`, and RLS does **not** guard `TRUNCATE`/`REFERENCES`. The live catalog and privilege audit must PASS before considering any deployment.
- The proposed PG adapter is not wired to application endpoints. The PostgreSQL policy has **no feature-complete audited text revision writer**, document acceptance workflow, anti-malware/CDR pipeline, legal retention/erasure workflow, real corporate registry verification, encrypted scalable object storage or operational MFA/key provisioning.
- A success in offline synthetic SQLite tests, even 222/222 PASS, cannot prove live PostgreSQL enforcement, race freedom on the new SQL, performance or business compliance. **Never report these as PASS.**
- No performance SLA/TPS is claimed. Existing SQLite concurrency smoke tests are functionality evidence only.

## 4. Required next gate

1. Review candidate as a new **private review branch** and its V2.7 execution manifest. Any GitHub publication / manually triggered CI requires explicit authorization.
2. Provision an isolated, disposable PostgreSQL 17 test database **with synthetic data only**, and execute manual `.github/workflows/pg-rls-attack-gate.yml`. Investigate any rejected SQL, permission ambiguity, FK/trigger mismatch or catalog defect and re-run. Enforce clean teardown.
3. After the entire live gate succeeds, design a verified FastAPI PostgreSQL transaction adapter, migration and rollback test in a separate step; keep the SQLite demonstration unchanged until full regression and abuse testing.
4. Validate real browsers/network loads, backup restore, data retention, audit and enterprise authentication before any customer onboarding or deployment.

**Overall result: PARTIAL.** V2.7 offline threat-gate implementation and regression evidence prepared; **live PG17 and production release remain BLOCKED / NOT RUN**.
