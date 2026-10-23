# JARVIS WORKS V2.1 — PostgreSQL RLS Adversarial Gate Hardening

Date: 2026-10-19. **Overall status: PARTIAL / LIVE POSTGRESQL NOT RUN / PRODUCTION BLOCKED.**

## Source and scope

- Baseline: preserved V2.0 offline candidate. This V2.1 release is a new, separate **local** candidate. No GitHub push, merge, deployment, Codespace creation, paid CI run, or customer-data operation occurred.
- Application and business engine files are byte-for-byte unchanged relative to the V2.0 working baseline. Only the isolated PostgreSQL gate runtime, its CI runner, manually-triggered workflow and dedicated gate tests were updated.
- No PostgreSQL server, `psql`/`pg_ctl`/`initdb`, or `psycopg` driver is installed in the execution environment. DNS for the Debian/PyPI package hosts is not available. PostgreSQL live statements were **NOT EXECUTED**.

## Newly diagnosed security-verification defects and corrections

1. **False-positive negative tests**: the V2.0 `_is_expected_error` accepted *any* `psycopg.Error`. A missing table, malformed SQL, dropped connection, or server malfunction could be mistaken for RLS enforcement. V2.1 requires an explicit SQLSTATE: `42501` for privilege/RLS denial, `P0001` for rejected verified-session binding, and `42501` or `23503` for tenant/RLS/composite-FK denial. Unrelated SQLSTATEs now FAIL.
2. **False PASS after failed cleanup**: V2.0 could print PASS, then fail to drop its ephemeral database or global test role while still exiting successfully. V2.1 fails with exit code 1 when cleanup fails and only prints final PASS after teardown is successful.
3. **Unexpected billable GitHub Actions runs**: V2.0 workflow could also start on a branch push. V2.1 allows `workflow_dispatch` **only** and preserves an eight-minute job limit and read-only repository permissions. It is only a source candidate and was not uploaded or triggered.
4. **Untested re-tenanting of an A-owned row**: the SQL attack suite now attempts to change an unreferenced tenant-A customer row to tenant-B. This isolates RLS's `WITH CHECK` from composite-FK errors, preventing misleading pass due solely to FK rejection.
5. **Unverified server major version**: the ephemeral runner now verifies PostgreSQL **17** before provisioning the test objects, and reports the engine without showing secrets.

## Repeatable test evidence

| Check | Result | Meaning |
|---|---|---|
| Security/auth/backup and RLS offline tests | 73/73 PASS | Includes new SQLSTATE, cleanup, budgeting, and re-tenanting source-level tests |
| Existing quotes/workflows/automation tests | 48/48 PASS | SQLite app/business rules preserved |
| Missing-fields supplement | 21/21 PASS | Structured upload review/regression preserved |
| Smart-import parser tests | 37/37 PASS | Structured PDF/XLSX import regression preserved |
| **Total** | **179/179 PASS** | Separate test groups, not PG runtime verification |
| Python syntax and `node --check` | PASS | Checked locally |
| PostgreSQL live catalog and attack tests | **NOT RUN** | Requires isolated PostgreSQL 17 plus psycopg |
| Existing PostgreSQL application adapter | **NOT IMPLEMENTED** | Production remains SQLite and gated |
| Penetration test on deployed system | **NOT RUN** | No production authorization or live environment |

### Exact local regression commands

```bash
PYTHONPATH=. pytest -q tests/test_pg_rls_v19.py tests/test_pg_rls_v20.py tests/test_pg_rls_v21.py tests/test_rls_plan_v18.py tests/test_security_hardening_v17.py tests/test_security_v18.py tests/test_security_center.py tests/test_secure_backup_v18.py tests/test_encrypted_evidence_v17.py tests/test_security.py
PYTHONPATH=. pytest -q tests/test_workflows.py tests/test_quote_import.py tests/test_automation_entry.py
PYTHONPATH=. pytest -q tests/test_import_supplement.py
PYTHONPATH=. pytest -q tests/test_smart_import.py
node --check app/static/app.js
python -m py_compile scripts/run_postgres_isolation_ci.py scripts/test_postgres_rls_runtime.py scripts/check_postgres_rls.py app/main.py
```

### Real PostgreSQL attack gate — NOT EXECUTED here

- Use **only a disposable PostgreSQL 17 CI service**, not an existing user DB. The candidate workflow `.github/workflows/pg-rls-attack-gate.yml` uses one temporary PG 17 service and `workflow_dispatch` only.
- If manually approved and published later to a dedicated review branch, execute the workflow on that branch after checking current Actions usage and stop-on-budget-limit settings.
- Require logs showing exact code SHA, Postgres version, setup, RLS catalog, all cross-tenant denial tests, transaction replay tests, and successful cleanup. Exit 0 alone without complete evidence is not an operations approval.
- The runner refuses absent `JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE`, explicit loopback admin DSN, wrong server version, pre-existing non-template databases / non-system roles / public tables, or pre-existing `jw_app` role. A genuine provision/test/teardown failure must return 1; missing environment returns 2 (NOT RUN).
- Protect user budget: no automatic CI on `push`, no scheduled CI. Hosting CI may incur charges; no charge was initiated here.

## Mandatory remaining tasks before business use

1. Actually execute the disposable Postgres 17 RLS attack suite, remediate runtime failures and preserve reproducible evidence.
2. Implement the **entire** FastAPI persistence adapter and tested migration from existing SQLite records; current SQL fixture is synthetic and not evidence of a compatible production schema.
3. Prove role separation and tenant-isolated connection pooling with MFA session lifetimes, reconnection, cancellation, multiple isolation levels, safe migration rollback, key rotation and append-only audit writer.
4. Complete employee RBAC, encrypted data and backup retention, malicious file screening with external isolation, external penetration test and production monitoring before any customer PII.

**No real customer documents should be used with this test candidate.**
