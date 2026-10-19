# JARVIS WORKS V3.5 — FastAPI + PostgreSQL 17 integration laboratory

**Review branch only. NOT for production, not customer data, and never expose an HTTP server.**

## What actually exists

- `app/pg_messenger_lab.py` implements a separate, explicitly gated FastAPI app factory with GET messages, POST text messages, and PUT read watermark. It is **not mounted or imported by `app/main.py`** and does not change the normal SQLite runtime.
- Each request obtains a new PostgreSQL 17 transaction using the existing `MessengerReviewAdapter`. It binds a synthetic MFA-verified, revocable PG session and uses the live V2.7/V2.8 RLS predicates. Clients cannot choose organization, sender, or employee identity.
- `scripts/test_postgres_api_lab_v35.py` runs TestClient (no listening socket) against the same disposable synthetic PG17 database only **after** the existing V2.8 RLS attacks succeed. It checks bilateral A/B access, C isolation, text send, read marker, duplicate idempotency request denial, missing auth, and immediate session revocation.
- `scripts/run_pg17_codespaces_v35.sh` reuses the existing Docker-based disposable PG17 harness. It sets an opt-in flag so the V3.5 lab executes after the unchanged V2.8 gate. The V2.8 runner remains V2.8-only when the flag is not set.
- `tests/test_pg_api_lab_v35.py` checks the lab's HTTP contract, fail-closed boot guard, no exposure through the SQLite app, 401/403/422/503 failures and redaction. These **are mock-based**, not a replacement for real PG testing.

## One command in an existing Codespace

After pulling the private review branch, assuming Docker works and free usage is confirmed:

```bash
bash scripts/run_pg17_codespaces_v35.sh
```

Results must show `PASS: V3.5 FastAPI TestClient + real PG17 ...`, followed by the existing final ephemeral cleanup PASS. Exit 1 is FAIL and exit 2 NOT RUN. The script uses a random loopback-only disposable PostgreSQL 17 Docker container, synthetic test users and passwords, ephemeral PostgreSQL DB/role and teardown. It does not publish a port. GitHub Actions is **not** auto-dispatched.

## Hard limitations

- V3.5 here is a **lab integration, not a production FastAPI adapter rollout**. Main app authorization is still SQLite. No full-history/attachment/document transfer to PostgreSQL, migration/rollback, binary file scanning, durable production PG session issuer, MFA onboarding, production backups, resilience/load audit, external security review or deployment has been implemented.
- Real PG17 TestClient integration remains **NOT RUN until actual Codespaces terminal proof**. Offline mock tests and the prior successful V2.8 database security test do not prove these new HTTP endpoints.
- No real user files or customer information are permitted. No deployment, main merge, PR, or billable job is authorized by this review candidate.

## Actual live execution evidence — 2026-10-20 (user-provided Codespaces screenshot)

**Observed outcome: PASS for the disposable PostgreSQL 17 laboratory only.** In a Codespace on the V3.5 review candidate (local short branch `v35`, after fetching the remote V3.5 tip), the terminal showed:

- `PASS: V2.8 live checksum, sender binding, message kinds, server read-time, monotonic cursors`
- `PASS: V3.5 FastAPI TestClient + real PG17 tenant isolation, writes, reads, idempotency, revocation`
- `PASS: ephemeral PG legacy + V2.7 + V2.8 integrity attacks; cleanup confirmed`
- `PASS: PostgreSQL 17 live RLS attacks and ephemeral cleanup completed`

This is **user-supplied terminal screenshot evidence**, not a directly retrieved machine-verifiable log or CI run. It validates the specific disposable lab test, not the production FastAPI/SQLite application's PostgreSQL integration, production credentials, actual company enrollment, scalability, migration, backup/restore or customer data handling.

The terminal's editor warning about an unrelated older test-encoding file is not proof of a code or test failure. The actual V3.5 test process exited back to the shell after printing PASS and cleanup; the test was not left running.

Next gating work: verify a synthetic SQLite→PostgreSQL migration with exact data and attachment hashes, a rollback path, and full API behavior using transaction-bound identity. Keep the production/main SQLite runtime unchanged until these tests pass.

