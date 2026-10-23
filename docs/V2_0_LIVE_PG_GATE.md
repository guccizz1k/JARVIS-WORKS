# V2.0 live PostgreSQL gate — manual / isolated / no real data

This document is a runbook; it does not certify that tests have run.

1. Review `.github/workflows/pg-rls-attack-gate.yml`, `security/pg_rls_test_fixture.sql`, `security/postgres_rls_proposal.sql`, `scripts/check_postgres_rls.py`, `scripts/test_postgres_rls_runtime.py`, and `scripts/run_postgres_isolation_ci.py` together.
2. Trigger the workflow manually **on a private review branch**. The GitHub Actions job creates a fresh PostgreSQL 17 container service with fixture data generated in SQL. It **must not** receive any production credentials or customer datasets.
3. A single-use root DSN with `postgres` user and loopback host is accepted only if the cluster has no extra non-template databases, no non-system roles, no public relations, and no existing `jw_app`. Any mismatch is `NOT RUN`.
4. Runner creates an ephemeral DB named `jw_v20_test_<random>` and a dedicated least-privileged login role, applies fixture and policy, runs catalog audit and adversarial suite, then destroys its own objects.
5. All checks must PASS. Save exact Git commit, PG version, fixture checksum, DB role attributes and full logs; independently review a successful cross-tenant attempt as a **release blocker**, never as an expected exception.
6. Live RLS passing is *not* enough to operate the product. The FastAPI server currently uses SQLite, and deployment requires a PostgreSQL driver/pool, tenant-bound transactions, migration, rollback plan, encryption, RBAC, MFA auth-service integration and a real security assessment.
