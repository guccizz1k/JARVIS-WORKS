# V2.0 PostgreSQL live isolation attack gate — operator runbook

This is a **test-only** GitHub Actions gate, not a production deployment.

## Boundaries

- Current repository `main` and live website are unchanged. The action YAML is *only inside this local candidate ZIP*.
- Workflow event: push branch `feature/pg-rls-v2-0-gate` (an explicit, review-only branch), or `workflow_dispatch` when GitHub allows it. Push to any other branch does not trigger this action.
- A push of that branch containing this workflow will start a GitHub Actions job, subject to the user's monthly **Actions $5 hard budget** and `Stop usage when budget limit is reached` account setting. The gate can consume Actions minutes even on failure. No schedule or retries.
- GitHub job is time-bounded to 8 minutes, `contents: read`, Ubuntu runner and isolated PostgreSQL 17 service. Test password is explicitly ephemeral and must NEVER be reused for operational data.
- Provisions only randomly named `jw_v20_test_*` database, test-only role `jw_app`, dummy A/B organizations and documents. Refuses an existing `jw_app` role or non-local server address, and destroys the test database and role on completion. An interrupted CI runner is decommissioned, including its test service.

## Verified scope and limitations

- The application still uses SQLite, and PostgreSQL RLS applies only to synthetic fixtures in this gate.
- The RLS policy is verified from Postgres system catalog and real SQL A/B attacks only **if the job executes successfully**. Source regex/offline pytest results are not a substitute.
- The RLS test does not cover SQL injection fuzzing, network isolation of PDF workers, PostgreSQL connection pooling across workers, or production schema migration.
- `psycopg` is required only for this gate (`requirements-postgres-check.txt`).

## Manual local execution with existing temporary Postgres

From the V2.0 repo, on a disposable, local-only PostgreSQL server that has no `jw_app` role and is not a production DB:

```sh
python -m pip install -r requirements-postgres-check.txt
export JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE
export JW_PG_CI_ROOT_DSN='postgresql://postgres:<EPHEMERAL_PASSWORD>@127.0.0.1:5432/postgres'
PYTHONPATH=. python -m scripts.run_postgres_isolation_ci
```

The run is refused unless BOTH variables are present and the DB connection points at localhost, the maintenance database and the `postgres` administrator. Do not use an operational database. Exit `0` means all live checks passed; `1` means FAILED; `2` means NOT RUN. Do not report `0` from another utility as an RLS pass.

## Outstanding product migration

The test fixture is **not** a migration of the SQLite business schema. Composite foreign keys and per-tenant identity columns must be deployed by a reviewed additive migration with full backup/rollback and baseline conversion tests. `JW_ENV=production` stays blocked. The authentication subsystem that issues registry sessions and the append-only audit writer are separate services yet to be implemented.
