# V9.7 owner-controlled secret provisioning and independent checks

Review only, for Draft PR #17 / Issue #16. No deployment, merge, database DDL,
password reset, role changes, customer-row reads, or writes are authorized here.

The initial `gh secret list --json name` attempt was blocked by this execution
environment's GitHub API network policy (`Forbidden`). This is **UNKNOWN**, not
evidence that secrets are absent. The V9.7 Actions workflow now records only
these names and their `SET` / `MISSING` status before dependencies or login:

- `JW_V97_TRADE_DSN`
- `JW_V97_AUTH_DSN`

GitHub evaluates nonempty-secret expressions to booleans. The status step never
receives either DSN; the regression step also receives neither. Both must be
`SET` before the live step receives the secrets. Missing either produces
`decision=BLOCKED`, `live_attempted=false`, and no database connection. `SET`
means configured, not valid credentials. Read the JSON verdict, not the green
readiness job. Configured credentials that fail authentication or the boundary
gate cause the workflow to fail and still upload the safe verdict.

## Safe registration by the owner

Open the repository's [Actions secrets settings](https://github.com/guccizz1k/JARVIS-WORKS/settings/secrets/actions).
Choose **New repository secret** and enter each value directly into GitHub's
protected UI from the owner's existing approved credential store. Never paste
it into chat, an issue, a PR, a command argument/history, or source. This work
does not recover Vault plaintext or generate/reset/rotate a role password. If
the owner has no existing credential, the live acceptance remains BLOCKED.

The DSN for each named secret must use the corresponding existing role:

| Secret | Username |
| --- | --- |
| `JW_V97_TRADE_DSN` | `jw_trade_gateway_v90.rvymwwzclagvljnofyss` |
| `JW_V97_AUTH_DSN` | `jw_auth_gateway_v90.rvymwwzclagvljnofyss` |

Both target `aws-0-ap-northeast-2.pooler.supabase.com:5432`, database
`postgres`, and `sslmode=verify-full`. URI passwords must be percent-encoded.
No administrator, service-role or API key is accepted. The runner injects the
absolute pinned public CA path (`tests/certs/prod-ca-2021.crt`), validates its
DER SHA-256 `807025ad50d4ed219d2c9c7d299c004f824eb00cf7f65afef607d07b72e6cafa`,
and does not permit a different root, host, project, transaction port, or TLS
downgrade. Ambient `PG*` configuration is rejected by name to prevent libpq
service/options overrides.

## Acceptance and evidence scope

The existing V8.7 two-session role/TLS gate remains intact. After it succeeds,
new independent sessions recheck PG17, TLS, exact principals, LOGIN,
NOINHERIT, NOBYPASSRLS, forbidden cross-role membership and SET permissions,
fixed `SET LOCAL ROLE`, payment INSERT denial, and catalog ENABLE/FORCE RLS.
The business schema is `jw_dev`: its complete table-name set must match the
canonical 35 tables, with ENABLE RLS and FORCE RLS on all 35. Missing, extra,
disabled, or unforced tables block acceptance. `public` has no required business
tables; existing security checks still apply if canonical names appear there.
Both schema counts are observed from the catalog, not assumed constants.
It does not claim tenant-row isolation from catalog flags: that remains
`NOT RUN` for the live database until separately authorized fixture-based E2E.

Every live connection forces default read-only transactions and bounded
statement/lock/idle timeouts. SQL is catalog/privilege metadata plus transaction
local role changes; no customer data or business RPC is read/executed. Sessions
roll back and close. An authentication error must be diagnosed using redacted
failure codes; never repair it by broadening roles or weakening TLS.

After provisioning, run **JW V9.7 restricted Supavisor login readiness (review
only)** on `review/v97-restricted-supavisor-login-20261025`. Inspect artifacts
`jw-v97-secret-status.json`, `jw-v97-verdict.json` and `jw-v97-focused.xml`.
Only `decision=PASS` proves that the measured authenticated/catalog boundaries
passed. Full product live HTTPS/E2E and release approval remain separate
blockers. The unchanged seven-job J1–J6 workflow provides the original full
regression, real Chromium, ephemeral PG17 concurrency/restore and security gates.

Rollback is reverting the review-only V9.7 files. No database rollback or
credential rotation is required because these changes perform no persistent
database mutation. Keep `main` and the original J6 product hashes unchanged.
