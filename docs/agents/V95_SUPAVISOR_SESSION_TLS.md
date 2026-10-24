# V9.5 — user-confirmed Supavisor session pooler readiness (J1–J6)

**Exact user-confirmed parameters** (2026-10-25 KST):
- Host: `aws-0-ap-northeast-2.pooler.supabase.com`
- Port: `5432` (**session pooler**, not transaction pooler 6543)
- Database: `postgres`
- Administrative dashboard username: `postgres.rvymwwzclagvljnofyss`

The above administrative user is **not** the application trading or authentication role. The app must preserve its reviewed restricted `jw_trade_gateway_v90` and `jw_auth_gateway_v90` roles with correct Supavisor username mapping; do not use a `postgres` superuser as a routine app principal. No password, DSN or key was requested or committed.

## Executed tests and exact trust meaning
The read-only probe `scripts/ci_v95_supavisor_session_tls.py` contacts only the exact approved pooler DNS and port, classifies DNS families and TCP, sends PostgreSQL SSLRequest and validates TLS with CA trust chain plus hostname. It sends **no StartupMessage, username, password or SQL**, never inserts Supabase rows and never changes RLS. A TLS success proves **transport only**; no evidence of authenticated Postgres or least-privilege tenant authorization.

No bypass of `sslmode=verify-full`, no paid IPv4 add-on, no guessed endpoint and no production deploy. Full J1–J6 browser/restore/regression remains on original synthetic PG17 until real, secured role-specific authentication is independently verified.

## Release blockers after TCP/TLS
1. Proven, trusted real Supavisor session pooler TLS and certificate/hostname.
2. Approved restricted-account credentials installed exclusively via secret manager and proper pooler username mapping; no secrets in GitHub artifacts, CLI logs, chats or repository.
3. Real nonprivileged app authentication/authorization and finance+messenger database E2E across customer orgs.
4. Deployed HTTPS app, representative data migration and real restore RPO/RTO, signed independent review.

**Launch decision remains BLOCKED until each relevant acceptance gate has genuine evidence.**
