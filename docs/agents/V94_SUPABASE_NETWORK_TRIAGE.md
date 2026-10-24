# JARVIS WORKS V9.4 — actual Supabase DB network blocker triage

**Baseline:** V9.3 exact 697-PASS J1–J6 full run: `802128f55a673d10f588988f68571eb27e4d8c51`. No production deploy or schema changes.

## Checked error
V9.3 CI on the real dev Supabase **direct** host `db.rvymwwzclagvljnofyss.supabase.co:5432` logged `OSError`, TLS BLOCKED. A generic OSError cannot establish whether the root cause was IPv6 routing, DNS, a refused connection or TLS.
Supabase documentation confirms **direct endpoints default to IPv6** and recommends the dashboard-provided **Supavisor session-mode endpoint** for IPv4-only persistent app servers. An IPv4 add-on may be billable and is NOT authorized.

## J1–J6 fail-closed triage
V9.4 adds hostname-pinned, no-password/no-SQL DNS address-family and error-code diagnostics before the PostgreSQL SSLRequest. It never reports remote IPs, user data, TLS certificates, DSNs or passwords. CA and hostname verification remain REQUIRED. The diagnostic must never be read as a successful real DB connection.
For an IPv6-only endpoint with no route, the next safe operational step is to provision an IPv6-capable authorized runtime or obtain the **EXACT** Supavisor session-mode host/port/user from the user's Supabase Dashboard **Connect** pane and manage its database credentials/CA outside Git. **Do not guess the pooler host from region**, do not use the public service key, and do not disable verify-full.

## Release gate
- DNS- and socket-level success are not PG authentication.
- A CA-verified SSL handshake alone is not PG authentication.
- Stage PostgreSQL read/write tested with synthetic PG17, not authenticated real Supabase session pooler.
- No production approval until exact login role, server CA/hostname, real HTTPS runtime, full finance/auth/messenger tests and representative restore are independently verified.
