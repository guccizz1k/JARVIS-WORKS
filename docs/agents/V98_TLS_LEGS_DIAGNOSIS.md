# V9.8 — classify Supavisor frontend/backend SSL difference before modifying V8.7 gate

Confirmed two GitHub repository Secrets provisioned by owner on 2026-10-25 and rerun of V9.7 same reviewed SHA e55c7523 (CI #40147764970, second attempt) yields 144 targeted tests PASS and actual **ROLE_GATE_REJECTED / tls_or_postgres_mismatch**. Do not interpret this as failed login: V8.7's LOGIN_PROBE reached server metadata and evaluated its backend TLS and PG major. The current gate requires the server-side pg_stat_ssl to be true, which may differ from client-side Supavisor verify-full TLS.

V9.8 performs only two authenticated restricted read-only transactions with forced verify-full to the exact accepted pooler and pinned official public CA. The diagnostic stores only booleans for backend pg_stat_ssl, PG major 17 and expected role/session identity; no SQL customer rows, credentials, usernames, PID, raw connection errors or privileged escalation. It does NOT alter existing V8.7 gate, Supabase roles, migrations or prod runtime.

**A verified client-to-pooler SSL connection must not be confused with a PostgreSQL backend ssl=true flag.** If backend reports false, any future correction must enforce actual libpq-side cryptographic SSL with the accepted root CA and expected hostname, and must not accept plaintext clients or disable verify-full. Legacy direct-connection tests must remain fail-closed.

This diagnostic's SUCCESS is not product authorization. No main merge, deploy or data modifications.
