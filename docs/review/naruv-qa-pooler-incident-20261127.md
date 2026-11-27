# Isolated QA pooler incident — 2026-11-27
Scope: naruv-one-isolated-qa, PostgreSQL 17.12; no production, main, UI, backup, or key changes.
Prior candidate: 9e5244c673f9c3942235bca4c857487cb2c87361.

## Preserved acceptance evidence
Owner Codespaces output: all three independent role logins and role boundaries PASS; cleanup PASS. Actual provider catalog readback: three original roles intact, no temporary roles or sessions; two QA marker rows. Logs show three authentication rejections after NOLOGIN and before DROP ROLE, then all three pool shutdowns. Exact old-password post-DROP client rejection is UNPROVEN; do not equate arbitrary-password tests with it.

## Incident
2026-11-27 17:33–17:38 KST: 34 Supavisor econnrefused log records, including 27 backend TCP failures, 5 checkout failures and 2 auth-path failures, SQLSTATE 08006. No password failure in that interval. Backend endpoint matches inet_server_addr() and port 5432. Management SQL healthy; 10 client backends vs max_connections 60; no connection-limit errors observed. Two get_secrets circuit breaker events at 17:28 KST precede this incident. Causation of later TCP failures is not proven. Do not bypass protection, rotate passwords again, repeatedly probe, or purchase IPv4. Wait for provider-supported recovery; one known-good control login only after protection clears. Provider support if persistent.

## Hosted workload cleanup constraint
Actual installed catalog: 28 active immutable triggers on 28 tables; 5 initially-deferred non-internal triggers. Management role was denied EXECUTE on internal immutable trigger function (42501). A rollback-only temporary table using the already authorized function owner confirmed update/delete both rejected and original value retained. No permanent schema change. Do not disable triggers, RLS or truncate protected tables. Run rollback-only synthetic transactions and SET CONSTRAINTS ALL IMMEDIATE before rollback to exercise deferred checks. This cannot attest committed concurrent workload. A separately authorized disposable hosted database/project or a separately designed cleanup strategy is needed for committed ERP load testing, without touching the installed QA schema.

## Verdict
Prior independent login PASS preserved. Cleanup catalog PASS; original credential post-DROP rejection BLOCKED; current pooler control login BLOCKED; hosted ERP workload NOT RUN. Gate5 BLOCKED. No extra paid service. Do not repeat successful login tests solely to reproduce evidence.
