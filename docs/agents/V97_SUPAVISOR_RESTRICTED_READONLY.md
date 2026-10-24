# V9.7 restricted Supavisor login preflight — J1–J6

Previous V9.6 head 1288d095b17047ffa5554ed9b16670df635c3a41: real Supavisor CA+hostname VERIFIED, 722 full regressions PASS. Actual password-based DB login NOT YET VERIFIED.

From Supabase official "Connect to your database" docs, Session pooler custom usernames are ROLE.PROJECT_REF. Use only the existing v90 least-privilege auth and trade role accounts with project suffix rvymwwzclagvljnofyss, host aws-0-ap-northeast-2.pooler.supabase.com, port 5432, db postgres. Never use postgres.PROJECT_REF as normal app principal.

Provision two GitHub Actions repository secrets (no passwords in chats, code, screenshots or PR discussion):
- JW_V97_TRADE_DSN
- JW_V97_AUTH_DSN

Both DSNs must have distinct restricted role passwords and verified-full TLS. They can be provisioned by the owner through GitHub Settings → Secrets and variables → Actions. The assistant cannot recover unseen secrets from Supabase Vault or transfer them between systems.

Workflow jw-v97-restricted-supavisor.yml performs syntax/role/hostname/CA fingerprint validation, then calls the preserved V8.7 two-account read-only SQL probe. It uses SET TRANSACTION READ ONLY and SET LOCAL ROLE; no customer contents are read and transactions always roll back. No direct payment table INSERT is permitted.

An empty or malformed secret prints BLOCKED and never attempts authentication. The CI job may be green for successful **readiness** testing while the JSON has decision BLOCKED. Only decision PASS proves actual role-authenticated connection, and neither outcome authorizes production rollout.

J1 original app/database protected, J2 safe next-step dependency, J3 positive real proof requirement, J4 negative cases, J5 always rollback, J6 evidence not fabricated. No merge/deploy.
