# V16.3 — Approved persistent DEV ledger install and staging preparation

Run: 2026-10-31 KST, approval in current conversation. Supabase project: `jarvis-works-dev` (`rvymwwzclagvljnofyss`), PostgreSQL 17.11. No PROD DB, `main` merge, payment posting or actual customer records.

## Exact source / migration

Migration `jw_v163_dev_review_ledger_restricted_writer_20261031` applied successfully via Supabase MCP to **DEV only**. Source was assembled unchanged from protected V16.2 review HEAD `b8313109a623c2cf86af86d36ae42bf8f95e7574` original V151/V153/V159 SQL, with guarded preconditions and postconditions. Reviewed, committed script: `scripts/review/v163_dev_review_ledger_approved.sql`. Reversal: `scripts/review/v163_dev_review_ledger_reversal.sql`.

Pre-install: **35 ordinary tables / 35 FORCE RLS / 40 policies**, zero orders/audits, no V151 ledger and no writer role. Full DDL tested using `BEGIN` → exact SQL → security assertions → `ROLLBACK`; once the expected count was corrected from 55 to 56 (V153 six policies + V159 ten), returned `PASS_ROLLBACK_PREFLIGHT_35_40_TO_40_56` and `restored=true`. Original DEV structures preserved after preview.

Approved persistent install: **40 tables / 40 FORCE RLS / 56 policies**, all five new V151 tables empty. Dedicated `jw_delivery_writer_v159` = `NOLOGIN NOINHERIT NOBYPASSRLS`; table SELECT+INSERT on reviews, no source-order UPDATE. Generic `jw_app_dev` has SELECT but **NO review-ledger INSERT**; `anon`, `authenticated`, auth and staging trade-login principals also have no direct INSERT. A real transactional `SET LOCAL ROLE jw_app_dev; INSERT INTO jw_dev.review_delivery_receipts_v151 DEFAULT VALUES` negative test caught `insufficient_privilege`, printed `PASS_DEV_GENERAL_APP_REAL_INSERT_DENIED` and confirmed no forged rows. This is actual authorized DEV behavior, not simulated.

Rollback SQL was executed under `BEGIN` and then `ROLLBACK` as a **non-destructive restoration rehearsal**; result `V163_REVERSAL_SQL_TRANSACTIONALLY_VERIFIED`, persisted ledger still present and policy count 56. **This verifies schema reversibility but not a full physical database backup/PITR recovery.** The revert script has a hard stop if any new ledger has rows, to prevent silent deletion. Supabase migration history includes `20261031003953/jw_v163_dev_review_ledger_restricted_writer_20261031`. No real customer data migrated.

Security advisors show two new protected signup tables with RLS but no policies, alongside 7 preexisting protected auth/system tables, **INFO / intentional default deny**. Do not add permissions simply to silence RLS-no-policy INFO. Current stage MUST NOT be given writer credentials/issuer key acknowledgement until externally genuine independent issuers have been verified. A compromised dedicated writer SQL credential could forge receipt data if issued prematurely; that remains a release blocker.

## Render staging: preparation only

Approved existing isolated Render service: `srv-dbi2l8qfngtc73c47phg`, `jw-stage1-secure-20261030`, free plan, autoDeploy=NO, URL `https://jw-stage1-secure-20261030.onrender.com`. Its original branch `review/v131-abc-finance-rollback-20261030` pointed to `92afea924d14b05e84a107b91db58250cc00f885`. The branch is an ancestor of V16.2 by 137 commits, with no divergence; fast-forward verified. Recovery reference `backup/jw-stage1-v131-before-v162-20261031` created before moving the stage branch forward with a non-force expected-SHA lease to `b8313109a623c2cf86af86d36ae42bf8f95e7574`. `main` remains protected.

**No Render deploy yet.** `mcp__Render__trigger_deploy(serviceId)` was attempted but returned `no workspace selected`. Render connector requires the USER to confirm workspace even if only one exists. `list_workspaces` returned one workspace `My Workspace` (`tea-dbeoq3qvcj2c73dlb180`), matching the target service ownerId, but the assistant must not choose it on its own. Once the user confirms `My Workspace`, request a manual deploy of that exact service with its confirmed workspace ID, check the SHA in Render deployment, inspect logs and test `/healthz`, 403 unauthorized API, HTTPS/TLS and actual authenticated test sessions if access key is available. Keep issuer/writer mode OFF and no real financial posting.

If stage deploy fails, service can be rolled back using the saved `backup/jw-stage1-v131-before-v162-20261031` reference and a conditional expected-SHA update, then manual redeploy in the user-confirmed workspace. Do not auto-roll back the saved branch without comparing current refs. Do not claim hosted E2E PASS until actually executed.

## Verdict

- DEV V151/V153/V159 persistent migration + verified RLS/privileges: **PASS in tested scope**
- DEV transaction and reversal SQL dry run: **PASS in tested scope**
- Full physical backup/PITR, external issuer provenance, trusted hosted V16.2 HTTPS authentication/browser E2E and operational sign-off: **NOT RUN / BLOCKED** until corresponding provider and workspace access
- Protected `main`, PROD DB, real-data migration, paid new Render service: **NOT TOUCHED**
