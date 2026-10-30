# JARVIS-WORKS V143 — Real hosted PostgreSQL authentication review evidence
Date: 2026-10-30 KST. Scope: isolated **DEV** staging only, not production.

**Exact code SHA:** `5e4d16cdb0831ec3c4acb6358f30d4b75f12f1fb`
**GitHub J1–J6 CI:** https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/41034324504
- 7/7 completed successfully, whole-product suite **1,045 PASS / 0 FAIL / 0 SKIP**, including seven new V143 regression tests.
- No main merge and no production release. CI success is not independent reviewer signoff or a protected release receipt.

## Real evidence on existing isolated Render HTTPS service
- Deployed SHA `5e4d16c...` on `jw-stage1-secure-20261030.onrender.com`, successful temporary test deployment `dep-dbi6au7lk1mc73fdkm0g`.
- App log: `STAGE1_REAL_PG_ROLE_PROBE=PASS checkpoint=BOTH_SEPARATE_REAL_ROLE_CONNECTIONS`.
- App log: `STAGE1_HOSTED_HTTPS_NEGATIVE=PASS_HOSTED_HTTPS_STAGE_GATE_NO_SESSION_FORGED_SESSION`.
- App log: `STAGE2_HOSTED_AUTH_HTTPS=PASS_HOSTED_V143_PG_LOGIN_LOGOUT_CSRF_MFA_RECOVERY_REPLAY`.
- Test used only two invalid.test synthetic DEV accounts, actual V8.5 PostgreSQL auth role and cookie-based V9.0 business role; proved invalid-password rejection, valid A login, secure/HttpOnly/SameSite strict cookie, verified A org, wrong-CSRF logout denied, valid logout, revoked A cookie denied, B MFA required, wrong recovery denied, correct recovery accepted once, B login and logout, recovery-code replay denied. Actual external HTTPS requests, **not** in-process mocking.
- Never displayed environment access key, raw cookie, real DSN or user credential in logs. Synthetic password/recovery code appear only in test-only private repository; no real account used.

## Fixture cleanup and isolation
- Seed artifact: `scripts/review/v143_synthetic_auth_https_seed.sql`, guard requires an empty DEV business/auth schema; generated TEST PBKDF2 hashes.
- Cleanup: `scripts/review/v143_synthetic_auth_https_cleanup.sql`, exact synthetic IDs only; independent actual cleanup verdict **PASS_V143_AUTH_FIXTURE_CLEANED**.
- Independent read after cleanup: organizations, users, sessions, login_failures, security_events, mfa_credentials, mfa_recovery_codes, messenger messages, messenger attachments, customers, quotes, payments — all **zero**.
- The one-time feature `JW_STAGE2_AUTH_HTTPS_PROBE` was set back to the empty string and Render redeploy was requested. The final deploy status should be checked separately before concluding shutdown; none of the fixture accounts survive.
- Previous direct DEV SQL Stage 2 verified unique business registration and normalized email uniqueness, session issuance/revoke, CSRF and MFA replay in rollback. Those SQL-only tests do not prove actual hosted signup or all browser flows.

## Original acceptance boundaries retained
- Stage 2 **technical HTTP auth core PASS**, **official stage remains PARTIAL**. Full company signup/registration, account ownership verification, mobile+desktop browser MFA UI, password reset, rate-limit and lockout end-to-end, and independent exact-SHA reviewer evidence remain to be proved.
- Stages 1 and 8 still require an authorized **independent** protected verifier and actual owner final-release signoff; owner willingness to approve verification work does not amount to signing an independent receipt.
- Stage 3 complete delivery note and downstream document chain, stage 4 real positive group/WSS and immutable history, stage 5 consented representative ground-truth OCR corpus (minimum 50 documents) and measured time savings, stage 6 end-to-end user browser flows, stage 7 representative RTO/RPO/p95 and recovery measurements remain incomplete. Do not promote them to PASS using synthetic CI results.
- Supabase security adviser currently lists seven internal auth tables with FORCE RLS and intentionally no direct SELECT policies as informational (not a public access approval). Performance adviser notes 36 unindexed foreign keys, informational; examine real query plans before adding indices.

## Failure prevention
- No unapproved role grants, RLS weakening, trigger suppression, main merge, actual customer data migration, production deployment or paid calls.
- Keep two-phase guard: local synthetic fixture/cleanup regression and actual DEV cleanup rehearsal must precede any public-stage synthetic session test.
- A historical test initially combined state-mutating revoke calls in a Boolean expression and yielded nondeterministic evaluation: use sequential statements and independent assertions, not side-effecting calls inside Boolean expressions.
- Real gateway deployment cutover may temporarily return 502: delay external probe after startup and allow at most one bounded transient retry. Never treat persistent 5xx as PASS.
- Re-read actual SQL outcome and Render logs. Maintain exact-SHA linkage between CI, isolated deployment and evidence receipt; report **BLOCKED** for missing independent signoff.
