# JARVIS-WORKS V144 — verified live HTTPS auth and residual release blockers
Date: 2026-10-30 (Asia/Seoul)
Scope: private review only. Latest reviewed implementation `92afea924d14b05e84a107b91db58250cc00f885`. Draft PR #57 (no main merge).

## Proven with actual services
- Render isolated free HTTPS `jw-stage1-secure-20261030.onrender.com`, build/deploy `dep-dbi6h57b9u1s73dnsfkg` LIVE while the one-shot V144 probe ran.
- Actual Supabase `jw_dev` using separate RLS-enforced PostgreSQL auth and business logins, `verify-full` TLS trust pinned to public CA.
- At 2026-10-30T09:52:56Z Render app log: `STAGE2_HOSTED_AUTH_HTTPS=PASS_HOSTED_V144_PG_LOGIN_LOGOUT_CSRF_MFA_RECOVERY_LOCKOUT`.
- End-to-end HTTPS observations: bad password 401, valid A login 200 and secured cookie, identity A GET 200, incorrect-CSRF logout 403 and session remains usable, valid-CSRF logout 200 and revoked session 401; after successful login resets failures, five wrong attempts 401, sixth wrong 429, correct password during lockout 429; B requires MFA, incorrect recovery denied 401, correct one-time recovery 200, duplicate consumed recovery denied 401; B logout 200.
- Original V143 one-shot proof at 2026-10-30T09:43:38Z passed HTTPS login/logout/CSRF/MFA recovery reuse; V144 added and tested live lockout.
- Synthetic-only fixture issued against confirmed empty DB via `scripts/review/v143_synthetic_auth_https_seed.sql`, with `PASS_V143_SYNTHETIC_AUTH_FIXTURE_READY`. Paired `scripts/review/v143_synthetic_auth_https_cleanup.sql` returned `PASS_V143_AUTH_FIXTURE_CLEANED` on BOTH runs. After V144, 12 checked dimensions including organizations, users, sessions, MFA devices/recovery codes, login failure counters, audit events, customers, quotes, messenger messages and attachments each 0 rows. Verified 35 FORCE RLS tables unchanged.
- One-shot V143/V144 probe `JW_STAGE2_AUTH_HTTPS_PROBE` cleared (empty), and a new Render deployment triggered to return to no-probe steady state.
- Full GitHub J1–J6 run 41036019163 7/7 success; `full-product` job 123996922573: 1,045 passed, 0 failed, 0 skipped. https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/41036019163
- No passwords/DSNs copied into this evidence report. No production merge, production deployment, customer migration, paid API invocation or release signature.

## Independent findings and remaining binding acceptance conditions
1. **Stage 1** A/B/C RLS real DB and hosted HTTPS technically passed and cleanly rolled back (see V142 evidence). An **independent exact-SHA protected evidence signature** is not issued. Self-review, CI green, or this document cannot substitute.
2. **Stage 2** Separate real hosted PostgreSQL auth login/logout/MFA recovery and 15-minute lockout is now PASS for synthetic accounts. Full **company creation, business verification and duplicate company signup**, user account recovery with real browser, and independently signed release evidence remain unproven. Do not inflate to final stage PASS.
3. **Stage 3** Existing V13.1 rollback-tested quote/order/invoice/payment ledger and CI disposable PG17 HTTPS finance routes PASS in that limited environment. Real Render-positive quote→order write/approval cannot be safely completed on shared development DB: `jw_dev.audit_logs` has immutable DELETE/UPDATE rejection trigger `jw_v82_audit_immutable`; committing quote creation leaves non-deletable audit rows. Use only an isolated disposable database with safe teardown, NOT disabled triggers/DELETE bypass.
4. **Stage 4** Real DEV transaction-only V90 messenger edit, replay idempotence, cursor sync and cross-company denial passed; hosted positive WSS + attachment/full history lifecycle still needs a disposable DB because of immutable messenger records.
5. **Stage 5** Existing synthetic OCR benchmark (40 XLSX + 3 PNG) is NOT a representative 50+ independently labelled real-document dataset. Required exact accounting, capture accuracy, injection resistance, human approval and measured time savings remain unproven. Do not generate claimed accuracy.
6. **Stage 6** Host HTTPS stage-key, forged-cookie, CSRF and A/B/C identity isolation passed; representative desktop full browser and live WSS complete workflows remain to be evidenced.
7. **Stage 7** PostgreSQL CI disposable restore, concurrency, fault checks passed. No representative deployment p95/RTO/RPO capacity and real migration rollback was measured and signed.
8. **Stage 8** Production rollout, main merge, real customer migration and final independent signoff remain blocked pending verified 1–7 acceptance and separate user release authorization.

## Error / regression prevention
- Never pass historical unfinished fixture results as new execution.
- A past V14.2 fixture synchronised a synthetic messenger message with no cursor; fix used real v90_send_text to obtain message cursor before checking sync. Stateful revocation assertions must execute sequentially.
- V143 synthetic password/recovery hashes were verified against 260,000-round PBKDF2-SHA256 and v85 recovery_hash; 7/7 CI and real HTTPS success independently corroborated it.
- V144 lockout test verifies five post-success password failures, sixth 429 and correct password 429, without modifying product auth code or RLS policy. Hashing/cookie content must not be logged.
- Never disable PostgreSQL FORCE RLS, immutable audit/message triggers, independent J1–J6 guards or release signature controls merely to pass a test.
