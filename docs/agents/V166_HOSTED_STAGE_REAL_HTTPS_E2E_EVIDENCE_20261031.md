# V16.6 — approved REAL DEV / Render hosted HTTPS security and E2E verification

Date: 2026-10-31 KST. Authorized Render workspace **My Workspace**, ID `tea-dbeoq3qvcj2c73dlb180`. Scoped to existing FREE stage only `srv-dbi2l8qfngtc73c47phg`, no PROD or main merge. Exact running application code: `b8f22a90e7dcdfd8cbf8b738cc35205c160cf736` (Draft [PR #77](https://github.com/guccizz1k/JARVIS-WORKS/pull/77)). Original V16.2 business code: `b8313109a623c2cf86af86d36ae42bf8f95e7574`.

## Root cause / immutable protections

The approved DEV V151/V153/V159 migration added five review tables, changing `jw_dev` from 35 FORCE-RLS base tables/40 policies to **40 FORCE-RLS base tables/56 policies**. The existing V135 hosted preflight demanded `(35,35)`; first V16.2 deploy `dep-dbijllc9v7es73fpmdr0` was LIVE but returned `STAGE1_REAL_PG_ROLE_PROBE=BLOCKED checkpoint=TRADE_FORCED_RLS_CATALOG`. Crucially, the app was sealed rather than opening unsafe business routes.

V16.4 minimally changed only preflight code and tests: require exactly (40,40), verify all five new V151 tables independently with FORCE RLS, require `jw_delivery_writer_v159` nonlogin/nobypassrls, reject ordinary app/anon/authenticated INSERT on private ledger. Negative tests include missing one review forced-RLS, incorrect count, writer LOGIN and forged direct INSERT grant. GitHub [V16.4 strict 18/18 CI](https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/41152477856) SUCCESS 18 passed/0 failure/0 skip. GitHub [whole J1–J6](https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/41152477863) SUCCESS 7/7 jobs, full product 1,265 passed, 0 failed/0 skipped, independent aggregation PASS, **release BLOCKED** as required.

Exact V16.4 stage deployment `dep-dbijo56tlv9c73au3s70` became LIVE; server log `STAGE1_REAL_PG_ROLE_PROBE=PASS checkpoint=BOTH_SEPARATE_REAL_ROLE_CONNECTIONS`.

## Actual externally validated HTTPS and Chromium

[Run 41152728018](https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/41152728018), source SHA `4480c8205dfae60c851bcac3aa9bca255669e7f2`, remotely targeted deployed V16.4, verified publicly trusted HTTPS with TLS verification on, `/healthz` 200 `mode=isolated_pg_api_only` and `release=BLOCKED`; **24 distinct protected paths** rejected both missing and 96-character fake `X-JW-Stage-Key`, three unauthorized POSTs rejected, real Chromium verified 320/390/768/1280px health and private review-console denial. Markers:
- `PASS_V165_TRUSTED_PUBLIC_HTTPS_HEALTH_PG_MODE_NO_RELEASE`
- `PASS_V165_24_ENDPOINTS_PUBLIC_AND_FORGED_KEYS_REJECTED`
- `PASS_V165_CHROMIUM_4_VIEWPORTS_REAL_RENDER_TLS_AND_PUBLIC_GATE`

The already installed **read-only server-side** V140 HTTPS probe, using the server-only access key without printing it, produced `STAGE1_HOSTED_HTTPS_NEGATIVE=PASS_HOSTED_HTTPS_STAGE_GATE_NO_SESSION_FORGED_SESSION`: no stage key=403, valid stage key but missing session=401, valid stage key with forged session=401. No credential, raw response, session token, or private DSN was disclosed in evidence.

## Hosted A/B/C tenant session and cross-tenant write tests

DEV preconditions: organizations/users/sessions/customers/quotes/orders/invoices/payments/security events all zero, RLS policies 56. Rehearsed exact reviewed `v141_synthetic_abc_https_seed.sql` with transaction rollback (`PASS_V141_SEED_TRANSACTIONALLY_ROLLED_BACK`). Seeded three synthetic review companies/sessions and two quotes under explicit guard (`PASS_V141_ABC_HTTPS_FIXTURE_SEEDED`), then opted in to existing `JW_STAGE1_POSITIVE_HTTPS_PROBE` for a ONE-SHOT server-local test. Actual hosted Render logs:

`STAGE1_HOSTED_HTTPS_ABC_POSITIVE=PASS_HOSTED_HTTPS_ABC_POSITIVE_SESSIONS_RLS_CSRF_WRITE_DENIAL`

Verified real HTTPS signed-in A/B/C sessions, disjoint tenant customer and quote sets, missing CSRF POST=403, forged cross-company quote POST=404. Synthetic records immediately removed via reviewed `v141_synthetic_abc_https_cleanup.sql`: `PASS_V141_SYNTHETIC_ABC_CLEANUP`. This is NOT actual third-party-verified business identity.

## Hosted V143/V144 actual login, secure cookie, MFA and lockout

Checked empty DEV after prior cleanup. Rolled back a full dry-run of reviewed `v143_synthetic_auth_https_seed.sql` (`PASS_V143_SEED_ROLLBACK`), then installed only synthetic auth A/B subjects with review-only password hashes and MFA recovery fixture (`PASS_V143_SYNTHETIC_AUTH_FIXTURE_READY`). Disabled former A/B/C probe and enabled existing read-only-status V143/V144 **one-shot real HTTPS auth exercise** on the same Render service. Actual Render log:

`STAGE2_HOSTED_AUTH_HTTPS=PASS_HOSTED_V144_PG_LOGIN_LOGOUT_CSRF_MFA_RECOVERY_LOCKOUT`

Verified bad password 401, real PostgreSQL auth/login 200, Secure/HttpOnly/SameSite Strict `__Host-` cookie, tenant/CSRF validity, logout with wrong CSRF 403, correct CSRF 200, revoked session 401, repeated login 401 then 429 lockout, MFA challenge/recovery negative and valid recovery authentication, second logout and invalidated session. Review-only fixture cleanup via `v143_synthetic_auth_https_cleanup.sql` returned `PASS_V143_AUTH_FIXTURE_CLEANED`.

The two opt-in probes were then disabled by merging environment variables with empty values; **not replacing** existing DSNs or stage access key. This triggered the final no-probe deploy `dep-dbijsbflk1mc73eu20v0`, exact SHA `b8f22a90...`, **LIVE**. Final startup log:
`STAGE1_REAL_PG_ROLE_PROBE=PASS checkpoint=BOTH_SEPARATE_REAL_ROLE_CONNECTIONS` and final existing V140 safe probe
`STAGE1_HOSTED_HTTPS_NEGATIVE=PASS_HOSTED_HTTPS_STAGE_GATE_NO_SESSION_FORGED_SESSION`.

## Post-test data and release boundaries

After both cleanups, actual Supabase SQL returned **zero** for organizations, users, sessions, customers, quotes, orders, invoices, payments, MFA credentials/recovery, login failures, security events, audit logs, messenger messages, signup review requests and delivery receipts. Policies **56**, FORCE RLS tables **40**, `jw_delivery_writer_v159` still NOLOGIN and `jw_app_dev` still without direct review INSERT.

Render original SHA `92afea924d14b05e84a107b91db58250cc00f885` was preserved in `backup/jw-stage1-v131-before-v162-20261031`; stage branch was fast-forwarded with expected-SHA lease, never forced. Existing service remained on free plan, autoDeploy=no. All PRs remained Draft/unmerged, `main` and PROD/real customer data untouched.

**Acceptance scope:** V16.4 code CI PASS, DEV RLS and writer restriction PASS, real HTTPS ingress PASS, public-browser 4 widths PASS, actual server-key/no-session/forged session PASS, signed-in tenant A/B/C RLS+CSRF/foreign write denied PASS, real auth/login/logout/MFA/lockout PASS, fixture cleanup PASS, final stage LIVE and connected.

**Not tested / release BLOCKED:** actual external business registry and email ownership provider, actual independently signed physical delivery proofs, real bank reconciliation/settlement, human-approved end-to-end file OCR→confirmed order→delivery→invoice→payment posting under real customer accounts, physical Supabase backup/PITR recovery, full privileged authenticated browser UX, final independent security certification or PROD deployment. Synthetic dev fixtures never establish these. Never expose V159 writer login or issuer keys without authentic external trust verification.
