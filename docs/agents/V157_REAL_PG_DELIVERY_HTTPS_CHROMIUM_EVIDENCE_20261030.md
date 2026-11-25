# V15.7 — Actual PG17 two-connection delivery HTTP + Chromium HTTPS proof

Date: 2026-10-30 KST. Protected origin Draft PR #69 / SHA `d9354df0d7a0cf11df91ac6c461ad1aa3edd5e80`.

## Source delivered

- `scripts/review/v157_disposable_pg17_source.sql`: nine base synthetic tables, RLS, identity functions, distinct admin A/B + member A, source orders, invoice/ledger audit. Intended **ONLY** for a freshly provisioned GitHub Actions ephemeral PostgreSQL 17 service, never shared DEV/prod.
- `scripts/ci_v157_real_pg_delivery_http.py`: guarded PostgreSQL 17 fresh-cluster preflight, nonprivileged `jw_ci_v157_trade` login and separate `jw_app_dev` role, **actual** V15.1/2 private ledger DDL, V15.3 six restricted RLS policies, V15.4 actual POST and V15.5 GET; synthetic, independent HMAC signatures in process memory for testing only, actual source invoice preview, real concurrent TCP PostgreSQL writes and transaction rollback.
- `.github/workflows/jw-v157-real-pg-delivery-acceptance.yml`: 9-minute ceiling, `postgres:17` ephemeral container, exact-source Git checkout, guarded localhost-only PostgreSQL credentials, artifact for Chromium screenshot. No real Supabase credentials, no deployment, no production privileges.

## Actually verified GitHub-hosted execution

Full successful GitHub Actions run **[41070305453](https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/41070305453)**, HEAD `7f46de98524edbf85f132213962b7f075277c0fb`.

- `PASS_V157_REAL_PG17_TWO_TCP_DELIVERY_POST_ONE_201_ONE_409`: independent HTTPS TestClient POST sessions with **two live PostgreSQL TCP connections competing on same order**; exactly one 201, one 409. Exactly one receipt, two nonce rows, one source item row, one actor-scoped audit entry, zero posted invoices. Replay 409, unauthenticated/CSRF/origin/member errors denied.
- `PASS_V157_REAL_HTTP_GET_A_ADMIN_B_FOREIGN_MEMBER_FORBIDDEN`: real restricted role and FORCE RLS; A admin reads review, B admin does not read A, A member cannot read or mutate; registered admin HTML page protected.
- `PASS_V157_DB_ATOMIC_RECEIPT_NONCE_LINE_AUDIT_AND_INJECTED_ROLLBACK`: tested malicious invalid signature rejection with zero residue; second order B has server-side trigger injecting audit failure after receipt/nonce/item inserts, full transaction rollback leaves no rows for B.
- `PASS_V157_NO_INVOICE_NO_PAYMENT_NO_PHYSICAL_DELIVERY_CLAIM`: no customer invoice, no payment posting and no physical delivery certification produced by review.
- `PASS_V157_CHROMIUM_REAL_LOCAL_HTTPS_PG_UI_320_390_768_1280`: launched temporary Uvicorn HTTPS server using a fresh self-signed localhost certificate, connected **actual Chromium** to the live API and PG17, tested responsive 320/390/768/1280px, accessible order input, invalid ID, real pending-review GET, and saved Chromium screenshot; member access denied.
- `PASS_V157_BROWSER_MEMBER_FORBIDDEN_AND_REVIEW_ONLY_STATUS`: browser member session denied; only pending review, never approval.
- Protected source and compilation steps PASS.

Initial run **[41069614736](https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/41069614736)** failed at administrator HTML due to a synthetic `__Host-` cookie not being delivered by modern TestClient CookieJar. Added exact diagnostic in **[41069794945](https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/41069794945)** and confirmed HTTP 401 `PostgreSQL session cookie required`. Fixed synthetic HTTPS client to send the explicit `Cookie` header; subsequent real PG HTTP test **[41069967691](https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/41069967691)** SUCCESS. Then added live Chromium + local TLS browser tests. Never altered production cookie security configuration; synthetic fixture corrected instead. Regression prevention: test session delivery explicitly and include real browser cookie with Secure and `__Host-` host-only prefix.

## IMPORTANT scope / unreached acceptance

- V15 private ledger was **actually installed** only in disposable PG17. It remains absent from long-lived Supabase DEV per protected persistent-schema policy. No app grant/role/DDL/change remained there.
- The independent dispatch/receipt HMAC keys were **synthetically generated inside CI**. This verifies cryptography and replay logic, **not authentic independent physical shipment**, third-party issuer trust, company registry validation or genuine email ownership.
- The HTTPS certificate is self-signed and Chromium explicitly permitted it **for isolated test only**. This is not the current publicly trusted Render staging version.
- The current V15.7 script seeds a synthetic quote and source fulfilled order. It exercises real evidence POST/GET and approval queue but not a third-party approved customer onboarding, quote-to-order full business approval, invoice/payment posting or reconciliation.
- Full previously passing J1–J6 workflow: [41066150153](https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/41066150153), SHA `d9354df0`, 1,215/1,215, 7/7; V15.7 exact-SHA full-run must be checked separately before claiming that entire SHA passed.
- The new review data and own RLS claims are test-scope PASS. Overall product final release PASS is not asserted. No main merge, Render deploy, persistent Supabase grants/DDL, real data transfer or external trust root.
