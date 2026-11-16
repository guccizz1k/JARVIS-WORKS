# JARVIS-WORKS V22.3 — safe public QA deployment prerequisites (NO DEPLOY)

This document is an **implementation and security readiness artifact**, not
authorization or evidence that a Render service was created or deployed.

## Why an old Render service cannot be reused as proof
The existing isolated QA Render service is pinned to a different review branch
and starts `uvicorn app.main:app`. The current owner-review candidate uses
`uvicorn app.owner_review_app_v223:app`. Both use the protected **SQLite**
business engine. A URL returning 200 or 401 only proves transport and
anonymous session enforcement; it is NOT a live PG17 transaction test.

Never change the old service, prod service, main, operational DB, DNS, public
allowlist, existing credentials, or prices to make a CI step green.

## Isolated publicly reachable QA service — deployment requirements
A separate service must be owner-authorized and explicitly free-tier.
The application has an optional fail-closed Basic authentication perimeter
in `app.owner_review_public_qa_guard_v223`. It applies to every mounted
business/account/UI route when `JW_PUBLIC_QA_MODE=1`.

- Git: `guccizz1k/JARVIS-WORKS` using exact frozen **review** SHA.
- Render runtime: Python; region: Singapore; **plan: free only**; **autoDeploy: no**.
- Build: `pip install --disable-pip-version-check -r requirements-dev.txt`
- Start: `uvicorn app.owner_review_app_v223:app --host 0.0.0.0 --port $PORT`
- `JW_PUBLIC_QA_MODE=1`
- `JW_ENV=review`
- `JW_ROOT_UI=owner-visual-review`
- `JW_APPROVED_UI_REVIEW=ISOLATED_REVIEW_ONLY`
- `JW_NO_EXTERNAL_DATABASE=1`, `JW_NO_PAID_MODEL_RUNTIME=1`, `DEMO_SEED=1`
- `JARVIS_DB_PATH=/tmp/jw-v223-qa-<random-nonce>.sqlite3`
- `JW_REVIEW_BASIC_USER`: nonsecret unique ASCII QA username, 4–40 chars
- `JW_REVIEW_BASIC_PASSWORD`: independent randomly generated long unique secret,
  at least 24 chars, provided **only** as a Render environment secret;
  never in the repository, code, GitHub issue, chat or CI logs.
- **Never** configure `DATABASE_URL`, `JW_PG_STAGE_DSN`, `JW_PG_SOURCE_DSN`,
  `JW_PG_BACKUP_KEY`, `SUPABASE_SERVICE_ROLE_KEY` or any live customer DSN.
- The dummy database and all files must be wiped at QA service decommission.
  This is test-only and not durable, suitable for no real customer data.

The app fails at startup if this guard is enabled without review-only mode,
isolated disposable SQLite path, explicit dummy seed, safe flags and protected
QA credentials. All routes except GET/HEAD `/api/health` require separate
HTTP Basic authentication before any business session authentication. Even
after Basic authentication, the business session, tenant, CSRF and admin
authorization checks still apply.

## Required PASS evidence on a *deployed* review SHA
1. Render deployment is LIVE at the exact SHA, no pending background deployment.
2. Anonymous GET `/api/health`=200; `/api/me`=401. Other data routes and
   root UI must be 401 without the secondary QA Basic authentication.
3. Authorized QA Basic + business login → tenant-specific workflow: customer,
   quote, order, admin order-diff approval, invoice, partial/full payment,
   reversal, reconciliation; verify real HTTPS, browser UI, CSRF, wrong-org,
   conflict/replay and disabled/role checks.
4. Chromium and Linux WebKit desktop/mobile run against **Render URL**,
   not loopback; physical iPhone Safari owner acceptance remains separate.
5. Do not claim the entire `P3 PG17 LIVE E2E` from this SQLite-only service.
   A separate PostgreSQL cutover and secure, disposable PG17 connection with
   tenant/RLS verification are needed before that gate can pass.
6. Shutdown/decommission the QA instance once testing concludes.

## B2/B3 and release
The publicly deployed QA service must never contain the recovery key,
encrypted real archive, unencrypted dumps, live Supabase credentials or the
backup-role password. B3 offline restore runs only in the owner's separate,
private, marker-proven disposable PostgreSQL 17 environment. Release ALL PASS
remains NO-GO until actual source backup and independently verified restore,
PG17-backed stage, independent QA and owner approval all have evidence.
