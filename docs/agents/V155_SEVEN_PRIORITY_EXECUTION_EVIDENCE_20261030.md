# V15.5 — Seven priority tasks, run records, blockers and non-bypass acceptance
Date: 2026-10-30 KST. Protected parent **Draft PR #67** HEAD `d1cca32a062bad4ad9ce81ead3110efe79e31b2a`. New review branch, not release.

## Execution priority & evidence — do not overstate PASS

| Requested task | Implemented / actually executed | Verdict for requested entire category |
|---|---|---|
| 1. Exact source investigation and defect fixes | New GET review-status route, pre-JSON byte limiter, corrected malicious huge decimal Content-Length conversion, explicit cleanup of threaded SQLite connections; remote Git blobs checked | **SCOPED PASS**, whole repo analysis not exhaustively tested |
| 2. J1–J6 regression | Local isolated `pytest` **157 PASS / 0 FAIL / 0 SKIP** with `PYTHONWARNINGS=error` and `-o asyncio_default_fixture_loop_scope=function`; `compileall` PASS. Several older local files are mirrored/stubbed, **not** exact remote checkout. Existing `.github/workflows/jw-j1-j6-unified-acceptance.yml` review branch filters exclude V15.5. | **PARTIAL** — entire exact-HEAD J1–J6 GitHub Actions and build **NOT RUN** |
| 3. Real PostgreSQL integrity/RLS | Exact retrieved PostgreSQL 17.11 V15.1–V15.5 chained synthetic SQL in one guarded BEGIN/ROLLBACK, current tenant A admin reads own status, B admin cannot read A, A member/unknown denied; **`PASS_V155_REAL_PG17_STATUS_ADMIN_TENANT_MEMBER_AND_ROLLBACK`**. Existing security policies 40, FORCE RLS 35; no durable schema created. | **SCOPED PASS** for restricted role and status isolation |
| 4. Concurrent writes/idempotency | Two-thread SQLite WAL synthetic reservation race, single winner / loser / nonce+audit atomicity tested and PASS, all connections explicitly closed. Two real Supabase PostgreSQL advisory-lock calls used separate backends but were serviced about 5s apart, so **did not prove overlapping transactions**. | **PARTIAL** — PostgreSQL *same-order, two-connection app transaction* collision **NOT RUN** |
| 5. Cross-feature API integration | PG-only isolated V15.4 POST handler now exposes authenticated, tenant-admin V15.5 GET status; both connect only to existing PG session / RLS candidate, no separate production app or finance mutations. Mock-based FastAPI route tests PASS, actual PG source status RLS PASS. | **PARTIAL** — issuer credentials and durable authorized ledger absent; user onboarding, official independent physical receipt, invoice/payment still not end-to-end |
| 6. Security/static analysis | GitHub exact source static 10/10 review assertions: original `app/main.py` Git blob `0ede250ddbcf98b19f7747c8781ca4c8aa95e738` unchanged; stage-only registration, CSRF, admin, no finance posting, no public DB grants, six tenant RLS policies, UI CSP and no innerHTML, raw byte cap. Parser/compileall PASS, 157 local warnings-as-errors tests PASS. | **SCOPED PASS**, Semgrep/independent security audit **NOT RUN** |
| 7. UI/UX browser | New stage-only mobile-accessible **read-only review console** with Korean labels, 17px root typography, 44px+ controls, responsive CSS, focus outline, ARIA live status and strict CSP, no approve/post buttons. Actual Chromium executable **/usr/bin/chromium** rendered exact GitHub console module UI source at 320/360/390/768/1280px: no horizontal overflow, status success/not-found/invalid-input PASS. Separate FastAPI TestClient confirms no member access and secure headers; browser navigations to actual loopback/HTTPS blocked by environment's administrator. | **SCOPED PASS** local DOM/response-mock, actual hosted HTTPS browser E2E **NOT RUN** |

## Remote source integrity / local run

The following local files had Git blob SHA-1 identical to the GitHub V15.5 review branch when tested:
- `app/pg_delivery_review_api_v154.py`: `9281b73827f3de76fc24b71dbc668c75ec5026ec`
- `app/pg_delivery_review_console_v155.py`: `d633211378d6a8bcd0549a94b13024e3b033417f`
- `app/pg_delivery_request_limit_v155.py`: `d5ad2c06679971df557d29baca3f84cd809f4563`
- `app/pg_delivery_review_reservation_v151.py`: `c1de3ed17ccb0b2a3668a4aa9cee1c5ca9e01be7`
- `tests/test_v155_review_console_and_limits.py`: `bd61e8970b9f8fca1f4eda842820a62dad5a6672`
- `tests/test_v155_threaded_collision_reference.py`: `937276cfd8c7aec35b4ee08d6c6301c18aa9fd52`

The local mirror was **not** a complete exact-GitHub-HEAD checkout: `app/pg_quote_api_v92.py` and `app/pg_v90_integrated_entry.py` were isolated stubs in the local test harness, so 157 PASS proves only the isolated subset. The new status UI was tested in Chromium using `page.set_content` and real DOM, not via a hosted fetch/navigation or real company credentials. New SQLite race tests explicitly use `contextlib.closing` because `with sqlite3.connect()` alone does not close the connection.

## Defects corrected

1. JSON proof payload limit originally ran only after parsing; added ASGI preparse raw-stream limiter for the isolated route.
2. Excessively long numeric Content-Length could trigger Python's integer parsing limit; now rejected by length before integer conversion, with regression test.
3. Original delivery review was only writable with no read-only status path; added tenant-admin-only GET, no raw signatures/nonce leaks.
4. A newly introduced SQLite threaded race test initially leaked database connections under strict warnings; fixed all created connections and re-ran fatal-warning test suite.

## Five-Gate assessment — scope vs product

- **Gate 1 PARTIAL**: local compile and 157 isolated PASS; entire exact-GitHub-HEAD J1–J6 CI NOT RUN.
- **Gate 2 PARTIAL**: actual PG17 role/status and mock-based HTTP GET/POST PASS; persistent DB migration, external issuer identities and full business lifecycle NOT DONE.
- **Gate 3 PARTIAL**: SQLite two-thread synthetic race PASS, PostgreSQL source/RLS rollback PASS; actual two live PostgreSQL writer transactions and full regression NOT RUN.
- **Gate 4 PARTIAL**: local Chromium review console UI PASS; real hosted HTTPS, login, browser backend E2E NOT RUN.
- **Gate 5 PARTIAL**: scoped security scan and RLS PASS; independent penetration, secret issuer approval, stage rollback/recovery NOT RUN.

No empirical evidence permits marking all seven categories or all five gates globally PASS. In particular the staged ledger has been **intentionally absent** to avoid unapproved persistent DB changes, stage still runs an older SHA, and verified external dispatch/receipt keys have not been supplied.

## Protection and prerequisites

Do not merge `main`, deploy production/staging, change persistent DEV database schemas/roles/secrets or move real customer data automatically. GitHub Actions might use paid runner minutes under the user's capped budget; no new workflow run triggered without explicit cost authorization. A legal/official identity provider and signed external issuer must exist before true physical delivery approval is accepted. Required next proof is *one exact SHA* running full J1–J6 with configured dependencies, two restricted real PostgreSQL connections on an isolated installed ledger, approved HTTPS staging, Chromium E2E and independent security signoff. Never replace these with only a static test, mock browser or transactional advisory reference.
