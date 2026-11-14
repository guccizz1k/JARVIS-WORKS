# Issue #142 / V22.3 — cookie isolation & dual-home resilience (2026-11-14)

## Provenance
- Base review SHA: `e6a1ce84694812451964732ef6101c9155bf28a1` from `review/jw-v223-s4-snapshot-guard-20261114` (A/S4/trade 100 PASS).
- New isolated branch: `review/jw-v223-cookie-resilience-20261114`.
- Tested combined SHA: `56564ce2f82059be9f87ec053420e45d1970bdc6`.
- Prior reviewed security source: `review/jw-v223-ab-cookie-attr-ambiguity-20261109`, source blob `dc0c536d43c521ba34b6f7159468a9b986f36677`. Three narrow original sections ported into the current candidate; no full-branch overwrite.
- Existing security tests copied exactly from prior reviewed test blobs: `ab43c7306ad16d3ca0f72d629c1873a053083056`, `bf6ffd90bc40a4825f597f177ffd576d1de17c07`, `eaa252a9144b5ad32e398bae75843d94e980f4ce`.

## Root causes and changes
1. `_safe_cookie()` previously allowed multiple occurrences of a given virtual session cookie, relying on the framework parser to pick one. Reject duplicate occurrences across both multiple `Cookie` headers and a single semicolon-delimited header with `duplicate_session_cookie` (401).
2. `_forward().wrapped_send()` previously accepted unsafe/ambiguous upstream `Set-Cookie` replies: duplicate session issue; missing HttpOnly/SameSite, invalid minted token; duplicate/conflicting Path, SameSite, Domain, Max-Age and flag attributes; alternate virtual-session cookie namespace or whitespace alias. Reject fail-closed before emitting the response header. Preserve valid secure legacy deletion normalization.
3. `_merged()` used to propagate raw non-ASCII query decoding exceptions or a downstream `httpx.RequestError`. Convert to explicit safe 400/503 without partial merged responses.

## Reproducible red → green evidence
- RED, identical restored 89-case regression on old production module: GitHub Actions run `43582906854`, **45 PASS / 44 FAIL**, source SHA `121b41b8dd4e2f282825f3b12e7491c2fe0aad98`.
  https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/43582906854
- Patch of only `app/pg_cinema_cutover_front_v223.py`: commit `2f07d75012090023a844899d7dcef04305c14f70`.
- GREEN, restored 89 cases: run `43582982456`, **89 PASS**.
  https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/43582982456
- Same SHA integrated A authentication, S4 reviewed immutable snapshot, real (synthetic gateway) PG trade router and restored cookie protection: run `43583068894`, **189 PASS / 0 FAIL / 0 ERROR / 0 SKIP** in 1.13s.
  https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/43583068894

## Safety
Only six files changed relative to prior review branch: one proxy app module, three existing regression files reintroduced, and two review-branch GitHub Actions workflows. No `main`, `app/main.py`, UI original, SQL migrations, customer rows, operational DB, Docker volumes, backup keys, or Render deployment was modified. Tests ran on synthetic ASGI apps only, without real database or network secrets.

## Residual blockers / independent release gates
- Codex local integrated candidate `faa97d10c89853faa1bea3d1e272c41ee8c3faac` remains unavailable in GitHub. This review patch must be checked against that commit before integration; do not overwrite its work.
- Real Supavisor HTTPS auth, full PostgreSQL transaction E2E, latest Render app candidate, physical GPU, real mobile and final UI acceptance remain NOT VERIFIED/BLOCKED.
- Current PASS refers to 189 **synthetic** regressions, not a declaration of JARVIS-WORKS release ALL PASS. Keep final gate BLOCKED until independently evidenced.


## Disposable PG17 S4 gate continuation — 2026-11-14
- Test source commit: `008177551274a292b0273fdd45c6afdf0adcea86`.
- Actual GitHub Actions run: https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/43583733025
- `PG17_REVIEWED_S4_23_OF_23_PASS` and `PG17_ATOMIC_S4_32_OF_32_PASS`. 55 scoped checks succeeded on disposable Docker `postgres:17` using synthetic data and isolated databases. Negative SQL errors were expected safeguards that the tests judged PASS.
- Protected original, approved layout/backup and fixture hashes were checked (10 pinned blobs); all other protected static content matched baseline; eight changed paths were within this review branch's fixed parent-relative allowlist.
- RED attempt `43583493488`: shallow checkout did not contain protected historical baseline SHA. Fixed using `fetch-depth: 0`.
- RED attempt `43583560292`: original global `scripts/ci_cinema_pg_guard.py` **FAILED** due to unrelated workflow/docs introduced by prior integrated work that fall outside its historical whole-branch whitelist. This protected original guard was NOT altered or called PASS; the new workflow uses its **own narrower independent source-hash and changed-path verification**.
- This is **not** a live Supabase/Supavisor or Render HTTPS E2E result. Original global guard and all release gates remain unfulfilled until their defined scope independently passes. Codex local `faa97d10` remains inaccessible in GitHub.


## Real SQLite + disposable PG17 dual-session E2E integration
- Existing `scripts/ci_cinema_pg_cutover_realdb_v223.py` was originally built for the older PG CSRF header contract. It sent `X-CSRF-Token` for both stores, which is intentionally stripped at the current cutover proxy PG trust boundary. Reproduced in GitHub Actions run `43583974170` (S4 PG17 55 checks PASS, subsequent E2E stopped at `FAIL_V223_REALDB_FRONT_REAL_PG_PARTNER_CREATED`).
- **Minimal fix:** in the existing synthetic E2E driver only, use `X-JW-PG-CSRF` for the two successful PostgreSQL create requests. The legacy CSRF and required dual-token logout tests remain unchanged. Source code auth policy was NOT weakened.
- Isolated branch test script commit `7e3f11ade297d2bc82fbdcea99021100a6eeeaf2`. Workflow tests this exact E2E file as a permitted changed source path, rather than silently excluding it from preflight.
- **GREEN**: GitHub Actions `43584134368` on SHA `e0a2a8608b9f5e82bf17449a4a1e95d529d812b1` — **23/23** PG17 reviewed-link SQL, **32/32** PG17 S4 atomic/concurrency, **30/30** real SQLite+disposable PG17 session/trade E2E, total **85 scoped checks PASS**, zero failed. Tested actual SQL sessions and rollback on fabricated disposable resources.
  https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/43584134368
- No live Supavisor/production Auth, customer data, hosted HTTPS, current Codex-only final HTML integration, or final 5-Gate release QA was tested. These are independent remaining blockers. Original global historical baseline whitelist gate remains not passed on this accumulated review branch.


## Same-SHA integrated CI extension — Nov 14, 2026 (281/281)
- New workflow: `.github/workflows/jw-v223-exact-sha-274-20261114.yml`. It reuses the existing scoped original/hash verification and runs Python A+S4+cookie controls, isolated PG17 S4 SQL, and real disposable SQLite/PG17 business E2E on a **single checked-out source SHA**. Each subgate asserts exact counters and zero failing/error/skipped cases. The runner uses synthetic, fresh Docker PG17 and temporary SQLite data only.
- First same-SHA run `43594283947` at SHA `cdd9b2e6b9335576ab996cee30ee8cbeec7fd6f7`: 189 Python PASS + 23 SQL reviewed-link PASS + 32 SQL atomic/concurrency PASS + 30 isolated SQLite/PG17 real-DB E2E PASS = 274 scoped checks; GitHub Actions SUCCESS.
  https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/43594283947
- Expanded same-SHA run `43594540832` at SHA `6ef6051a4712122dae9767265d5bc4229bd96b56`: the above **274** plus **7** S4 single-writer dual-engine enablement guards PASS, total **281 / 281**, all FAIL/ERROR/SKIP **0**; workflow SUCCESS.
  https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/43594540832
- Source-scope check pinned **10 Git blobs**, validated protected static tree excluding the explicitly approved CSS blob, and checked exactly 10 allowed delta paths relative to parent `e6a1ce84694812451964732ef6101c9155bf28a1`.
- Non-failing dependency notices remain: Starlette `httpx` TestClient deprecation, pytest-asyncio loop-scope setting warning, runner Node 20 compatibility/deprecation messages. Future version bumps require dedicated verification; no suppressions added.
- **Honest boundary:** the historic `scripts/ci_cinema_pg_guard.py` whole-branch changed-file whitelist is still not PASS for this aggregated review branch; the new pinned scoped guard is independent, not an assertion that the historic guard passed.
- Neither workflow makes Codex-only local `faa97d10c89853faa1bea3d1e272c41ee8c3faac` available. That commit remains absent from GitHub and from accessible conversation/library files. Latest Render deployments still correspond to prior November 3 and October 25 sources; no deployment occurred.
- Final approved HTML `jarvis-works-v2.html` was not compared with this hosted frontend bundle in this pipeline. Physical GPU, real device, hosted Supavisor credentials, production backup/restore, latest Render HTTPS E2E, independent release QA and overall 5-Gate ALL PASS remain BLOCKED/NOT RUN/NOT VERIFIED according to their own evidence.
