# V22.2 root UI candidate (isolated, default OFF)

Status: **candidate, not merged, not deployed.** Base `d8ee0e70daa0674fdefbf7df2e5a7c42ffcd5ed9`
(`review/jw-cinema-pg-engine-20261104`, Draft PR #139). JARVIS-CORE is unrelated.

## Decision and conflict

Product decision: the real `/` login, main and business screens are the V22.2 silver-infinity
cinematic dark UI. `app/main.py` (blob), `app/static/` (tree) and the changed-file whitelist are pinned by
`scripts/ci_cinema_pg_guard.py`, and `/` is pinned to CINEMA by `tests/test_cinema_pg_entry_load.py`.
Changing the route directly would require editing those guards, which is exactly what the protection
policy forbids. So the change is isolated as a candidate that touches **no protected file**.

## What changed

| File | Change |
|---|---|
| `app/cinema_entry_v1.py` (whitelisted, modify) | `JW_ROOT_UI=v222` makes `/` return `static/index.html` (V22.2). Any other value, including unset, returns the unchanged CINEMA page. |
| `tests/test_cinema_pg_root_ui_switch.py` | 19 unit tests: default is CINEMA, fail-closed values, V22.2 page is Korean / dark-declared / same-origin / no inline script, all assets exist, `main.py` wiring untouched. |
| `scripts/ci_cinema_pg_v222_root_browser.py` | Real Chromium acceptance on `/` (see below). |
| `.github/workflows/jw-cinema-pg-v222-root.yml` | Runs the guard, the unit tests, the protected CINEMA regression, the new acceptance, and the two historical V22.2 suites unchanged against `/`. |

Untouched: CINEMA original HTML, `app/main.py`, `app/static/**`, every API/RLS/auth/data path,
`/_legacy-ui`, `ci_cinema_pg_browser_entrypoints.py`, `ci_v222_cinematic_browser.py`,
`ci_v223_real_browser_recording.py`. The historical V22.2/V22.3 scripts target the `index.html` DOM, which
is what `/` now serves under the flag, so they need no selector edits.

## Activate / roll back

Activate: set `JW_ROOT_UI=v222` in the process environment. Roll back: unset it and restart (no data or
schema is involved). Nothing in this change sets the variable on any existing service.

## Acceptance covered by the new browser script

Entry routing and control (default `/` still CINEMA); Korean; dark-only (OS light preference and a persisted
light setting are both overridden); moving single-photon infinity (canvas head tracked across samples) and a
static photon under reduced motion; PC resolutions 1366x768 / 1440x900 / 1920x1080 and the desktop-only
notice at 768; the `jw214-auth-enter` entrance animation plays and ends after a real login; business menu
and all ten routes; left-rail overlap (collapsed per route, and open state); document upload -> pending
preview -> manual approval with no silent registration and no invoice side effect; JS page errors; HTTP 5xx;
measured performance; one continuous recording encoded to H.264 MP4 and verified by probe, full decode and
frame-content checks.

Performance budgets in the script are **provisional and uncalibrated**. The first CI run is the baseline.

## Verification status

| Item | Status |
|---|---|
| Containment guard on the candidate tree | PASS (local) |
| Unit tests (new 19 + protected entry/guard tests) | PASS (local) |
| Login-screen, reduced-motion, narrow-width and MP4 logic of the new script | PASS against a throwaway static stub (not the FastAPI app) |
| Authenticated flow, rail, routes, documents, performance, recording on the real app | **NOT RUN** (needs the workflow) |
| Existing V22.2 / V22.3 suites against `/` | **NOT RUN** |
| Full pytest, PostgreSQL 17 Gate 2 / 3 / 4 on the new SHA | **NOT RUN** |

## Open items for the owner

1. Making V22.2 the default (no environment variable) requires changing the protected guard and
   `test_cinema_pg_entry_load.py`; that is a separate, explicit approval.
2. A permanent internal CINEMA preview route needs `app/main.py`, which is protected. With the flag on,
   the original file is preserved in the repository but is not served.
3. Pushing the candidate branch and running the workflow needs push permission and approval.
