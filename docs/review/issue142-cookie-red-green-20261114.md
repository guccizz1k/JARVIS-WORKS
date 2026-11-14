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
