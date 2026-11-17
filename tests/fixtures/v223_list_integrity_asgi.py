"""SYNTHETIC local-only HTTPS browser fixture for the real protected CutoverFront.

Never mounted in app.main or the production build. No external DB or secrets.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from app.pg_cinema_cutover_front_v223 import (
    CutoverFront, Identity, UPSTREAM_COOKIE,
)
from app.pg_cinema_list_integrity_v223 import MergedListIntegrityGuard

LEGACY_TOKEN = "L" * 40
PG_TOKEN = "P" * 40
OTHER_PG_TOKEN = "Q" * 40
PG_ID = "pg_" + "a" * 32

legacy = FastAPI(docs_url=None, openapi_url=None)
postgres = FastAPI(docs_url=None, openapi_url=None)


@legacy.get("/")
def synthetic_browser_console():
    # Explicitly not the actual V22.2 user interface. This exercises browser
    # session cookie handling and API-to-DOM display with real Chromium/WebKit.
    return HTMLResponse("""<!doctype html><html lang="ko"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>JARVIS-WORKS Synthetic Boundary QA</title>
</head><body><main><h1>격리된 통합 목록 검증</h1>
<button id="normal" type="button">정상 목록</button>
<button id="duplicate" type="button">중복 목록</button>
<output id="status" aria-live="polite">준비</output>
<pre id="result"></pre></main>
<script>
async function check(mode) {
  const response = await fetch('/api/quotes?mode=' + mode, {credentials:'same-origin'});
  const payload = await response.json();
  document.getElementById('status').textContent = String(response.status);
  document.getElementById('result').textContent = JSON.stringify(payload);
}
document.getElementById('normal').addEventListener('click', () => check('normal'));
document.getElementById('duplicate').addEventListener('click', () => check('duplicate'));
</script></body></html>""", headers={"Cache-Control": "no-store"})


@legacy.get("/api/quotes")
def legacy_quotes():
    return [{"id": "legacy-1", "amount": 500}]


@postgres.get("/api/quotes")
def pg_quotes(request: Request):
    if request.query_params.get("mode") == "duplicate":
        return [{"id": PG_ID, "amount": 100}, {"id": PG_ID, "amount": 100}]
    return [{"id": PG_ID, "amount": 100}]


def legacy_identity(request: Request):
    if request.cookies.get(UPSTREAM_COOKIE) != LEGACY_TOKEN:
        raise HTTPException(401, "Synthetic legacy login required")
    return Identity("org-A", "actor-A", "admin")


def pg_identity(request: Request):
    token = request.cookies.get(UPSTREAM_COOKIE)
    if token == OTHER_PG_TOKEN:
        return Identity("org-B", "actor-A", "admin")
    if token != PG_TOKEN:
        raise HTTPException(401, "Synthetic PG login required")
    return Identity("org-A", "actor-A", "admin")


original = CutoverFront(
    legacy, postgres, legacy_identity, pg_identity,
    lambda: frozenset(("org-A",)),
)

guarded_app = MergedListIntegrityGuard(original)
original_app = original
