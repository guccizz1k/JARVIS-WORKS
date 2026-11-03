"""Accessible read-only V15.5 delivery-review console. Isolated PG stage ONLY.

No production/static asset modifications and no approve/post buttons. A verified
company-admin session is required to receive the HTML page. The browser queries
the existing GET review endpoint; signatures and raw evidence are never shown.
"""
from __future__ import annotations

from typing import Callable

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from . import pg_v90_integrated_entry as sessions

_BASE = "/api/pg-stage/v155"
_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'")

_HTML = """<!doctype html>
<html lang="ko"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>JARVIS-WORKS | 납품 증거 검토</title>
<link rel="stylesheet" href="/api/pg-stage/v155/review-console.css">
<script defer src="/api/pg-stage/v155/review-console.js"></script>
</head><body>
<main id="main" class="shell">
<header><h1>납품 증거 검토</h1>
<p>승인 대기 상태만 조회합니다. 실제 납품 확정이나 청구·입금 처리는 수행하지 않습니다.</p></header>
<section class="panel" aria-labelledby="lookup-title">
<h2 id="lookup-title">주문 조회</h2>
<form id="review-form" novalidate>
<label for="order-id">주문 ID (영문 소문자와 숫자 32자리)</label>
<input id="order-id" name="order_id" required spellcheck="false"
 autocomplete="off" inputmode="text" maxlength="32"
 pattern="[0-9a-f]{32}" aria-describedby="order-hint">
<p id="order-hint" class="hint">해당 기업의 관리자 계정으로 조회할 수 있습니다.</p>
<button id="submit" type="submit">검토 상태 확인</button>
</form>
<p id="review-result" role="status" aria-live="polite" aria-atomic="true"></p>
</section>
</main></body></html>"""

_CSS = """*{box-sizing:border-box}html{font-family:system-ui,-apple-system,sans-serif;
font-size:17px;background:#f6f8fb;color:#172334}
body{margin:0;line-height:1.55}.shell{max-width:740px;margin:48px auto;padding:0 20px}
h1{font-size:clamp(1.6rem,4vw,2.2rem);margin:0 0 10px}
h2{font-size:1.25rem;margin:0 0 16px}p{margin:8px 0 20px}
.panel{background:#fff;border:1px solid #cfd8e3;border-radius:14px;padding:26px}
label{display:block;font-weight:650;margin:0 0 8px}
input{width:100%;min-height:48px;border:2px solid #9baebe;border-radius:8px;
padding:10px 12px;font:inherit;letter-spacing:.01em}
button{display:inline-block;margin-top:12px;min-height:48px;border:0;
border-radius:8px;background:#164d8d;color:#fff;padding:11px 20px;
font:inherit;font-weight:700;cursor:pointer}
button:disabled{opacity:.7;cursor:progress}
button:hover:not(:disabled){background:#0b3564}
:focus-visible{outline:3px solid #ff9800;outline-offset:3px}
.hint{font-size:.91rem;color:#43566b;margin:5px 0 16px}
#review-result{min-height:34px;font-weight:600;overflow-wrap:anywhere}
@media(max-width:480px){.shell{margin:18px auto;padding:0 14px}
.panel{padding:18px}button{width:100%}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
"""

_JS = """'use strict';
(() => {
 const form = document.getElementById('review-form');
 const field = document.getElementById('order-id');
 const output = document.getElementById('review-result');
 const submit = document.getElementById('submit');
 if (!form || !field || !output || !submit) return;
 form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const id = field.value.trim();
  if (!/^[0-9a-f]{32}$/.test(id)) {
   output.textContent = '주문 ID는 영문 소문자와 숫자 32자리여야 합니다.';
   field.focus(); return;
  }
  submit.disabled = true;
  output.textContent = '검토 상태를 조회 중입니다.';
  try {
   const response = await fetch(
     '/api/pg-stage/v154/orders/' + encodeURIComponent(id) + '/delivery-review',
     { method: 'GET', credentials: 'same-origin', cache: 'no-store',
       headers: { 'Accept': 'application/json' } });
   if (!response.ok) {
    output.textContent = response.status === 404 ?
     '조회 가능한 승인 대기 기록이 없습니다.' :
     (response.status === 403 || response.status === 401) ?
     '관리자 인증이 필요합니다.' : '조회에 실패했습니다. 다시 확인해 주세요.';
    return;
   }
   const data = await response.json();
   output.textContent = data.status === 'PENDING_HUMAN_REVIEW' ?
     '검토 대기 중입니다. 납품 확정·청구·입금은 진행되지 않았습니다.' :
     '검증되지 않은 상태입니다. 관리자에게 문의하세요.';
  } catch (_) {
   output.textContent = '연결 오류가 발생했습니다. 다시 시도해 주세요.';
  } finally { submit.disabled = false; }
 });
})();
"""


def register_v155_review_console(app: FastAPI, enabled: Callable[[], bool]) -> bool:
    if not enabled():
        return False
    router = APIRouter(prefix=_BASE, tags=["Isolated delivery review status UI"])

    @router.get("/review-console", response_class=HTMLResponse)
    def page(request: Request, response: Response):
        with sessions._pg_validated_cursor(sessions._session_hash(request)) as (_, identity):
            if identity[3] != "admin":
                raise HTTPException(403, "Administrator role required")
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        return HTMLResponse(
            content=_HTML, headers=dict(response.headers)
        )

    @router.get("/review-console.js")
    def javascript():
        return Response(content=_JS, media_type="application/javascript",
                        headers={"Cache-Control": "no-store",
                                 "X-Content-Type-Options": "nosniff"})

    @router.get("/review-console.css")
    def stylesheet():
        return Response(content=_CSS, media_type="text/css",
                        headers={"Cache-Control": "no-store",
                                 "X-Content-Type-Options": "nosniff"})

    app.include_router(router)
    return True
