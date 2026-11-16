"""Isolated V22.3 owner review adapter with a separate ASGI entrypoint.

Never replaces app.main:app. Existing 530+ baseline and schema guards remain
unaltered. Only the explicit review runtime installs additive account tables.
"""
from contextlib import asynccontextmanager
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from . import main as core
from .owner_settings_v223 import install_schema, register_routes


@asynccontextmanager
async def owner_review_lifespan(_app):
    if not (os.environ.get('JW_ENV', '').lower() in ('review', 'test')
            and os.environ.get('JW_ROOT_UI') == 'owner-visual-review'
            and os.environ.get('JW_APPROVED_UI_REVIEW') == 'ISOLATED_REVIEW_ONLY'):
        raise RuntimeError('Owner account extension requires isolated explicit review mode')
    # The legacy application still owns its exact original schema and lifecycle.
    async with core.app.router.lifespan_context(core.app):
        # Only the isolated review application's database receives optional rows.
        install_schema(core.conn)
        yield


app = FastAPI(title='JARVIS WORKS isolated owner review', docs_url=None,
              redoc_url=None, openapi_url=None, lifespan=owner_review_lifespan)


@app.middleware('http')
async def account_security_headers(request: Request, call_next):
    account = request.url.path.startswith('/api/account/')
    if account and request.method not in ('GET', 'HEAD', 'OPTIONS'):
        if request.headers.get('Sec-Fetch-Site') == 'cross-site':
            return JSONResponse(status_code=403, content={'detail':'외부 요청이 차단됐습니다'})
        origin=request.headers.get('Origin')
        if origin and origin != str(request.base_url).rstrip('/'):
            return JSONResponse(status_code=403,content={'detail':'요청 출처가 일치하지 않습니다'})
    response=await call_next(request)
    if account:
        response.headers['Cache-Control']='no-store'
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Content-Security-Policy']=(
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        if request.url.scheme=='https':
            response.headers['Strict-Transport-Security']='max-age=31536000'
    return response


register_routes(app, current_user=core.current_user, conn=core.conn,
                transaction=core.transaction, now=core.now,
                audit=core.audit, fail=core.fail)

# A mounted sub-application keeps every original business route and middleware
# unchanged while the four account routes above take precedence.
app.mount('/', core.app)
