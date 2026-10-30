"""Protected, review-only HTTPS entrypoint; never a production release.

Without approved role-scoped database configuration, /healthz is sealed-only
and every business route denies access. With configuration, ONLY the existing
PG-only business routers are mounted. An independent outer ASGI gate covers
HTTP AND WebSocket handshake with a high-entropy server-only access key.
"""
from __future__ import annotations
import hmac
import os
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from scripts import jw_v104_standalone

_ACK = "V134_STAGE1_PUBLIC_ISOLATED_ONLY"

class ProtectedStage:
    def __init__(self, app: FastAPI, secret: str):
        self.app=app
        self.secret=secret.encode("utf-8")
    async def __call__(self, scope, receive, send):
        kind=scope.get("type")
        if kind not in ("http","websocket"):
            return await self.app(scope, receive, send)
        path=scope.get("path","")
        if kind=="http" and path=="/healthz":
            return await self.app(scope, receive, send)
        presented=b""
        for k,v in scope.get("headers",[]):
            if k.lower()==b"x-jw-stage-key":
                presented=v
                break
        if len(presented)<32 or not hmac.compare_digest(self.secret,presented):
            if kind=="websocket":
                await send({"type":"websocket.close","code":1008,"reason":"Isolated staging access denied"})
            else:
                res=JSONResponse({"detail":"Staging access denied"},status_code=403,
                                 headers={"Cache-Control":"no-store"})
                await res(scope,receive,send)
            return
        return await self.app(scope,receive,send)

def create_app():
    if (os.getenv("JW_ENV") not in ("dev","development","test")
        or os.getenv("JW_STAGE1_PUBLIC_ACK")!=_ACK
        or os.getenv("JW_RELEASE_APPROVED","").lower() in ("yes","1","true")):
        raise RuntimeError("Stage1 preview is explicitly non-production")
    secret=os.getenv("JW_STAGE1_ACCESS_KEY","")
    if len(secret)<40:
        raise RuntimeError("Stage1 access key missing or weak")
    enabled=jw_v104_standalone.preflight()
    if enabled:
        app=jw_v104_standalone.create_app()
        # Preserve the existing product's health route but do not advertise
        # acceptance or customer data until independent E2E evidence exists.
    else:
        app=FastAPI(docs_url=None,openapi_url=None,redoc_url=None)
        @app.get("/healthz")
        def sealed():
            return {"mode":"sealed-no-db","release":"BLOCKED","stage1":"FAIL"}
    return ProtectedStage(app,secret)
