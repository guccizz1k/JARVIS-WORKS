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
        # A deployed preview may be inspected while credentials are withheld.
        # No request can satisfy both a >=32-byte header and the empty secret.
        app=FastAPI(docs_url=None,openapi_url=None,redoc_url=None)
        @app.get("/healthz")
        def awaiting_secret():
            return {"mode":"sealed-awaiting-stage-key","release":"BLOCKED","stage1":"FAIL"}
        return ProtectedStage(app,"")
    enabled=jw_v104_standalone.preflight()
    if not enabled:
        # Report names of failed checks only; never echo a DSN or password.
        import logging
        bad = []
        checks = {
            "DEV_ENV": os.getenv("JW_ENV") in ("dev","development","test"),
            "API_ACK": os.getenv("JW_STAGE_API_ACK") == jw_v104_standalone.ACK,
            "INSECURE_DEV": os.getenv("JW_INSECURE_LOCAL_DEV") != "1",
            "SUPAVISOR_ACK": os.getenv("JW_STAGE1_SUPAVISOR_ACK") == "V134_REVIEW_POOLER_ONLY",
            "EXPECTED_HOST": bool(os.getenv("JW_STAGE_EXPECTED_DB_HOST")),
            "EXPECTED_DATABASE": bool(os.getenv("JW_STAGE_EXPECTED_DB_NAME")),
            "DISTINCT_DSN": os.getenv("JW_PG_STAGE_DSN", "") != os.getenv("JW_PG_AUTH_STAGE_DSN", ""),
            "TRADE_DSN": jw_v104_standalone._safe_dsn(
                os.getenv("JW_PG_STAGE_DSN", ""), "jw_trade_gateway_v90"),
            "AUTH_DSN": jw_v104_standalone._safe_dsn(
                os.getenv("JW_PG_AUTH_STAGE_DSN", ""), "jw_auth_gateway_v90"),
        }
        for name, expected in jw_v104_standalone.REQUIRED_MODES.items():
            checks["MODE_" + name] = os.getenv(name) == expected
        try:
            origins = jw_v104_standalone.pg_v90_integrated_entry._origins()
            checks["HTTPS_ORIGIN"] = (len(origins) == 1
                and jw_v104_standalone._safe_origin(next(iter(origins))))
        except Exception:
            checks["HTTPS_ORIGIN"] = False
        bad = [name for name, passed in checks.items() if not passed]
        logging.getLogger("jarvis.stage1").warning(
            "STAGE1_CONFIG_PREFLIGHT=BLOCKED invalid_checks=%s",
            ",".join(bad) if bad else "UNKNOWN")
    if enabled:
        # Render connects with its own role-scoped DSNs; never infer live DB
        # access from syntactically valid env settings or a green HTTP deploy.
        import logging
        from scripts import jw_v135_stage_connection_probe as connection_probe
        enabled, checkpoint = connection_probe.verify()
        logging.getLogger("jarvis.stage1").warning(
            "STAGE1_REAL_PG_ROLE_PROBE=%s checkpoint=%s",
            "PASS" if enabled else "BLOCKED", checkpoint)
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
