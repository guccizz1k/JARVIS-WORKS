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

def _dsn_shape_issue(raw: str, principal: str) -> str:
    """A fixed failure label only: never logs password, user input, or URL."""
    if not raw:
        return "MISSING"
    if raw != raw.strip():
        return "LEADING_OR_TRAILING_WHITESPACE"
    if not raw.startswith("postgresql://"):
        return "NOT_A_POSTGRES_URL"
    try:
        from psycopg.conninfo import conninfo_to_dict
        d = conninfo_to_dict(raw)
    except Exception:
        return "URI_PARSE"
    expected_role = {
        "TRADE": "jw_stage1_trade_20261030",
        "AUTH": "jw_stage1_auth_20261030",
    }[principal] + ".rvymwwzclagvljnofyss"
    checks = (
        ("USERNAME", d.get("user") == expected_role),
        ("HOST", d.get("host") == "aws-0-ap-northeast-2.pooler.supabase.com"),
        ("DATABASE", d.get("dbname") == "postgres"),
        ("PORT", d.get("port", "5432") == "5432"),
        ("TLS_MODE", d.get("sslmode") == "verify-full"),
        ("TLS_CERT", d.get("sslrootcert") == "system"),
        ("PASSWORD", len(d.get("password", "")) >= 16),
        ("UNEXPECTED_OPTIONS", not (set(d) - {
            "host", "port", "dbname", "user", "password", "sslmode",
            "connect_timeout", "sslrootcert"})),
    )
    for name, good in checks:
        if not good:
            return name
    try:
        timeout = int(d.get("connect_timeout", "5"))
        if not 1 <= timeout <= 5:
            return "TIMEOUT"
    except ValueError:
        return "TIMEOUT"
    return "UNKNOWN"

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
    # Render's multiline UI may add whitespace outside a pasted URI.
    # Only the isolated stage entrypoint normalizes it, before preflight and
    # before the original PostgreSQL connectors read their environment.
    # Never strip or alter the password, username, TLS fields inside the URL.
    for env_key in ("JW_PG_STAGE_DSN", "JW_PG_AUTH_STAGE_DSN"):
        raw = os.getenv(env_key, "")
        if raw and raw != raw.strip():
            os.environ[env_key] = raw.strip()
    # The pooler requires the pinned Supabase public CA for verify-full.
    # OpenSSL honors SSL_CERT_FILE for libpq's sslrootcert=system.
    from scripts import jw_v138_supabase_ca
    jw_v138_supabase_ca.install()
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
        if not checks["TRADE_DSN"]:
            logging.getLogger("jarvis.stage1").warning(
                "STAGE1_DSN_SHAPE_TRADE=%s",
                _dsn_shape_issue(os.getenv("JW_PG_STAGE_DSN", ""), "TRADE"))
        if not checks["AUTH_DSN"]:
            logging.getLogger("jarvis.stage1").warning(
                "STAGE1_DSN_SHAPE_AUTH=%s",
                _dsn_shape_issue(os.getenv("JW_PG_AUTH_STAGE_DSN", ""), "AUTH"))
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
        if os.getenv("JW_STAGE1_SAFE_HTTPS_PROBE") == "V140_ISOLATED_READONLY_HTTPS_DENIAL_ONLY":
            from scripts import jw_v140_safe_live_https_probe
            app.on_event("startup")(jw_v140_safe_live_https_probe.schedule)
        if os.getenv("JW_STAGE1_POSITIVE_HTTPS_PROBE") == "V141_REVIEW_ONLY_NONMESSENGER_SYNTHETIC_A_B_C":
            from scripts import jw_v141_hosted_https_abc
            app.on_event("startup")(jw_v141_hosted_https_abc.schedule)
        if os.getenv("JW_STAGE2_AUTH_HTTPS_PROBE") == "V143_ISOLATED_SYNTHETIC_AUTH_HTTPS_ONESHOT":
            from scripts import jw_v143_hosted_https_auth
            app.on_event("startup")(jw_v143_hosted_https_auth.schedule)
        # Preserve the existing product's health route but do not advertise
        # acceptance or customer data until independent E2E evidence exists.
    else:
        app=FastAPI(docs_url=None,openapi_url=None,redoc_url=None)
        @app.get("/healthz")
        def sealed():
            return {"mode":"sealed-no-db","release":"BLOCKED","stage1":"FAIL"}
    return ProtectedStage(app,secret)
