"""Review-only PostgreSQL API entrypoint with NO legacy SQLite app routes.

CLI (only on separately authorized isolated HTTPS staging):
  uvicorn scripts.jw_v104_standalone:create_app --factory --host 0.0.0.0 --port 10000

Do not confuse endpoint registration with full authentication, finance, OCR,
representative migration or release acceptance.
"""
from __future__ import annotations

import os

from fastapi import FastAPI
from psycopg.conninfo import conninfo_to_dict

from app import pg_api_v84, pg_auth_v85, pg_v90_integrated_entry
from app import pg_quote_api_v92, pg_quote_read_v93

ACK = "PRIVATE_HTTPS_PG_ONLY"
REQUIRED_MODES = {
    "JW_PG_STAGE_V84": "ISOLATED_DEV_READ_ONLY",
    "JW_PG_AUTH_V85": "ISOLATED_DEV_AUTH_ONLY",
    "JW_PG_MESSENGER_V90": "ISOLATED_DEV_MESSENGER_ONLY",
    "JW_PG_QUOTE_V92": "ISOLATED_DEV_QUOTE_V92",
}


def _safe_dsn(raw: str, principal: str) -> bool:
    if not raw:
        return False
    try:
        d = conninfo_to_dict(raw)
        user = d.get("user", "").split(".", 1)[0]
        return (
            user == principal and bool(d.get("host")) and bool(d.get("password"))
            and d.get("sslmode", "verify-full") == "verify-full"
            and d.get("dbname") not in (None, "")
        )
    except (TypeError, ValueError):
        return False


def preflight() -> bool:
    if os.getenv("JW_ENV") not in ("dev", "development", "test"):
        return False
    if os.getenv("JW_STAGE_API_ACK") != ACK or os.getenv("JW_INSECURE_LOCAL_DEV") == "1":
        return False
    if any(os.getenv(k) != v for k, v in REQUIRED_MODES.items()):
        return False
    try:
        origins = pg_v90_integrated_entry._origins()
    except RuntimeError:
        return False
    if len(origins) != 1:
        return False
    trade = os.getenv("JW_PG_STAGE_DSN", "")
    auth = os.getenv("JW_PG_AUTH_STAGE_DSN", "")
    if trade == auth:
        return False
    return (_safe_dsn(trade, "jw_trade_gateway_v90")
            and _safe_dsn(auth, "jw_auth_gateway_v90"))


def create_app() -> FastAPI:
    if not preflight():
        raise RuntimeError("BLOCKED: isolated PG-only HTTPS preview not safely configured")
    app = FastAPI(title="JARVIS WORKS restricted PostgreSQL stage",
                  docs_url=None, redoc_url=None, openapi_url=None)
    # Explicitly compose ONLY PostgreSQL routers: importing app.main here would
    # accidentally expose the independent SQLite login and financial endpoints.
    for registered in (
        pg_api_v84.register_stage_api(app),
        pg_auth_v85.register_v85_auth(app),
        pg_v90_integrated_entry.register_v90_messenger(app),
        pg_quote_api_v92.register_v92_quote_api(app),
        pg_quote_read_v93.register_v93_quote_reader(app),
    ):
        if not registered:
            raise RuntimeError("BLOCKED: an isolated PostgreSQL router is disabled")

    @app.get("/healthz", include_in_schema=False)
    def health():
        return {"mode": "isolated_pg_api_only", "release": "BLOCKED"}

    return app
