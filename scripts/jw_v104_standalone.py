"""Review-only PostgreSQL API entrypoint with NO legacy SQLite app routes.

CLI (only on separately authorized isolated HTTPS staging):
  uvicorn scripts.jw_v104_standalone:create_app --factory --host 0.0.0.0 --port 10000

Do not confuse endpoint registration with full authentication, finance, OCR,
representative migration or release acceptance.
"""
from __future__ import annotations

import os
from urllib.parse import urlsplit

from fastapi import FastAPI
from psycopg.conninfo import conninfo_to_dict

from app import pg_api_v84, pg_auth_v85, pg_v90_integrated_entry
from app import pg_quote_api_v92, pg_quote_read_v93, pg_invoice_preview_v145, pg_delivery_review_api_v154, pg_trade_lineage_v158, pg_import_quote_v160, pg_invoice_balance_v161

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
        keys = frozenset({"host", "port", "dbname", "user", "password",
                          "sslmode", "connect_timeout", "sslrootcert"})
        if set(d) - keys:
            return False
        host = os.getenv("JW_STAGE_EXPECTED_DB_HOST", "")
        dbname = os.getenv("JW_STAGE_EXPECTED_DB_NAME", "")
        if not host or not dbname:
            return False
        timeout = int(d.get("connect_timeout", "5"))
        pooler = os.getenv("JW_STAGE1_SUPAVISOR_ACK") == "V134_REVIEW_POOLER_ONLY"
        if pooler:
            # Only pre-approved, revocable test logins. No existing V90 role
            # password rotation or privileged Supabase credentials permitted.
            stage_role = {
                "jw_trade_gateway_v90": "jw_stage1_trade_20261030",
                "jw_auth_gateway_v90": "jw_stage1_auth_20261030",
            }.get(principal)
            expected_ref = "rvymwwzclagvljnofyss"
            expected_user = stage_role + "." + expected_ref if stage_role else ""
            if host != "aws-0-ap-northeast-2.pooler.supabase.com" or (
                d.get("sslrootcert") != "system"
            ):
                return False
        else:
            expected_user = principal
            if d.get("sslrootcert") not in (None, "system"):
                return False
        return (
            d.get("user") == expected_user
            and d.get("host") == host
            and d.get("dbname") == dbname
            and len(d.get("password", "")) >= 16
            and d.get("sslmode") == "verify-full"
            and d.get("port", "5432") == "5432"
            and 1 <= timeout <= 5
        )
    except Exception:
        # Invalid conninfo may raise psycopg.ProgrammingError; no secrets in logs.
        return False


def _safe_origin(origin: str) -> bool:
    try:
        url = urlsplit(origin)
        return (
            url.scheme == "https" and bool(url.hostname)
            and url.username is None and url.password is None
            and url.path == "" and url.query == "" and url.fragment == ""
            and origin == "https://" + url.netloc
            and (url.port is None or 1 <= url.port <= 65535)
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
    if len(origins) != 1 or not _safe_origin(next(iter(origins))):
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
        pg_invoice_preview_v145.register_v145_invoice_preview(app),
    ):
        if not registered:
            raise RuntimeError("BLOCKED: an isolated PostgreSQL router is disabled")

    # Optional V15.4 route is OFF by default; if explicitly requested, it
    # must pass issuer-key / non-production gates or block startup.
    pg_delivery_review_api_v154.register_v154_delivery_review(app)
    # V15.8 only shows already-verified tenant-scoped record links; OFF by default.
    pg_trade_lineage_v158.register_v158_trade_lineage(app)
    # Requires separately confirmed import evidence + encrypted source key.
    pg_import_quote_v160.register_v160_pg_import_quote(app)
    # Read-only existing invoice/payment balance; cannot post or reconcile.
    pg_invoice_balance_v161.register_v161_invoice_balance(app)
    # V17.4 is disabled by default and registers no routes without an explicit
    # non-production opt-in. Never calls a bank or posts legal invoices.
    from scripts.review import pg_order_activation_v174
    pg_order_activation_v174.register_v174_internal_order(app)
    # V18.0 is disabled by default; records INTERNAL unreconciled entries
    # only via restricted V83 RPC. Never claims actual bank settlement.
    from scripts.review import pg_manual_ledger_v180
    pg_manual_ledger_v180.register_v180_ledger(app)

    @app.get("/healthz", include_in_schema=False)
    def health():
        return {"mode": "isolated_pg_api_only", "release": "BLOCKED"}

    return app
