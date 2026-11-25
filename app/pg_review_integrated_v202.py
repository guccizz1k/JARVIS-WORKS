"""Isolated PostgreSQL trade-stage composition. Never mounts the SQLite app.

This factory reuses vetted PG authorization and business endpoints. It does NOT
claim a complete quote-to-cash backend, delivery posting, or release readiness.
No legacy /api/* route or UI is mounted. Every data route retains PG session,
forced-RLS role and CSRF protections from its original module.
"""
from __future__ import annotations

import os
from fastapi import FastAPI, Request, Response

from . import pg_api_v84 as pg_reader
from . import pg_auth_v85 as pg_auth
from . import pg_v90_integrated_entry as pg_messenger
from . import pg_quote_api_v92 as pg_quote
from . import pg_quote_read_v93 as pg_quote_read
from . import pg_invoice_preview_v145 as invoice_preview
from . import pg_delivery_review_api_v154 as delivery_review
from . import pg_import_quote_v160 as import_quote
from . import pg_invoice_balance_v161 as invoice_balance
from . import pg_trade_lineage_v158 as trade_lineage
from . import pg_cinema_register_v1 as cinema_trade
from . import pg_cinema_legacy_api_v1 as cinema_legacy_api

_MODE = "ISOLATED_DEV_PG_REVIEW_INTEGRATION"
_REQUIRED = {
    "JW_PG_STAGE_V84": "ISOLATED_DEV_READ_ONLY",
    "JW_PG_AUTH_V85": "ISOLATED_DEV_AUTH_ONLY",
    "JW_PG_MESSENGER_V90": "ISOLATED_DEV_MESSENGER_ONLY",
    "JW_PG_QUOTE_V92": "ISOLATED_DEV_QUOTE_V92",
}
_FORBIDDEN_USERS = frozenset({
    "postgres", "supabase_admin", "service_role", "jw_app_dev",
    "jw_auth_stage_v85", "authenticator", "anon", "authenticated",
})
_OPTIONAL_FLAGS = (
    "JW_PG_DELIVERY_REVIEW_V154",
    "JW_PG_IMPORT_QUOTE_V160",
    "JW_PG_INVOICE_BALANCE_V161",
    "JW_PG_TRADE_LINEAGE_V158",
)


def _validate_dsn(name: str) -> tuple[str, str]:
    """Reject privileged and insecure stage configuration before mounting routes.

    Actual DB privileges are checked again within the original per-request
    cursor implementations, never inferred from the configured username.
    """
    from psycopg.conninfo import conninfo_to_dict
    value = os.environ.get(name, "")
    if not value or len(value) > 8192:
        raise RuntimeError("BLOCKED: missing or invalid PostgreSQL role credential")
    try:
        config = conninfo_to_dict(value)
    except (ValueError, TypeError):
        raise RuntimeError("BLOCKED: invalid PostgreSQL connection string") from None
    user = config.get("user", "")
    host = config.get("host", "")
    if not user or user in _FORBIDDEN_USERS or not host:
        raise RuntimeError("BLOCKED: PostgreSQL credential must be restricted")
    if config.get("sslmode", "verify-full") not in ("verify-full",):
        raise RuntimeError("BLOCKED: PostgreSQL certificate verification required")
    # Never return/print the password. Require independent, explicit credentials.
    if not config.get("password"):
        raise RuntimeError("BLOCKED: PostgreSQL role password missing")
    return user, host


def preflight() -> None:
    if (os.environ.get("JW_PG_REVIEW_INTEGRATION") != _MODE
            or os.environ.get("JW_ENV", "").lower() not in ("dev", "development", "test")
            or os.environ.get("JW_INSECURE_LOCAL_DEV") == "1"):
        raise RuntimeError("BLOCKED: isolated PostgreSQL review opt-in required")
    for key, expected in _REQUIRED.items():
        if os.environ.get(key) != expected:
            raise RuntimeError("BLOCKED: required PostgreSQL capability disabled")
    trade = _validate_dsn("JW_PG_STAGE_DSN")
    auth = _validate_dsn("JW_PG_AUTH_STAGE_DSN")
    if trade == auth or os.environ["JW_PG_STAGE_DSN"] == os.environ["JW_PG_AUTH_STAGE_DSN"]:
        raise RuntimeError("BLOCKED: authentication and business roles must be separated")
    pg_messenger._origins()
    if not (pg_reader.stage_enabled() and pg_auth.auth_stage_enabled()
            and pg_messenger.v90_enabled() and pg_quote.enabled()):
        raise RuntimeError("BLOCKED: PostgreSQL prerequisite gate denied")
    if os.environ.get("JW_PG_DELIVERY_WRITER_V159") and not os.environ.get("JW_PG_DELIVERY_REVIEW_V154"):
        raise RuntimeError("BLOCKED: unattached dedicated delivery writer")
    if os.environ.get("JW_PG_DELIVERY_REVIEW_V154") and not delivery_review.enabled():
        raise RuntimeError("BLOCKED: delivery verification not ready")
    if os.environ.get("JW_PG_IMPORT_QUOTE_V160") and not import_quote.enabled():
        raise RuntimeError("BLOCKED: verified import source unavailable")
    if os.environ.get("JW_PG_TRADE_LINEAGE_V158") and not trade_lineage.enabled():
        raise RuntimeError("BLOCKED: trade lineage verification unavailable")
    if os.environ.get("JW_PG_INVOICE_BALANCE_V161") and not invoice_balance.enabled():
        raise RuntimeError("BLOCKED: invoice balance verification unavailable")
    if os.environ.get("JW_PG_CINEMA_TRADE_V1") and not cinema_trade.cinema_trade_enabled():
        raise RuntimeError("BLOCKED: CINEMA trade writer prerequisite gate denied")
    if os.environ.get(cinema_legacy_api.GATE_ENV) and not (
            cinema_legacy_api.legacy_api_gate_on() and cinema_trade.cinema_trade_enabled()):
        raise RuntimeError("BLOCKED: legacy-contract PG API needs its own gate and the CINEMA trade gate")


def create_app() -> FastAPI:
    """Explicit uvicorn --factory entrypoint for review; not production."""
    preflight()
    app = FastAPI(
        title="JARVIS WORKS isolated PG review",
        docs_url=None, redoc_url=None, openapi_url=None,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    @app.get("/health")
    def health():
        # Reachability is not a database/auth/release acceptance signal.
        return {"service": "isolated-pg-review", "release_ready": False}

    @app.get("/api/pg-review/capabilities")
    def capabilities(request: Request, response: Response):
        # Authenticated tenant identity originates inside PostgreSQL, not UI.
        with pg_messenger._pg_validated_cursor(pg_messenger._session_hash(request)) as (_, identity):
            response.headers["Cache-Control"] = "no-store"
            return {
                "org_id": identity[2],
                "quote_draft": True,
                "order_draft": True,
                "messenger_server": True,
                "delivery_review_only": bool(os.environ.get("JW_PG_DELIVERY_REVIEW_V154")),
                "import_reviewed_draft_only": bool(os.environ.get("JW_PG_IMPORT_QUOTE_V160")),
                "invoice_balance_preview_only": bool(os.environ.get("JW_PG_INVOICE_BALANCE_V161")),
                "trade_lineage_read_only": bool(os.environ.get("JW_PG_TRADE_LINEAGE_V158")),
                "delivery_posting": False,
                "invoice_posting": False,
                "payment_posting": False,
                "automatic_document_approval": False,
                "release_ready": False,
            }

    # S4 selects a single writer for this stage without modifying existing
    # v92 business tables or the existing quote API implementation.
    cinema_single_writer = cinema_trade.cinema_trade_enabled()
    required = (
        (pg_reader.register_stage_api, "reader"),
        (pg_auth.register_v85_auth, "auth"),
        (pg_messenger.register_v90_messenger, "messenger"),
        (pg_quote.register_v92_quote_api, "quote writer"),
        (pg_quote_read.register_v93_quote_reader, "quote reader"),
        (invoice_preview.register_v145_invoice_preview, "invoice preview"),
    )
    for register, name in required:
        if name == "quote writer" and cinema_single_writer:
            continue  # v92 writer disabled in CINEMA trade mode (fail closed).
        if not register(app):
            raise RuntimeError("BLOCKED: PostgreSQL stage component unavailable: " + name)
    for register in (
        delivery_review.register_v154_delivery_review,
        import_quote.register_v160_pg_import_quote,
        trade_lineage.register_v158_trade_lineage,
        invoice_balance.register_v161_invoice_balance,
        cinema_trade.register_cinema_trade_v1,
    ):
        register(app)  # Modules independently fail closed on malformed opt-ins.
    # V22.3: legacy UI contract on the PG engine. Own gate + CINEMA trade gate; per-company
    # allow-list read per request, default nobody. Registered separately so the reviewed
    # optional list above stays unchanged.
    cinema_legacy_api.register_legacy_api_v1(app)
    return app
