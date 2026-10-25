"""Render free-tier HTTPS transport preflight ONLY (no DB, auth, or product APIs).

This deliberately exposes just a safe status message. Real PostgreSQL-backed
business endpoints must NOT be mounted until independent credentials, migrations,
live identity and tenant authorization have been verified.
"""
from __future__ import annotations

import os

from fastapi import FastAPI, Response

ACK = "REVIEW_ONLY_NO_BUSINESS_ENDPOINTS"
MODE = "HTTPS_TRANSPORT_PROBE"
BANNED = (
    "JW_PG_STAGE_DSN",
    "JW_PG_AUTH_STAGE_DSN",
    "DATABASE_URL",
    "JW_RENDER_PG_TRADE_DSN",
    "JW_RENDER_PG_AUTH_DSN",
    "JW_RENDER_PG_BOOTSTRAP_DSN",
    "JW_INSECURE_LOCAL_DEV",
)


def preflight() -> bool:
    return (
        os.environ.get("JW_ENV") == "review"
        and os.environ.get("JW_HTTPS_PROBE_MODE") == MODE
        and os.environ.get("JW_HTTPS_PROBE_ACK") == ACK
        and os.environ.get("JW_RELEASE_APPROVED", "").lower() not in ("true", "1", "yes")
        and not any(os.environ.get(name) for name in BANNED)
    )


def create_app() -> FastAPI:
    if not preflight():
        raise RuntimeError("BLOCKED: review transport probe requires no DB or product credentials")
    app = FastAPI(
        title="JARVIS WORKS HTTPS transport probe",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/", include_in_schema=False)
    def index(response: Response):
        response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return {
            "service": "JARVIS-WORKS isolated staging infrastructure",
            "transport": "HTTPS via hosting TLS termination",
            "database": "NOT_CONNECTED",
            "business_api": "DISABLED",
            "release": "BLOCKED",
        }

    @app.get("/healthz", include_in_schema=False)
    def health(response: Response):
        response.headers["Cache-Control"] = "no-store"
        return {"status": "ok", "scope": "transport_only"}

    return app
