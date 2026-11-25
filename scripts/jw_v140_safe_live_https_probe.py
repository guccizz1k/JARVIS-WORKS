"""One-shot, non-mutating live Render HTTPS ingress/security probe.

Actual HTTPS outbound to the deployed Render hostname. It does NOT create
fixture rows, invoke auth/login writes, disclose the staging key, or claim
cross-tenant positive-control acceptance. Disabled unless the exact opt-in
environment flag is set. All public-facing business routes remain behind the
existing outer X-JW-Stage-Key gate.
"""
from __future__ import annotations

import asyncio
import logging
import os

import httpx

_LOG = logging.getLogger("jarvis.stage1.hosted_safe")
_HOST = "https://jw-stage1-secure-20261030.onrender.com"
_ACK = "V140_ISOLATED_READONLY_HTTPS_DENIAL_ONLY"


async def verify() -> str:
    if (os.getenv("JW_ENV") not in ("dev", "development", "test")
        or os.getenv("JW_STAGE1_PUBLIC_ACK") != "V134_STAGE1_PUBLIC_ISOLATED_ONLY"
        or os.getenv("JW_STAGE1_SAFE_HTTPS_PROBE") != _ACK):
        return "NOT_RUN_NOT_APPROVED"
    key = os.getenv("JW_STAGE1_ACCESS_KEY", "")
    if len(key) < 40:
        return "BLOCKED_STAGE_KEY"
    endpoints = (
        "/api/pg-stage/v84/me",
        "/api/pg-stage/v84/customers",
        "/api/pg-stage/v84/quotes",
        "/api/pg-stage/v90/me",
        "/api/pg-stage/v90/companies",
        "/api/pg-stage/v90/chats/jw-v140-missing/attachments/jw-v140-missing",
    )
    try:
        async with httpx.AsyncClient(timeout=18, follow_redirects=False) as c:
            h = await c.get(_HOST + "/healthz")
            if (h.status_code != 200
                or h.json().get("mode") != "isolated_pg_api_only"):
                return "BLOCKED_HOSTED_HEALTH_OR_PG_MODE"
            for n, path in enumerate(endpoints):
                denied = await c.get(_HOST + path)
                if denied.status_code != 403:
                    return "FAIL_PUBLIC_GATE_" + str(n)
                no_cookie = await c.get(
                    _HOST + path, headers={"X-JW-Stage-Key": key})
                if no_cookie.status_code != 401:
                    return "FAIL_MISSING_SESSION_" + str(n) + "_" + str(no_cookie.status_code)
                # Retry once only on transient gateway errors caused by
                # zero-downtime worker rotation; a persistent 5xx stays FAIL.
                forged_headers = {
                    "X-JW-Stage-Key": key,
                    "Cookie": "__Host-jw_session=not-a-real-verified-session-token-abcdefghijk",
                }
                forged = await c.get(_HOST + path, headers=forged_headers)
                if forged.status_code in (502, 503, 504):
                    await asyncio.sleep(4)
                    forged = await c.get(_HOST + path, headers=forged_headers)
                if forged.status_code != 401:
                    return "FAIL_FORGED_SESSION_" + str(n) + "_" + str(forged.status_code)
        return "PASS_HOSTED_HTTPS_STAGE_GATE_NO_SESSION_FORGED_SESSION"
    except Exception:
        # Never echo request headers, exception strings or anything from env.
        return "BLOCKED_HTTPS_TRANSPORT_OR_RESPONSE"


async def _after_startup() -> None:
    # Render's old worker may still be draining after new uvicorn startup.
    # Probe external HTTPS after the service cutover settles.
    await asyncio.sleep(14)
    result = await verify()
    _LOG.warning("STAGE1_HOSTED_HTTPS_NEGATIVE=%s", result)


def schedule() -> None:
    if os.getenv("JW_STAGE1_SAFE_HTTPS_PROBE") == _ACK:
        asyncio.create_task(_after_startup())
