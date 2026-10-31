"""V18.3: direct OUTSIDE-HOST HTTPS fail-closed probe of approved isolated Render stage.

Read-only GET only. Never accepts arbitrary URLs, live cookies, credentials,
production endpoints, or user-controlled paths. This is NOT positive E2E.
"""
from __future__ import annotations

import json
import os
import time

import httpx

HOST = "https://jw-stage1-secure-20261030.onrender.com"
ARM = "EXACT_ISOLATED_RENDER_STAGE_READONLY"
PATHS = (
    "/", "/docs", "/openapi.json", "/api/pg-stage/v84/me",
    "/api/pg-stage/v84/customers", "/api/pg-stage/v84/quotes",
    "/api/pg-stage/v90/me", "/api/pg-stage/v90/companies",
    "/api/pg-stage/v92/quotes",
    "/api/pg-stage/v90/chats/jw-v183-invalid/attachments/jw-v183-invalid",
)
HEADERS = (
    {},
    {"X-JW-Stage-Key": "invalid-short"},
    {"X-JW-Stage-Key": "v183-" + ("q" * 52),
     "X-Original-URL": "/healthz", "X-Forwarded-Host": "localhost",
     "Cookie": "__Host-jw_session=v183-forged-no-session"},
)


def probe(client: httpx.Client) -> int:
    """Fail on any unexpected public exposure, proxy redirect, or claimed release."""
    health = client.get(HOST + "/healthz", headers={"Cache-Control": "no-store"})
    if health.status_code != 200:
        raise AssertionError("V183_HEALTH_NOT_200")
    try:
        data = health.json()
    except (ValueError, json.JSONDecodeError) as e:
        raise AssertionError("V183_HEALTH_NOT_JSON") from e
    if data.get("mode") != "isolated_pg_api_only" or data.get("release") != "BLOCKED":
        raise AssertionError("V183_HOST_UNEXPECTED_MODE_OR_RELEASE")
    n = 0
    for path in PATHS:
        for headers in HEADERS:
            res = client.get(HOST + path, headers=headers)
            if res.status_code != 403:
                raise AssertionError("V183_UNPROTECTED_PATH_OR_PROXY_RESPONSE")
            try:
                payload = res.json()
            except (ValueError, json.JSONDecodeError) as e:
                raise AssertionError("V183_DENIAL_NOT_JSON") from e
            if payload != {"detail": "Staging access denied"}:
                raise AssertionError("V183_UNEXPECTED_DENIAL_BODY")
            if res.headers.get("cache-control", "").lower() != "no-store":
                raise AssertionError("V183_DENIAL_CACHE_CONTROL_MISSING")
            n += 1
    return n


def main() -> None:
    if os.getenv("JW_ENV") != "review" or os.getenv("JW_V183_READONLY_ACK") != ARM:
        raise RuntimeError("BLOCKED_V183_EXPLICIT_REVIEW_CONSENT_MISSING")
    # Genuine external TLS verification by httpx/OpenSSL, no redirect following.
    for attempt in range(3):
        try:
            with httpx.Client(timeout=httpx.Timeout(25.0, connect=15.0),
                              follow_redirects=False, verify=True,
                              trust_env=False) as client:
                count = probe(client)
            if count != 30:
                raise AssertionError("V183_INSUFFICIENT_CASES")
            print("PASS_V183_OUTSIDE_HOST_TLS_30_NEGATIVE_HTTPS_CASES_NO_RELEASE", flush=True)
            return
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError):
            if attempt == 2:
                raise RuntimeError("BLOCKED_V183_EXTERNAL_NETWORK_OR_TLS") from None
            time.sleep(3)
    raise AssertionError("BLOCKED_V183_UNREACHABLE")


if __name__ == "__main__":
    main()
