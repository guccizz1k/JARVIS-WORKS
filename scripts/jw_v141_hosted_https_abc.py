"""One-shot real Render HTTPS A/B/C positive session and cross-tenant review.

Opt-in for a disposable, explicitly seeded DEV fixture only. No customer data,
no messenger history, no persistent write from this probe. Existing PostgreSQL
session validation, RLS and HTTPS stage-key middleware are exercised unmodified.
The independent fixture cleanup must be run immediately after the probe.
"""
from __future__ import annotations

import asyncio
import logging
import os
import httpx

_LOG = logging.getLogger("jarvis.stage1.hosted_abc")
_HOST = "https://jw-stage1-secure-20261030.onrender.com"
_ACK = "V141_REVIEW_ONLY_NONMESSENGER_SYNTHETIC_A_B_C"
_TOKENS = {
    "A": "jw-v140-synthetic-cookie-aba9-nonprod-20261030-A-aYk7u2Qp",
    "B": "jw-v140-synthetic-cookie-aba9-nonprod-20261030-B-bJw9f5Km",
    "C": "jw-v140-synthetic-cookie-aba9-nonprod-20261030-C-cWn8x4Ts",
}
_ORGS = {"A": "jw-v141-orga", "B": "jw-v141-orgb", "C": "jw-v141-orgc"}
_CUSTOMERS = {"A": {"jw-v141-ca"}, "B": {"jw-v141-cb"}, "C": set()}
_QUOTES = {"A": {"jw-v141-qa"}, "B": {"jw-v141-qb"}, "C": set()}


async def _get(client, url: str, headers):
    res = await client.get(url, headers=headers)
    if res.status_code in (502, 503, 504):
        await asyncio.sleep(4)
        res = await client.get(url, headers=headers)
    return res


async def check() -> str:
    if (os.getenv("JW_ENV") not in ("dev", "development", "test")
        or os.getenv("JW_STAGE1_PUBLIC_ACK") != "V134_STAGE1_PUBLIC_ISOLATED_ONLY"
        or os.getenv("JW_STAGE1_POSITIVE_HTTPS_PROBE") != _ACK):
        return "NOT_RUN_NOT_APPROVED"
    key = os.getenv("JW_STAGE1_ACCESS_KEY", "")
    if len(key) < 40:
        return "BLOCKED_STAGE_KEY"
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
            for actor in ("A", "B", "C"):
                headers = {
                    "X-JW-Stage-Key": key,
                    "Cookie": "__Host-jw_session=" + _TOKENS[actor],
                    "Cache-Control": "no-store",
                }
                me = await _get(client, _HOST + "/api/pg-stage/v90/me", headers)
                if me.status_code != 200:
                    return "FAIL_SESSION_" + actor + "_" + str(me.status_code)
                who = me.json()
                if who.get("org_id") != _ORGS[actor] or not who.get("csrf_token"):
                    return "FAIL_SERVER_ISSUED_IDENTITY_" + actor
                for path, expected, label in (
                    ("/api/pg-stage/v84/customers", _CUSTOMERS[actor], "CUSTOMER"),
                    ("/api/pg-stage/v84/quotes", _QUOTES[actor], "QUOTE"),
                    ("/api/pg-stage/v92/quotes", _QUOTES[actor], "V93_QUOTE"),
                ):
                    response = await _get(client, _HOST + path, headers)
                    if response.status_code != 200:
                        return ("FAIL_" + label + "_HTTP_" + actor + "_"
                                + str(response.status_code))
                    ids = {row["id"] for row in response.json()}
                    if ids != expected:
                        return "FAIL_CROSS_ORG_" + label + "_" + actor
            a_headers = {
                "X-JW-Stage-Key": key,
                "Cookie": "__Host-jw_session=" + _TOKENS["A"],
                "Origin": _HOST,
                "Cache-Control": "no-store",
            }
            payload = {
                "request_id": "jw141-cross-tenant-001",
                "customer_id": "jw-v141-cb",
                "title": "must not persist",
                "vat_mode": "taxable",
                "items": [{"name": "forged", "quantity": 1, "unit_price": 100}],
            }
            no_csrf = await client.post(
                _HOST + "/api/pg-stage/v92/quotes", headers=a_headers, json=payload)
            if no_csrf.status_code != 403:
                return "FAIL_MISSING_CSRF_" + str(no_csrf.status_code)
            me_a = await _get(client, _HOST + "/api/pg-stage/v90/me", a_headers)
            if me_a.status_code != 200:
                return "FAIL_CSRF_IDENTITY_" + str(me_a.status_code)
            forged = await client.post(
                _HOST + "/api/pg-stage/v92/quotes",
                headers={**a_headers, "X-CSRF-Token": me_a.json()["csrf_token"]},
                json=payload,
            )
            if forged.status_code != 404:
                return "FAIL_CROSS_TENANT_WRITE_" + str(forged.status_code)
        return "PASS_HOSTED_HTTPS_ABC_POSITIVE_SESSIONS_RLS_CSRF_WRITE_DENIAL"
    except Exception:
        # Do not log exception text, response bodies, cookies or headers.
        return "BLOCKED_HTTPS_TRANSPORT_OR_RESPONSE"


async def _run() -> None:
    await asyncio.sleep(15)
    result = await check()
    _LOG.warning("STAGE1_HOSTED_HTTPS_ABC_POSITIVE=%s", result)


def schedule() -> None:
    if os.getenv("JW_STAGE1_POSITIVE_HTTPS_PROBE") == _ACK:
        asyncio.create_task(_run())
