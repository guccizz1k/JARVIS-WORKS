"""One-shot actual hosted HTTPS synthetic-tenant probe (review only).

Enabled only on a separately authorized isolated staging service, after
preflight+PG role checks. All requests go over the public HTTPS hostname and
through the existing stage-key middleware and actual PostgreSQL-backed routers.
It neither issues fixture DDL nor claims independent release acceptance.
This is a review probe; the separate owner-authorized cleanup MUST run after it.
"""
from __future__ import annotations

import asyncio
import logging
import os

import httpx

LOG = logging.getLogger("jarvis.stage1.https_abc")
URL = "https://jw-stage1-secure-20261030.onrender.com"
ACK = "JW_V140_ISOLATED_SYNTHETIC_ONE_SHOT"

# TEST sessions; non-production, do not use after the paired fixture cleanup.
SYNTHETIC_TOKENS = {
    "A": "jw-v140-synthetic-cookie-aba9-nonprod-20261030-A-aYk7u2Qp",
    "B": "jw-v140-synthetic-cookie-aba9-nonprod-20261030-B-bJw9f5Km",
    "C": "jw-v140-synthetic-cookie-aba9-nonprod-20261030-C-cWn8x4Ts",
}
EXPECTED_ORGS = {k: "jw-v140-org-" + k.lower() for k in SYNTHETIC_TOKENS}


class ProofFailed(Exception):
    pass


async def _request(
    client: httpx.AsyncClient,
    path: str,
    *,
    subject: str | None = None,
    stage_key: str,
    method: str = "GET",
    csrf: str | None = None,
    body: dict | None = None,
) -> httpx.Response:
    headers = {"X-JW-Stage-Key": stage_key, "Cache-Control": "no-store"}
    if subject:
        headers["Cookie"] = "__Host-jw_session=" + SYNTHETIC_TOKENS[subject]
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    return await client.request(method, URL + path, headers=headers, json=body)


def _check(label: str, condition: bool) -> None:
    if not condition:
        raise ProofFailed(label)


async def check() -> str:
    if (os.getenv("JW_ENV") not in ("dev", "development", "test")
        or os.getenv("JW_STAGE1_PUBLIC_ACK") != "V134_STAGE1_PUBLIC_ISOLATED_ONLY"
        or os.getenv("JW_STAGE1_HTTPS_ABC_PROBE") != ACK):
        return "BLOCKED_NOT_ISOLATED_STAGE"
    secret = os.getenv("JW_STAGE1_ACCESS_KEY", "")
    if len(secret) < 40:
        return "BLOCKED_NO_STAGE_KEY"
    try:
        async with httpx.AsyncClient(timeout=18, follow_redirects=False) as client:
            # A real external HTTPS request, NOT TestClient/in-process mock.
            public = await client.get(URL + "/api/pg-stage/v84/me")
            _check("EXTERNAL_STAGE_GATE", public.status_code == 403)
            invalid = await _request(client, "/api/pg-stage/v84/me",
                                     stage_key=secret)
            _check("MISSING_PG_SESSION", invalid.status_code == 401)
            for org in SYNTHETIC_TOKENS:
                me = await _request(client, "/api/pg-stage/v90/me",
                                    subject=org, stage_key=secret)
                _check("LIVE_SESSION_" + org + "_" + str(me.status_code),
                       me.status_code == 200)
                _check("ORG_ID_" + org, me.json().get("org_id") == EXPECTED_ORGS[org])
                cust = await _request(client, "/api/pg-stage/v84/customers",
                                      subject=org, stage_key=secret)
                _check("CUSTOMERS_HTTP_" + org + "_" + str(cust.status_code),
                       cust.status_code == 200)
                ids = {item["id"] for item in cust.json()}
                own = {"A": {"jw-v140-customer-a"},
                       "B": {"jw-v140-customer-b"},
                       "C": set()}[org]
                _check("CUSTOMERS_RLS_" + org, ids == own)
                quotes = await _request(client, "/api/pg-stage/v84/quotes",
                                        subject=org, stage_key=secret)
                _check("QUOTES_HTTP_" + org + "_" + str(quotes.status_code),
                       quotes.status_code == 200)
                qids = {item["id"] for item in quotes.json()}
                expected = {"A": {"jw-v140-quote-a"},
                            "B": {"jw-v140-quote-b"},
                            "C": set()}[org]
                _check("QUOTES_RLS_" + org, qids == expected)
            attachment_path = ("/api/pg-stage/v90/chats/jw-v140-chat-ab"
                               "/attachments/jw-v140-message-ab")
            for org in ("A", "B"):
                attachment = await _request(client, attachment_path,
                                            subject=org, stage_key=secret)
                _check("ATTACHMENT_ALLOWED_" + org + "_" + str(attachment.status_code),
                       attachment.status_code == 200
                       and attachment.content == b"jw-v140-test-attachment")
            outsider = await _request(client, attachment_path,
                                      subject="C", stage_key=secret)
            _check("ATTACHMENT_C_DENIAL_" + str(outsider.status_code),
                   outsider.status_code == 403)
            wrong_conversation = await _request(
                client, "/api/pg-stage/v90/chats/jw-v140-chat-bc/attachments/jw-v140-message-bc",
                subject="A", stage_key=secret)
            _check("ATTACHMENT_A_DENIAL_" + str(wrong_conversation.status_code),
                   wrong_conversation.status_code == 403)
            missing_csrf = await _request(
                client, "/api/pg-stage/v90/chats/jw-v140-chat-ab/messages",
                subject="A", stage_key=secret, method="POST",
                body={"request_id": "jw-v140-forged-no-csrf", "body": "should not send"})
            _check("CSRF_DENIAL_" + str(missing_csrf.status_code),
                   missing_csrf.status_code == 403)
            # Uses real DB-provided CSRF for an unauthorized conversation.
            real_me = await _request(client, "/api/pg-stage/v90/me",
                                     subject="A", stage_key=secret)
            token = real_me.json().get("csrf_token", "")
            forbidden_write = await _request(
                client, "/api/pg-stage/v90/chats/jw-v140-chat-bc/messages",
                subject="A", stage_key=secret, csrf=token, method="POST",
                body={"request_id": "jw-v140-forged-foreign-send", "body": "should not send"})
            _check("WRONG_TENANT_WRITE_DENIAL_" + str(forbidden_write.status_code),
                   forbidden_write.status_code == 403)
        return "PASS_HOSTED_HTTPS_A_B_C_RLS_RPC_CSRF"
    except ProofFailed as exc:
        return "BLOCKED_" + str(exc)
    except Exception:
        # Never surface transport exceptions: some drivers include sensitive URIs.
        return "BLOCKED_HTTPS_TRANSPORT_OR_RESPONSE"


async def run_after_startup() -> None:
    await asyncio.sleep(2)
    result = await check()
    LOG.warning("STAGE1_HOSTED_HTTPS_ABC=%s", result)


def schedule() -> None:
    if os.getenv("JW_STAGE1_HTTPS_ABC_PROBE") != ACK:
        return
    asyncio.create_task(run_after_startup())
