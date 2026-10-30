"""One-shot actual Render HTTPS -> V85 PostgreSQL login/recovery/logout probe.

Review-only opt-in and explicitly seeded synthetic accounts. Uses the real
separate PostgreSQL auth login and cookie, not a TestClient nor mocked SQL.
All status reporting is fixed, never a session cookie, password, or DSN.
Paired V143 database cleanup MUST run after the probe on any outcome.
"""
from __future__ import annotations

import asyncio
import logging
import os

import httpx

LOG = logging.getLogger("jarvis.stage2.hosted_auth")
HOST = "https://jw-stage1-secure-20261030.onrender.com"
ACK = "V143_ISOLATED_SYNTHETIC_AUTH_HTTPS_ONESHOT"
PWD = "JWv143.synth.only_20261030.TestPassword-42!"
RECOVERY = "0123456789abcdef0123456789abcdef"
PATH = "/api/pg-stage/v85"
ME = "/api/pg-stage/v90/me"


def _check(label: str, good: bool) -> None:
    if not good:
        raise ValueError(label)


async def _login(client: httpx.AsyncClient, user: str, password: str,
                 recovery: str | None = None) -> httpx.Response:
    body = {"email": "jw-v143-" + user + "@invalid.test", "password": password}
    if recovery is not None:
        body["recovery_code"] = recovery
    return await client.post(HOST + PATH + "/login", json=body)


async def verify() -> str:
    if (os.getenv("JW_ENV") not in ("dev", "development", "test")
        or os.getenv("JW_STAGE1_PUBLIC_ACK") != "V134_STAGE1_PUBLIC_ISOLATED_ONLY"
        or os.getenv("JW_STAGE2_AUTH_HTTPS_PROBE") != ACK):
        return "NOT_RUN_NOT_APPROVED"
    key = os.getenv("JW_STAGE1_ACCESS_KEY", "")
    if len(key) < 40:
        return "BLOCKED_NO_STAGE_KEY"
    try:
        async with httpx.AsyncClient(
            timeout=25, follow_redirects=False,
            headers={"X-JW-Stage-Key": key, "Cache-Control": "no-store"},
        ) as client:
            response = await _login(client, "a", "deliberately-wrong")
            _check("BAD_PASSWORD_A_" + str(response.status_code), response.status_code == 401)
            response = await _login(client, "a", PWD)
            _check("GOOD_LOGIN_A_" + str(response.status_code), response.status_code == 200)
            cookie = response.headers.get("set-cookie", "")
            _check("COOKIE_FLAGS", all(x in cookie.lower() for x in
                    ("__host-jw_session=", "secure", "httponly", "samesite=strict", "path=/")))
            body = response.json()
            _check("PG_AUTH_BACKEND", body.get("backend") == "postgresql_auth_stage")
            csrf = body.get("csrf_token", "")
            _check("CSRF_ISSUED", isinstance(csrf, str) and len(csrf) >= 32)
            me = await client.get(HOST + ME)
            _check("ME_A_" + str(me.status_code),
                   me.status_code == 200 and me.json().get("org_id") == "jw-v143-orga")
            wrong_logout = await client.post(HOST + PATH + "/logout",
                                              headers={"X-CSRF-Token": "wrong-csrf"})
            _check("WRONG_CSRF_LOGOUT_" + str(wrong_logout.status_code),
                   wrong_logout.status_code == 403)
            still_valid = await client.get(HOST + ME)
            _check("SESSION_SURVIVED_WRONG_CSRF", still_valid.status_code == 200)
            good_logout = await client.post(HOST + PATH + "/logout",
                                             headers={"X-CSRF-Token": csrf})
            _check("LOGOUT_A_" + str(good_logout.status_code), good_logout.status_code == 200)
            after = await client.get(HOST + ME)
            _check("REVOKED_A_" + str(after.status_code), after.status_code == 401)
            client.cookies.clear()
            response = await _login(client, "b", PWD)
            _check("MFA_REQUIRED_B_" + str(response.status_code), response.status_code == 401)
            response = await _login(client, "b", PWD, "f" * 32)
            _check("MFA_BAD_RECOVERY_B_" + str(response.status_code),
                   response.status_code == 401)
            response = await _login(client, "b", PWD, RECOVERY)
            _check("MFA_GOOD_RECOVERY_B_" + str(response.status_code),
                   response.status_code == 200)
            csrf_b = response.json().get("csrf_token", "")
            me_b = await client.get(HOST + ME)
            _check("ME_B_" + str(me_b.status_code),
                   me_b.status_code == 200 and me_b.json().get("org_id") == "jw-v143-orgb")
            logout_b = await client.post(HOST + PATH + "/logout",
                                          headers={"X-CSRF-Token": csrf_b})
            _check("LOGOUT_B_" + str(logout_b.status_code), logout_b.status_code == 200)
            client.cookies.clear()
            replay = await _login(client, "b", PWD, RECOVERY)
            _check("RECOVERY_REPLAY_DENIED_" + str(replay.status_code),
                   replay.status_code == 401)
        return "PASS_HOSTED_V143_PG_LOGIN_LOGOUT_CSRF_MFA_RECOVERY_REPLAY"
    except ValueError as exc:
        return "FAIL_" + str(exc)
    except Exception:
        return "BLOCKED_HTTPS_OR_DATABASE_EXCEPTION"


async def _run() -> None:
    await asyncio.sleep(18)
    LOG.warning("STAGE2_HOSTED_AUTH_HTTPS=%s", await verify())


def schedule() -> None:
    if os.getenv("JW_STAGE2_AUTH_HTTPS_PROBE") == ACK:
        asyncio.create_task(_run())
