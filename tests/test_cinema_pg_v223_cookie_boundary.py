"""V22.3 review-only cookie boundary negatives, with the real cutover module.

Both original session issuers use secrets.token_urlsafe; no PG or SQLite user data
or secrets are needed. Invalid values must be denied before backend routing.
"""
import secrets

import pytest
from app import pg_cinema_cutover_front_v223 as cut


def scope(cookie_name=None, value=""):
    headers = []
    if cookie_name is not None:
        headers.append((b"cookie", (cookie_name + "=" + value).encode("ascii")))
    return {"type": "http", "method": "GET", "scheme": "https",
            "path": "/api/quotes", "headers": headers}


@pytest.mark.parametrize("cookie_name", [cut.LEGACY_COOKIE, cut.PG_COOKIE])
@pytest.mark.parametrize("token", [
    "a" * 30, "a" * 512, "A" * 40, "p" * 64, "U" * 35 + "-_",
])
def test_actual_cookie_boundary_accepts_urlsafe_tokens(cookie_name, token):
    assert cut._safe_cookie(scope(cookie_name, token), cookie_name) == token


@pytest.mark.parametrize("cookie_name", [cut.LEGACY_COOKIE, cut.PG_COOKIE])
@pytest.mark.parametrize("invalid", [
    "a" * 29, "a" * 513, "a" * 40 + ".spoof",
    "a" * 40 + "%0d%0a", "a" * 40 + "@evil", "a" * 40 + ",admin=1",
    "a" * 40 + ":test", "a" * 40 + "=evil", "a" * 40 + "/evil",
])
def test_actual_cookie_boundary_denies_malformed_before_forwarding(cookie_name, invalid):
    with pytest.raises(cut.CutoverRefused) as exc:
        cut._safe_cookie(scope(cookie_name, invalid), cookie_name)
    assert exc.value.code == "invalid_session_cookie"
    assert exc.value.status == 401


@pytest.mark.parametrize("cookie_name", [cut.LEGACY_COOKIE, cut.PG_COOKIE])
def test_actual_login_issuer_urlsafe_tokens_remain_compatible(cookie_name):
    for size in (36, 48):
        token = secrets.token_urlsafe(size)
        assert cut._safe_cookie(scope(cookie_name, token), cookie_name) == token


@pytest.mark.parametrize("cookie_name", [cut.LEGACY_COOKIE, cut.PG_COOKIE])
def test_absent_session_cookie_is_not_manufactured(cookie_name):
    assert cut._safe_cookie(scope(), cookie_name) == ""
