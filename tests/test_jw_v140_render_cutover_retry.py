"""Bounded hosted HTTPS cutover retries: transient 502 recovers; permanent 502 fails."""
import asyncio

from scripts import jw_v140_safe_live_https_probe as p


class Response:
    def __init__(self, status, data=None):
        self.status_code = status
        self._data = data or {}
    def json(self):
        return self._data


class FakeClient:
    def __init__(self, persistent=False):
        self.persistent = persistent
        self.first_forged = True
        self.forged_count = 0
    async def __aenter__(self):
        return self
    async def __aexit__(self, *args):
        return False
    async def get(self, url, headers=None):
        if url.endswith("/healthz"):
            return Response(200, {"mode": "isolated_pg_api_only"})
        if headers is None:
            return Response(403)
        if "Cookie" not in headers:
            return Response(401)
        self.forged_count += 1
        if self.persistent:
            return Response(502)
        if self.first_forged:
            self.first_forged = False
            return Response(502)
        return Response(401)


def _run(monkeypatch, persistent):
    monkeypatch.setenv("JW_ENV", "dev")
    monkeypatch.setenv("JW_STAGE1_PUBLIC_ACK", "V134_STAGE1_PUBLIC_ISOLATED_ONLY")
    monkeypatch.setenv("JW_STAGE1_SAFE_HTTPS_PROBE", p._ACK)
    monkeypatch.setenv("JW_STAGE1_ACCESS_KEY", "test-stage-key-abcdefghijklmnopqrstuvwxyz12345678")
    fake = FakeClient(persistent=persistent)
    monkeypatch.setattr(p.httpx, "AsyncClient", lambda **kw: fake)
    async def no_delay(*args):
        return None
    monkeypatch.setattr(p.asyncio, "sleep", no_delay)
    return asyncio.run(p.verify()), fake.forged_count


def test_single_render_cutover_502_is_retried_and_all_denials_still_checked(monkeypatch):
    result, n = _run(monkeypatch, persistent=False)
    assert result == "PASS_HOSTED_HTTPS_STAGE_GATE_NO_SESSION_FORGED_SESSION"
    assert n == 7  # six endpoints + one retry, not silently skipped


def test_persistent_gateway_502_remains_fail_closed(monkeypatch):
    result, n = _run(monkeypatch, persistent=True)
    assert result == "FAIL_FORGED_SESSION_0_502"
    assert n == 2  # bounded retry: fail after one extra request
