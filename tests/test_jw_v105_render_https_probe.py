"""Guardrails for optional Render HTTPS transport probe; never a DB E2E pass."""
import pytest
from fastapi.testclient import TestClient
from scripts import jw_v105_render_https_probe as stage


def setup(monkeypatch):
    monkeypatch.setenv("JW_ENV", "review")
    monkeypatch.setenv("JW_HTTPS_PROBE_MODE", stage.MODE)
    monkeypatch.setenv("JW_HTTPS_PROBE_ACK", stage.ACK)
    monkeypatch.delenv("JW_RELEASE_APPROVED", raising=False)
    for name in stage.BANNED:
        monkeypatch.delenv(name, raising=False)


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("JW_HTTPS_PROBE_ACK", raising=False)
    assert not stage.preflight()
    with pytest.raises(RuntimeError, match="BLOCKED"):
        stage.create_app()


@pytest.mark.parametrize("name,value", [
    ("JW_ENV", "production"),
    ("JW_RELEASE_APPROVED", "true"),
    ("JW_HTTPS_PROBE_MODE", "BUSINESS_API"),
    ("JW_PG_STAGE_DSN", "postgresql://example"),
    ("JW_PG_AUTH_STAGE_DSN", "postgresql://example"),
    ("DATABASE_URL", "postgresql://example"),
    ("JW_INSECURE_LOCAL_DEV", "1"),
])
def test_preflight_fails_closed_for_unsafe_configuration(monkeypatch, name, value):
    setup(monkeypatch)
    monkeypatch.setenv(name, value)
    assert not stage.preflight()
    with pytest.raises(RuntimeError, match="BLOCKED"):
        stage.create_app()


def test_http_surface_has_zero_business_endpoints(monkeypatch):
    setup(monkeypatch)
    app = stage.create_app()
    c = TestClient(app, base_url="https://preview.example.invalid")
    response = c.get("/")
    assert response.status_code == 200
    assert response.json()["business_api"] == "DISABLED"
    assert response.json()["database"] == "NOT_CONNECTED"
    assert response.json()["release"] == "BLOCKED"
    assert response.headers["x-robots-tag"].startswith("noindex")
    assert response.headers["cache-control"] == "no-store"
    assert c.get("/healthz").json() == {"status":"ok","scope":"transport_only"}
    for path in ("/docs", "/openapi.json", "/api/me", "/api/login",
                 "/api/pg-stage/v85/login", "/api/pg-stage/v90/chats",
                 "/api/pg-stage/v92/quotes"):
        assert c.get(path).status_code == 404, path
    assert c.post("/api/pg-stage/v92/quotes", json={}).status_code == 404
