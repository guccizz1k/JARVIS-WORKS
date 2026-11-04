"""Independent negative-controls for the isolated PostgreSQL composition.

These are contract/route tests with intentionally unusable DSNs, not proof of
a real hosted PG transaction or release suitability.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import pg_review_integrated_v202 as stage

TRADE = "postgresql://jw_trade_stage_user:synthetic-only@pg-trade.invalid/jw?sslmode=verify-full"
AUTH = "postgresql://jw_auth_stage_user:synthetic-only@pg-auth.invalid/jw?sslmode=verify-full"


@pytest.fixture
def secure_stage(monkeypatch):
    values = {
        "JW_ENV": "dev",
        "JW_PG_REVIEW_INTEGRATION": "ISOLATED_DEV_PG_REVIEW_INTEGRATION",
        "JW_PG_STAGE_V84": "ISOLATED_DEV_READ_ONLY",
        "JW_PG_AUTH_V85": "ISOLATED_DEV_AUTH_ONLY",
        "JW_PG_MESSENGER_V90": "ISOLATED_DEV_MESSENGER_ONLY",
        "JW_PG_QUOTE_V92": "ISOLATED_DEV_QUOTE_V92",
        "JW_PG_STAGE_DSN": TRADE,
        "JW_PG_AUTH_STAGE_DSN": AUTH,
        "JW_V90_ALLOWED_ORIGINS": "https://pg-stage.example.test",
    }
    for key in (
        "JW_INSECURE_LOCAL_DEV", "JW_PG_DELIVERY_WRITER_V159",
        "JW_PG_DELIVERY_REVIEW_V154", "JW_PG_IMPORT_QUOTE_V160",
        "JW_PG_INVOICE_BALANCE_V161", "JW_DATA_KEY",
        "JW_V154_ISSUER_INDEPENDENCE_ACK",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return values


@pytest.mark.parametrize(("key", "bad"), [
    ("JW_ENV", "production"),
    ("JW_ENV", "prod"),
    ("JW_ENV", "review"),
    ("JW_ENV", ""),
    ("JW_INSECURE_LOCAL_DEV", "1"),
    ("JW_PG_REVIEW_INTEGRATION", "ISOLATED_DEV_READ_ONLY"),
    ("JW_PG_REVIEW_INTEGRATION", ""),
    ("JW_PG_STAGE_V84", "OFF"),
    ("JW_PG_STAGE_V84", ""),
    ("JW_PG_AUTH_V85", "OFF"),
    ("JW_PG_MESSENGER_V90", "OFF"),
    ("JW_PG_QUOTE_V92", "OFF"),
    ("JW_PG_STAGE_DSN", ""),
    ("JW_PG_AUTH_STAGE_DSN", ""),
    ("JW_PG_AUTH_STAGE_DSN", TRADE),
    ("JW_PG_STAGE_DSN", "postgresql://postgres:synthetic-only@host.invalid/jw"),
    ("JW_PG_AUTH_STAGE_DSN", "postgresql://service_role:synthetic-only@host.invalid/jw"),
    ("JW_PG_STAGE_DSN", "postgresql://jw_app_dev:synthetic-only@host.invalid/jw"),
    ("JW_PG_AUTH_STAGE_DSN", "postgresql://jw_auth_stage_v85:synthetic-only@host.invalid/jw"),
    ("JW_PG_STAGE_DSN", "postgresql://jw_stage:synthetic-only@host.invalid/jw?sslmode=disable"),
    ("JW_PG_STAGE_DSN", "postgresql://jw_stage:synthetic-only@host.invalid/jw?sslmode=require"),
    ("JW_PG_AUTH_STAGE_DSN", "postgresql://jw_auth:synthetic-only@host.invalid/jw?sslmode=prefer"),
    ("JW_PG_STAGE_DSN", "postgresql://jw_stage@host.invalid/jw"),
    ("JW_V90_ALLOWED_ORIGINS", ""),
    ("JW_V90_ALLOWED_ORIGINS", "http://pg-stage.example.test"),
    ("JW_V90_ALLOWED_ORIGINS", "https://pg-stage.example.test/path"),
    ("JW_V90_ALLOWED_ORIGINS", "https://*.example.test"),
    ("JW_V90_ALLOWED_ORIGINS", "https://pg-stage.example.test,https://pg-stage.example.test"),
    ("JW_PG_DELIVERY_WRITER_V159", "ISOLATED_DEV_SEPARATE_REVIEW_WRITER"),
    ("JW_PG_DELIVERY_REVIEW_V154", "ISOLATED_DEV_SIGNED_RECEIPT_REVIEW_ONLY"),
    ("JW_PG_IMPORT_QUOTE_V160", "ISOLATED_DEV_APPROVED_IMPORT_QUOTE_ONLY"),
    ("JW_PG_INVOICE_BALANCE_V161", "MISCONFIGURED"),
    ("JW_PG_TRADE_LINEAGE_V158", "WRONG_MODE"),
])
def test_unsafe_stage_configuration_never_mounts_endpoints(secure_stage, monkeypatch, key, bad):
    monkeypatch.setenv(key, bad)
    with pytest.raises(RuntimeError, match="BLOCKED|HTTPS"):
        stage.create_app()


def test_distinct_stage_roles_are_required_even_with_distinct_dsns(secure_stage, monkeypatch):
    monkeypatch.setenv("JW_PG_AUTH_STAGE_DSN", AUTH.replace("jw_auth_stage_user", "jw_trade_stage_user").replace("pg-auth.invalid", "pg-trade.invalid"))
    with pytest.raises(RuntimeError, match="separated"):
        stage.create_app()


def test_stage_has_pg_capabilities_but_zero_legacy_business_routes(secure_stage):
    # Exercise HTTP instead of assuming FastAPI's internal router object shape.
    # The latest framework can return _IncludedRouter wrappers without .path.
    with TestClient(stage.create_app()) as client:
        assert client.get("/api/pg-stage/v90/me").status_code == 401
        assert client.get("/api/pg-stage/v92/quotes").status_code == 401
        assert client.post("/api/pg-stage/v92/quotes", json={}).status_code == 422
        assert client.get("/api/pg-stage/v92/quotes/" + "a" * 32).status_code == 401
        assert client.get("/api/pg-stage/v145/orders/" + "b" * 32 + "/invoice-preview").status_code == 401
        assert client.get("/api/pg-review/capabilities").status_code == 401
        for path in ("/api/login", "/api/customers", "/api/orders",
                     "/api/invoices", "/api/messenger/threads",
                     "/openapi.json", "/"):
            assert client.get(path).status_code == 404, path


def test_unauthenticated_capabilities_never_open_pg_connection(secure_stage, monkeypatch):
    app = stage.create_app()
    def forbidden(*_a, **_kw):
        raise AssertionError("No PostgreSQL query allowed without a cookie")
    monkeypatch.setattr(stage.pg_messenger, "_pg_validated_cursor", forbidden)
    with TestClient(app) as client:
        denied = client.get("/api/pg-review/capabilities")
        assert denied.status_code == 401
        assert client.get("/api/customers").status_code == 404
        assert client.get("/api/login").status_code == 404
        assert client.get("/").status_code == 404
        assert client.get("/openapi.json").status_code == 404
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json() == {"service": "isolated-pg-review", "release_ready": False}
        for response in (health, denied):
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["x-frame-options"] == "DENY"
            assert response.headers["x-content-type-options"] == "nosniff"


def test_stage_source_has_no_legacy_main_import_or_sqlite_runtime():
    source = Path(stage.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and ("main" in node.module.split(".") or "sqlite3" in node.module.split(".")):
                forbidden.append(node.module)
        if isinstance(node, ast.Import):
            forbidden.extend(alias.name for alias in node.names if alias.name in ("sqlite3", "app.main"))
    assert not forbidden, forbidden
    assert "from .main import" not in source
    assert "sqlite3.connect" not in source


def test_real_stage_opt_in_uses_only_pg_namespaced_api(secure_stage):
    with TestClient(stage.create_app()) as client:
        assert client.get("/api/pg-stage/v90/me").status_code == 401
        assert client.post("/api/pg-stage/v92/quotes", json={}).status_code in (401, 422)
        assert client.get("/api/pg-stage/v92/quotes").status_code == 401
        assert client.get("/api/pg-stage/v84/customers").status_code in (401, 404)


def test_read_only_trade_lineage_is_explicit_and_tenant_authenticated(secure_stage, monkeypatch):
    monkeypatch.setenv("JW_PG_TRADE_LINEAGE_V158", "ISOLATED_DEV_TRADE_LINEAGE_READ_ONLY")
    with TestClient(stage.create_app()) as client:
        unauthenticated = client.get("/api/pg-stage/v158/quotes/" + "a" * 32 + "/lineage")
        assert unauthenticated.status_code == 401
        assert client.post("/api/pg-stage/v158/quotes/" + "a" * 32 + "/lineage").status_code == 405
    monkeypatch.setenv("JW_PG_TRADE_LINEAGE_V158", "OFF")
    with pytest.raises(RuntimeError, match="BLOCKED"):
        stage.create_app()
