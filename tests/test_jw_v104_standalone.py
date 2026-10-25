"""Safe PG-only external staging assembly contracts; no database/network actions."""
import pytest
from fastapi.testclient import TestClient
from scripts import jw_v104_standalone as stage

def configure(monkeypatch):
    monkeypatch.setenv("JW_ENV", "dev")
    monkeypatch.setenv("JW_STAGE_API_ACK", stage.ACK)
    monkeypatch.setenv("JW_V90_ALLOWED_ORIGINS", "https://review.example.invalid")
    monkeypatch.delenv("JW_INSECURE_LOCAL_DEV", raising=False)
    for k,v in stage.REQUIRED_MODES.items():
        monkeypatch.setenv(k,v)
    monkeypatch.setenv("JW_PG_STAGE_DSN",
        "postgresql://jw_trade_gateway_v90:fake@pg.invalid:5432/postgres?sslmode=verify-full")
    monkeypatch.setenv("JW_PG_AUTH_STAGE_DSN",
        "postgresql://jw_auth_gateway_v90:fake@pg.invalid:5432/postgres?sslmode=verify-full")

def test_default_off_and_wrong_environment(monkeypatch):
    assert stage.preflight() is False
    with pytest.raises(RuntimeError, match="BLOCKED"):
        stage.create_app()
    configure(monkeypatch)
    monkeypatch.setenv("JW_ENV","production")
    assert stage.preflight() is False

def test_reject_unsafe_database_and_insecure_cookie_config(monkeypatch):
    configure(monkeypatch)
    assert stage.preflight()
    monkeypatch.setenv("JW_PG_STAGE_DSN",
        "postgresql://postgres:password@pg.invalid/postgres?sslmode=verify-full")
    assert not stage.preflight()
    configure(monkeypatch)
    monkeypatch.setenv("JW_PG_AUTH_STAGE_DSN",
        "postgresql://jw_trade_gateway_v90:fake@pg.invalid/postgres?sslmode=verify-full")
    assert not stage.preflight()
    configure(monkeypatch)
    monkeypatch.setenv("JW_PG_STAGE_DSN",
        "postgresql://jw_trade_gateway_v90:fake@pg.invalid/postgres?sslmode=disable")
    assert not stage.preflight()
    configure(monkeypatch)
    monkeypatch.setenv("JW_INSECURE_LOCAL_DEV","1")
    assert not stage.preflight()

def test_reject_no_origin_or_wildcard(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setenv("JW_V90_ALLOWED_ORIGINS","https://review.example.invalid,*")
    assert not stage.preflight()
    monkeypatch.setenv("JW_V90_ALLOWED_ORIGINS","")
    assert not stage.preflight()

def test_standalone_excludes_legacy_sqlite_and_document_production_routes(monkeypatch):
    configure(monkeypatch)
    app=stage.create_app()
    # Route-tree internals vary with FastAPI versions. Verify the actual HTTP
    # boundary instead of relying on private _IncludedRouter.path layout.
    client=TestClient(app,base_url="https://review.example.invalid")
    assert client.get("/healthz").json()=={
        "mode":"isolated_pg_api_only","release":"BLOCKED"}
    assert client.get("/docs").status_code==404
    assert client.get("/openapi.json").status_code==404
    for forbidden in ("/api/login","/api/register","/api/me",
                      "/api/quotes","/api/orders/from-quote",
                      "/api/invoices/from-order","/api/import-previews"):
        assert client.get(forbidden).status_code==404,forbidden
    assert client.get("/api/pg-stage/v90/me").status_code==401
    assert client.get("/api/pg-stage/v84/me").status_code==401
    assert client.get("/api/pg-stage/v92/quotes").status_code==401
    for route in ("/api/pg-stage/v85/login","/api/pg-stage/v90/chats",
                  "/api/pg-stage/v92/quotes"):
        assert client.post(route,json={}).status_code==422,route
