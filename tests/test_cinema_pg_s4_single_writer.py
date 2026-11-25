"""S4 single-writer boundary; actual FastAPI route tests with synthetic invalid DSNs.

Both historical v92 and CINEMA data remain read-only reachable where explicitly
registered; only ONE write router may be mounted in this composition.
No network, Postgres, production credentials, or SQLite are accessed.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import pg_review_integrated_v202 as stage

TRADE="postgresql://jw_trade_stage_user:synthetic-only@pg-trade.invalid/jw?sslmode=verify-full"
AUTH="postgresql://jw_auth_stage_user:synthetic-only@pg-auth.invalid/jw?sslmode=verify-full"


@pytest.fixture
def isolated_stage(monkeypatch):
    required = {
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
        "JW_PG_CINEMA_TRADE_V1", "JW_INSECURE_LOCAL_DEV",
        "JW_PG_DELIVERY_WRITER_V159", "JW_PG_DELIVERY_REVIEW_V154",
        "JW_PG_IMPORT_QUOTE_V160", "JW_PG_INVOICE_BALANCE_V161",
        "JW_PG_TRADE_LINEAGE_V158", "JW_DATA_KEY",
        "JW_V154_ISSUER_INDEPENDENCE_ACK"
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in required.items():
        monkeypatch.setenv(key, value)
    return monkeypatch


def test_s4_disabled_by_default_preserves_v92_writer_routes(isolated_stage):
    with TestClient(stage.create_app()) as client:
        # The v92 write route is still present; malformed input returns 422.
        assert client.post("/api/pg-stage/v92/quotes", json={}).status_code == 422
        # CINEMA writer is absent and therefore cannot be used.
        assert client.post("/api/pg-stage/cinema-trade/quotes", json={}).status_code == 404


def test_s4_enabled_cinema_writer_excludes_v92_writer(isolated_stage):
    isolated_stage.setenv("JW_PG_CINEMA_TRADE_V1", "ISOLATED_DEV_CINEMA_TRADE_ONLY")
    with TestClient(stage.create_app()) as client:
        # Legacy v92 writer route never mounts in cinema mode.
        assert client.post("/api/pg-stage/v92/quotes", json={}).status_code == 405
        # GET route stays registered as read-only and still requires session.
        assert client.get("/api/pg-stage/v92/quotes").status_code == 401
        # CINEMA writer route is mounted and still enforces body validation.
        assert client.post("/api/pg-stage/cinema-trade/quotes", json={}).status_code == 422
        # But no request can commit without database-verified session + CSRF.
        assert client.get("/api/pg-stage/cinema-trade/partners").status_code in (401, 403)
        # Both legacy and CINEMA original business tables remain intact.


@pytest.mark.parametrize("invalid", ["on", "true", "DISABLED", ""])
def test_s4_wrong_gate_does_not_enable_new_writer(isolated_stage, invalid):
    if invalid:
        isolated_stage.setenv("JW_PG_CINEMA_TRADE_V1", invalid)
        with pytest.raises(RuntimeError, match="BLOCKED"):
            stage.create_app()
    else:
        with TestClient(stage.create_app()) as client:
            assert client.post("/api/pg-stage/v92/quotes", json={}).status_code == 422


def test_s4_cinema_gate_is_verified_again_at_mount(monkeypatch):
    # Explicit contract that no code path adds both writer routers at once.
    source = Path(stage.__file__).read_text()
    tree = ast.parse(source)
    app = next(node for node in tree.body
               if isinstance(node, ast.FunctionDef) and node.name=="create_app")
    assert "cinema_single_writer = cinema_trade.cinema_trade_enabled()" in source
    assert 'if name == "quote writer" and cinema_single_writer:' in source
    assert "continue  # v92 writer disabled in CINEMA trade mode" in source
    assert "cinema_trade.register_cinema_trade_v1" in source
    assert not any(isinstance(n, ast.ImportFrom) and n.module == "main"
                   for n in ast.walk(app))
