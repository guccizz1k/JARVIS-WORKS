"""Proof that hosted probe remains opt-in and never writes business rows."""
import asyncio
import inspect
from pathlib import Path

from scripts import jw_v140_safe_live_https_probe as probe


def test_live_https_probe_disabled_by_default(monkeypatch):
    monkeypatch.delenv("JW_STAGE1_SAFE_HTTPS_PROBE", raising=False)
    assert asyncio.run(probe.verify()) == "NOT_RUN_NOT_APPROVED"
    assert probe.schedule() is None


def test_live_https_probe_denies_non_dev_and_weak_key(monkeypatch):
    monkeypatch.setenv("JW_STAGE1_SAFE_HTTPS_PROBE", probe._ACK)
    monkeypatch.setenv("JW_STAGE1_PUBLIC_ACK", "V134_STAGE1_PUBLIC_ISOLATED_ONLY")
    monkeypatch.setenv("JW_ENV", "production")
    monkeypatch.setenv("JW_STAGE1_ACCESS_KEY", "x" * 60)
    assert asyncio.run(probe.verify()) == "NOT_RUN_NOT_APPROVED"
    monkeypatch.setenv("JW_ENV", "dev")
    monkeypatch.setenv("JW_STAGE1_ACCESS_KEY", "short")
    assert asyncio.run(probe.verify()) == "BLOCKED_STAGE_KEY"


def test_probe_source_is_readonly_and_denies_unauthed_access():
    source = inspect.getsource(probe)
    assert "await c.get(" in source
    assert "await c.post(" not in source
    assert "await c.delete(" not in source
    assert "await c.put(" not in source
    assert "X-JW-Stage-Key" in source
    assert "__Host-jw_session" in source
    assert "PASS_HOSTED_HTTPS_STAGE_GATE_NO_SESSION_FORGED_SESSION" in source
    assert "PASS_HOSTED_HTTPS_A_B_C" not in source


def test_compatible_fastapi_startup_hook(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from scripts import jw_v134_protected_stage as stage
    from scripts import jw_v104_standalone as core
    from scripts import jw_v135_stage_connection_probe as db_probe
    from scripts import jw_v138_supabase_ca

    monkeypatch.setenv("JW_ENV", "dev")
    monkeypatch.setenv("JW_STAGE1_PUBLIC_ACK", "V134_STAGE1_PUBLIC_ISOLATED_ONLY")
    monkeypatch.setenv("JW_STAGE1_ACCESS_KEY", "synthetic-stage-test-access-key-abcdefghijklmnopqrstuvwxyz")
    monkeypatch.setenv("JW_STAGE1_SAFE_HTTPS_PROBE", probe._ACK)
    monkeypatch.setattr(jw_v138_supabase_ca, "install", lambda: "/synthetic/ca")
    monkeypatch.setattr(core, "preflight", lambda: True)
    monkeypatch.setattr(db_probe, "verify", lambda: (True, "ROLE_SCOPED_TEST"))
    observed = []

    def fake_product_app():
        app = FastAPI(docs_url=None)
        @app.get("/healthz")
        def health():
            return {"mode": "isolated_pg_api_only", "release": "BLOCKED"}
        return app
    monkeypatch.setattr(core, "create_app", fake_product_app)
    monkeypatch.setattr(probe, "schedule", lambda: observed.append("startup"))
    wrapped = stage.create_app()
    with TestClient(wrapped) as client:
        result = client.get("/healthz")
        assert result.status_code == 200
        assert result.json()["mode"] == "isolated_pg_api_only"
        assert client.get("/api/pg-stage/v84/customers").status_code == 403
    assert observed == ["startup"]
