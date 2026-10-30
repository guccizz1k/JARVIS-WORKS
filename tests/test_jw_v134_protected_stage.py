"""V13.4 fail-closed public staging tests, including HTTP AND WS ingress."""
import asyncio
import os
import pytest
from fastapi.testclient import TestClient
from scripts import jw_v134_protected_stage as protected
from scripts import jw_v104_standalone as core

def test_no_enable_by_default(monkeypatch):
    monkeypatch.delenv("JW_STAGE1_PUBLIC_ACK",raising=False)
    with pytest.raises(RuntimeError,match="non-production"):
        protected.create_app()

def test_weak_stage_key_denied(monkeypatch):
    monkeypatch.setenv("JW_ENV","dev")
    monkeypatch.setenv("JW_STAGE1_PUBLIC_ACK",protected._ACK)
    monkeypatch.setenv("JW_STAGE1_ACCESS_KEY","short")
    with TestClient(protected.create_app()) as client:
        check=client.get("/healthz")
        assert check.status_code==200 and check.json()["stage1"]=="FAIL"
        assert check.json()["mode"]=="sealed-awaiting-stage-key"
        assert client.get("/api/pg-stage/v90/me").status_code==403
        assert client.get("/api/pg-stage/v90/me", headers={
            "X-JW-Stage-Key":"x"*80}).status_code==403

def test_sealed_no_db_and_all_routes_denied(monkeypatch):
    monkeypatch.setenv("JW_ENV","dev")
    monkeypatch.setenv("JW_STAGE1_PUBLIC_ACK",protected._ACK)
    monkeypatch.setenv("JW_STAGE1_ACCESS_KEY","isolated-stage-only-secret-abcdefghijklmnopqrstuvwxyz123456")
    monkeypatch.delenv("JW_PG_STAGE_DSN",raising=False)
    wrapper=protected.create_app()
    with TestClient(wrapper) as cli:
        health=cli.get("/healthz")
        assert health.status_code==200 and health.json()["stage1"]=="FAIL"
        assert cli.get("/api/pg-stage/v90/me").status_code==403
        assert cli.get("/api/pg-stage/v90/me",headers={"X-JW-Stage-Key":"wrong"}).status_code==403
        assert cli.get("/api/pg-stage/v90/me",headers={"X-JW-Stage-Key":"isolated-stage-only-secret-abcdefghijklmnopqrstuvwxyz123456"}).status_code==404

def test_pooler_review_only_principals(monkeypatch):
    monkeypatch.setenv("JW_STAGE1_SUPAVISOR_ACK","V134_REVIEW_POOLER_ONLY")
    monkeypatch.setenv("JW_STAGE_EXPECTED_DB_HOST","aws-0-ap-northeast-2.pooler.supabase.com")
    monkeypatch.setenv("JW_STAGE_EXPECTED_DB_NAME","postgres")
    a="aws-0-ap-northeast-2.pooler.supabase.com"
    base="rvymwwzclagvljnofyss"
    dsn=f"postgresql://jw_stage1_trade_20261030.{base}:synthetic-review-password-no-secret@{a}:5432/postgres?sslmode=verify-full&sslrootcert=system"
    assert core._safe_dsn(dsn,"jw_trade_gateway_v90")
    assert not core._safe_dsn(dsn,"jw_auth_gateway_v90")
    assert not core._safe_dsn(dsn.replace("verify-full","require"),"jw_trade_gateway_v90")
    assert not core._safe_dsn(dsn.replace("sslrootcert=system","sslrootcert=/tmp/missing"),"jw_trade_gateway_v90")
    assert not core._safe_dsn(dsn.replace("jw_stage1_trade_20261030","postgres"),"jw_trade_gateway_v90")
    assert not core._safe_dsn(dsn.replace(base,"other-project-tenant"),"jw_trade_gateway_v90")

def test_no_production_stage(monkeypatch):
    monkeypatch.setenv("JW_ENV","production")
    monkeypatch.setenv("JW_STAGE1_PUBLIC_ACK",protected._ACK)
    monkeypatch.setenv("JW_STAGE1_ACCESS_KEY","isolated-stage-only-secret-abcdefghijklmnopqrstuvwxyz123456")
    with pytest.raises(RuntimeError,match="non-production"):
        protected.create_app()

def test_websocket_access_key_outer_gate(monkeypatch):
    monkeypatch.setenv("JW_ENV","dev")
    monkeypatch.setenv("JW_STAGE1_PUBLIC_ACK",protected._ACK)
    monkeypatch.setenv("JW_STAGE1_ACCESS_KEY","isolated-stage-only-secret-abcdefghijklmnopqrstuvwxyz123456")
    monkeypatch.delenv("JW_PG_STAGE_DSN",raising=False)
    wrapper=protected.create_app()
    with TestClient(wrapper) as cli:
        with pytest.raises(Exception):
            with cli.websocket_connect("/api/pg-stage/v90/stream"): pass
