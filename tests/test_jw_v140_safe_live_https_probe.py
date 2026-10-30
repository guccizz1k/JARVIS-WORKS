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
