"""Presence is metadata, not proof of usable credentials or authentication."""
import json
import pytest
from scripts import ci_v97_secret_status as s


@pytest.mark.parametrize("trade,auth", [("false", "false"), ("true", "false"),
                                      ("false", "true"), ("", "true")])
def test_missing_either_secret_blocks_live_step(trade, auth, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "step-output"))
    monkeypatch.setenv("JW_V97_TRADE_DSN_SET", trade)
    monkeypatch.setenv("JW_V97_AUTH_DSN_SET", auth)
    assert s.main() == 0
    assert (tmp_path / "step-output").read_text() == "ready=false\n"
    verdict = json.loads((tmp_path / "jw-v97-verdict.json").read_text())
    assert verdict["decision"] == "BLOCKED" and verdict["live_attempted"] is False


def test_set_names_do_not_claim_authentication_or_read_secret_values():
    metadata = {name + "_SET": "true" for name in s.SECRET_NAMES}
    class NamesOnly(dict):
        def get(self, key, default=None):
            assert key.endswith("_SET"), "secret value unexpectedly accessed"
            return super().get(key, default)
    result = s.status(NamesOnly(metadata))
    assert result["ready"] and result["values_inspected"] is False
    assert result["secret_status"] == {name: "SET" for name in s.SECRET_NAMES}
    assert "authenticated" not in result
