import pytest
from scripts.recovery_gate_v72 import run


def test_recovery_gate_local():
    result=run()
    assert result['local_result']=='PASS'
    assert len(result['tests'])==6
    assert result['production_recovery_certified'] is False
    assert result['restore_elapsed_seconds']>=0


def test_disallows_production_environment(monkeypatch):
    monkeypatch.setenv('JW_ENV','production')
    with pytest.raises(RuntimeError,match='production'):
        run()
