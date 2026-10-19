"""Safety constraints on the isolated SQLite-only benchmark."""
import pytest
from scripts.benchmark_messenger_sqlite_v28 import run


def test_benchmark_denies_production_environment(monkeypatch):
    monkeypatch.setenv('JW_ENV','PRODUCTION')
    with pytest.raises(RuntimeError, match='production'):
        run(writers=1,total=1)


def test_benchmark_refuses_unbounded_workload(monkeypatch):
    monkeypatch.delenv('JW_ENV',raising=False)
    with pytest.raises(ValueError, match='workload'):
        run(writers=17,total=5000)
    with pytest.raises(ValueError, match='workload'):
        run(writers=1,total=2001)
