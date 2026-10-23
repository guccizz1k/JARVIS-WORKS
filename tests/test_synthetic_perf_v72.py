import pytest
from scripts.synthetic_perf_v72 import run


def test_concurrent_gets_and_metrics():
    r=run(workers=4,repeats=2)
    assert r['successes']==8 and r['requests']==8
    assert r['local_result']=='PASS' and not r['production_sla_measured']
    assert 0<=r['p50_ms']<=r['p95_ms']<=r['max_ms']


def test_refuses_unsafe_settings(monkeypatch):
    monkeypatch.setenv('JW_ENV','production')
    with pytest.raises(RuntimeError):run()
    monkeypatch.setenv('JW_ENV','development')
    with pytest.raises(ValueError):run(workers=200)
