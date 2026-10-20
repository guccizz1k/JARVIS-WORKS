"""V4.7 historical gate chain, failure containment and module-cache regression."""
from __future__ import annotations
import sys
from types import ModuleType
import pytest
from scripts import run_postgres_isolation_ci_v47 as wrapper


def setup(monkeypatch,previous=0,current=0,crash=False):
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    monkeypatch.delenv('JW_ENV',raising=False)
    for n in range(35,48): monkeypatch.setenv(f'JW_PG_LAB_V{n}','ONLY_DISPOSABLE_LAB')
    import scripts
    previous_mod=ModuleType('scripts.test_postgres_cutover_readiness_v46')
    current_mod=ModuleType('scripts.test_postgres_lossless_projection_v47')
    supervisor=ModuleType('scripts.run_postgres_isolation_ci_v46')
    events=[]
    previous_mod.run=lambda: (events.append('v46') or previous)
    current_mod.run=lambda: (events.append('v47') or current)
    orig=previous_mod.run
    def main():
        events.append('supervisor')
        if crash:raise RuntimeError('injected')
        return previous_mod.run()
    supervisor.main=main
    for name,obj in [('test_postgres_cutover_readiness_v46',previous_mod),
                     ('test_postgres_lossless_projection_v47',current_mod),
                     ('run_postgres_isolation_ci_v46',supervisor)]:
        monkeypatch.setitem(sys.modules,'scripts.'+name,obj)
        monkeypatch.setattr(scripts,name,obj,raising=False)
    return events,previous_mod,orig


def test_prior_then_v47(monkeypatch):
    events,mod,orig=setup(monkeypatch)
    assert wrapper.main()==0
    assert events==['supervisor','v46','v47'] and mod.run is orig


@pytest.mark.parametrize('status',[1,2,3])
def test_historical_failure_stops_v47(monkeypatch,status):
    events,mod,orig=setup(monkeypatch,previous=status)
    assert wrapper.main()==status and events==['supervisor','v46']
    assert mod.run is orig


@pytest.mark.parametrize('status',[1,2,3])
def test_new_gate_failure_propagates(monkeypatch,status):
    events,mod,orig=setup(monkeypatch,current=status)
    assert wrapper.main()==status and events==['supervisor','v46','v47']
    assert mod.run is orig


def test_supervisor_exception_restores_cache(monkeypatch):
    events,mod,orig=setup(monkeypatch,crash=True)
    with pytest.raises(RuntimeError):wrapper.main()
    assert mod.run is orig


def test_environment_gates_are_fail_closed(monkeypatch):
    events,_,_=setup(monkeypatch)
    monkeypatch.setenv('JW_ENV','production')
    assert wrapper.main()==2 and events==[]
    monkeypatch.delenv('JW_ENV',raising=False)
    monkeypatch.delenv('JW_PG_LAB_V47')
    assert wrapper.main()==2 and events==[]


def test_no_history_edit_or_production_operation():
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]
    sh=(root/'scripts/check_v47_review.sh').read_text()
    assert 'bash scripts/check_v46_review.sh' in sh
    assert 'sha256sum --check --status V4_7_PG_GATE_SHA256.txt' in sh
    assert 'V4_6_PG_GATE_SHA256.txt' not in sh
