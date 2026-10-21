"""Fail-closed historical supervisor chain and export safety."""
from __future__ import annotations
import sys
from pathlib import Path
from types import ModuleType
import pytest
from scripts import run_postgres_isolation_ci_v48 as v48


def arrange(monkeypatch,previous=0,latest=0,crash=False):
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    monkeypatch.delenv('JW_ENV',raising=False)
    for version in range(35,49):monkeypatch.setenv(f'JW_PG_LAB_V{version}','ONLY_DISPOSABLE_LAB')
    import scripts
    prior=ModuleType('scripts.test_postgres_lossless_projection_v47')
    current=ModuleType('scripts.test_postgres_semantic_envelopes_v48')
    supervisor=ModuleType('scripts.run_postgres_isolation_ci_v47')
    events=[]
    prior.run=lambda:(events.append('v47') or previous)
    current.run=lambda:(events.append('v48') or latest)
    orig=prior.run
    def main():
        events.append('supervisor')
        if crash:raise RuntimeError('fixture')
        return prior.run()
    supervisor.main=main
    for name,mod in [('test_postgres_lossless_projection_v47',prior),
                     ('test_postgres_semantic_envelopes_v48',current),
                     ('run_postgres_isolation_ci_v47',supervisor)]:
        monkeypatch.setitem(sys.modules,'scripts.'+name,mod)
        monkeypatch.setattr(scripts,name,mod,raising=False)
    return events,prior,orig


def test_previous_pass_then_v48(monkeypatch):
    events,mod,orig=arrange(monkeypatch)
    assert v48.main()==0
    assert events==['supervisor','v47','v48'] and mod.run is orig


@pytest.mark.parametrize('code',[1,2,3])
def test_prior_failure_stops_new_gate(monkeypatch,code):
    events,mod,orig=arrange(monkeypatch,previous=code)
    assert v48.main()==code and events==['supervisor','v47']
    assert mod.run is orig


@pytest.mark.parametrize('code',[1,2,3])
def test_new_failure_cannot_be_pass(monkeypatch,code):
    events,mod,orig=arrange(monkeypatch,latest=code)
    assert v48.main()==code and events==['supervisor','v47','v48']
    assert mod.run is orig


def test_exception_restores_previous(monkeypatch):
    events,mod,orig=arrange(monkeypatch,crash=True)
    with pytest.raises(RuntimeError):v48.main()
    assert mod.run is orig


def test_live_env_refused(monkeypatch):
    events,mod,orig=arrange(monkeypatch)
    monkeypatch.setenv('JW_ENV','production')
    assert v48.main()==2 and events==[]
    monkeypatch.delenv('JW_ENV',raising=False)
    monkeypatch.delenv('JW_PG_LAB_V48')
    assert v48.main()==2 and events==[]


def test_prior_manifests_and_zero_skip_chain_are_preserved():
    root=Path(__file__).resolve().parents[1]
    runner=(root/'scripts/run_pg17_codespaces_v48.sh').read_text()
    checker=(root/'scripts/check_v48_review.sh').read_text()
    assert 'V4_6 V4_7 V4_8;' in runner
    assert 'bash scripts/check_v47_review.sh' in checker
    assert 'scripts.run_postgres_isolation_ci_v48' in runner
    assert 'JW_ENV' in runner and 'production' in runner
    assert 'sha256sum --check --status' in runner and 'sha256sum --check --status' in checker
    assert 'docker rm -f' in runner and 'rm -rf -- "$WORK"' in runner
