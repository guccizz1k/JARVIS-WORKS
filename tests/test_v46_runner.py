"""V4.6 supervisor chaining must preserve the complete prior gate."""
import sys
from types import ModuleType
import pytest
from scripts import run_postgres_isolation_ci_v46 as v46


def setup(monkeypatch,old_status=0,new_status=0,crash=False):
    monkeypatch.delenv('JW_ENV',raising=False)
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    for n in range(35,47):monkeypatch.setenv('JW_PG_LAB_V'+str(n),'ONLY_DISPOSABLE_LAB')
    events=[]
    old=ModuleType('scripts.test_postgres_evidence_shadow_v45')
    nxt=ModuleType('scripts.test_postgres_cutover_readiness_v46')
    supervisor=ModuleType('scripts.run_postgres_isolation_ci_v45')
    def prior():events.append('v45');return old_status
    def current():events.append('v46');return new_status
    old.run=prior;nxt.run=current
    def main():
        events.append('supervisor')
        if crash:raise RuntimeError('Synthetic exception')
        return old.run()
    supervisor.main=main
    import scripts
    for name,obj in (
        ('test_postgres_evidence_shadow_v45',old),
        ('test_postgres_cutover_readiness_v46',nxt),
        ('run_postgres_isolation_ci_v45',supervisor)):
        monkeypatch.setitem(sys.modules,'scripts.'+name,obj)
        monkeypatch.setattr(scripts,name,obj,raising=False)
    return events,old,prior


def test_full_chain_success(monkeypatch):
    events,mod,original=setup(monkeypatch)
    assert v46.main()==0
    assert events==['supervisor','v45','v46']
    assert mod.run is original

@pytest.mark.parametrize('bad',[1,2,3])
def test_prior_failure_prevents_v46(monkeypatch,bad):
    events,mod,original=setup(monkeypatch,old_status=bad)
    assert v46.main()==bad
    assert events==['supervisor','v45'] and mod.run is original

@pytest.mark.parametrize('bad',[1,2,3])
def test_v46_failure_prevents_success(monkeypatch,bad):
    events,mod,original=setup(monkeypatch,new_status=bad)
    assert v46.main()==bad
    assert events==['supervisor','v45','v46'] and mod.run is original


def test_exception_restores_prior_runner(monkeypatch):
    events,mod,original=setup(monkeypatch,crash=True)
    with pytest.raises(RuntimeError):v46.main()
    assert mod.run is original


def test_production_environment_refused(monkeypatch):
    events,_,_=setup(monkeypatch)
    monkeypatch.setenv('JW_ENV','production')
    assert v46.main()==2 and events==[]


def test_missing_required_lab_flag_refused(monkeypatch):
    events,_,_=setup(monkeypatch)
    monkeypatch.delenv('JW_PG_LAB_V46')
    assert v46.main()==2 and events==[]
