"""V5.0 full prior gate fail-closed and module cache isolation."""
import sys
from types import ModuleType
from pathlib import Path
import pytest
from scripts import run_postgres_isolation_ci_v50 as wrapper


def env(monkeypatch, old=0, new=0, crash=False):
    monkeypatch.delenv('JW_ENV',raising=False)
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    for n in range(35,49):monkeypatch.setenv(f'JW_PG_LAB_V{n}','ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_LAB_V50','ONLY_DISPOSABLE_LAB')
    import scripts
    previous=ModuleType('scripts.test_postgres_semantic_envelopes_v48')
    current=ModuleType('scripts.test_postgres_identity_audit_v50')
    supervisor=ModuleType('scripts.run_postgres_isolation_ci_v48')
    events=[]
    previous.run=lambda: (events.append('v48') or old)
    current.run=lambda: (events.append('v50') or new)
    orig=previous.run
    def do():
        events.append('supervisor')
        if crash: raise RuntimeError('synthetic failure')
        return previous.run()
    supervisor.main=do
    for name, value in [('test_postgres_semantic_envelopes_v48',previous),
                        ('test_postgres_identity_audit_v50',current),
                        ('run_postgres_isolation_ci_v48',supervisor)]:
        monkeypatch.setitem(sys.modules,'scripts.'+name,value)
        monkeypatch.setattr(scripts,name,value,raising=False)
    return events, previous, orig


def test_historical_chain_then_new_gate(monkeypatch):
    events,mod,original=env(monkeypatch)
    assert wrapper.main()==0 and events==['supervisor','v48','v50']
    assert mod.run is original

@pytest.mark.parametrize('rc',[1,2,3])
def test_previous_failure_blocks_new(monkeypatch,rc):
    events,mod,original=env(monkeypatch,old=rc)
    assert wrapper.main()==rc and events==['supervisor','v48']
    assert mod.run is original

@pytest.mark.parametrize('rc',[1,2,3])
def test_current_failure_is_not_pass(monkeypatch,rc):
    events,mod,original=env(monkeypatch,new=rc)
    assert wrapper.main()==rc and events==['supervisor','v48','v50']
    assert mod.run is original


def test_supervisor_exception_restores_callback(monkeypatch):
    events,mod,original=env(monkeypatch,crash=True)
    with pytest.raises(RuntimeError):wrapper.main()
    assert mod.run is original

@pytest.mark.parametrize('var,value',[
    ('JW_ENV','production'),('JW_PG_CI_ALLOW','missing'),
    ('JW_PG_LAB_V50','missing'),('JW_PG_LAB_V48','missing')])
def test_guard_blocks_before_any_prior_gate(monkeypatch,var,value):
    events,_,_=env(monkeypatch)
    monkeypatch.setenv(var,value)
    assert wrapper.main()==2 and events==[]


def test_shell_chain_keeps_historical_integrity_and_short_cli():
    root=Path(__file__).resolve().parents[1]
    check=(root/'scripts/check_v50_review.sh').read_text()
    runner=(root/'scripts/run_pg17_codespaces_v50.sh').read_text()
    assert 'V4_9_PG_GATE_SHA256.txt' in check
    assert 'bash scripts/check_v49_review.sh' in check
    assert 'V4_9 V5_0;' in runner
    assert 'scripts.run_postgres_isolation_ci_v50' in runner
    assert 'JW_PG_LAB_V50' in runner
    assert 'docker rm -f' in runner and 'rm -rf -- "$WORK"' in runner


def test_adapter_must_get_validated_ephemeral_uri_not_libpq_dsn():
    source=(Path(__file__).resolve().parents[1]/'scripts/test_postgres_identity_audit_v50.py').read_text()
    assert 'lab_uri=_verified_lab_uri(' in source
    assert 'MessengerReviewAdapter(lab_uri)' in source
    assert 'MessengerReviewAdapter(app_dsn)' not in source
