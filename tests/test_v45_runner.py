"""V4.5 chained runner must not convert failures into PASS."""
from types import ModuleType
import sys
from pathlib import Path
import pytest
from scripts import run_postgres_isolation_ci_v45 as wrapper


def fake_chain(monkeypatch,prev=0,next_rc=0,supervisor_raise=False):
    monkeypatch.delenv('JW_ENV',raising=False)
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    for k in range(35,46):monkeypatch.setenv('JW_PG_LAB_V'+str(k),'ONLY_DISPOSABLE_LAB')
    history=[]
    old=ModuleType('scripts.test_postgres_cookie_shadow_v44')
    nxt=ModuleType('scripts.test_postgres_evidence_shadow_v45')
    supervisor=ModuleType('scripts.run_postgres_isolation_ci_v44')
    old.run=lambda: (history.append('v44') or prev)
    nxt.run=lambda: (history.append('v45') or next_rc)
    def supervise():
        history.append('supervisor')
        if supervisor_raise:raise RuntimeError('injected')
        return old.run()
    supervisor.main=supervise
    import scripts
    original=old.run
    for name,obj in (('test_postgres_cookie_shadow_v44',old),
                     ('test_postgres_evidence_shadow_v45',nxt),
                     ('run_postgres_isolation_ci_v44',supervisor)):
        monkeypatch.setitem(sys.modules,'scripts.'+name,obj)
        monkeypatch.setattr(scripts,name,obj,raising=False)
    return history,old,original


def test_full_success(monkeypatch):
    events,prior,orig=fake_chain(monkeypatch)
    assert wrapper.main()==0
    assert events==['supervisor','v44','v45'] and prior.run is orig


@pytest.mark.parametrize('status',[1,2,3])
def test_previous_fail_not_run_nonzero_stops_v45(monkeypatch,status):
    events,prior,orig=fake_chain(monkeypatch,prev=status)
    assert wrapper.main()==status and events==['supervisor','v44'] and prior.run is orig


@pytest.mark.parametrize('status',[1,2,3])
def test_new_fail_not_run_not_pass(monkeypatch,status):
    events,prior,orig=fake_chain(monkeypatch,next_rc=status)
    assert wrapper.main()==status and events==['supervisor','v44','v45'] and prior.run is orig


def test_callback_restored_on_crash(monkeypatch):
    events,prior,orig=fake_chain(monkeypatch,supervisor_raise=True)
    with pytest.raises(RuntimeError):wrapper.main()
    assert prior.run is orig


def test_production_refused_even_when_flags_present(monkeypatch):
    fake_chain(monkeypatch)
    monkeypatch.setenv('JW_ENV','production')
    assert wrapper.main()==2


def test_missing_v45_flag_refused(monkeypatch):
    fake_chain(monkeypatch)
    monkeypatch.delenv('JW_PG_LAB_V45')
    assert wrapper.main()==2


def test_historical_chain_and_test_cluster_protected():
    root=Path(__file__).resolve().parents[1]
    shell=(root/'scripts/run_pg17_codespaces_v45.sh').read_text()
    check=(root/'scripts/check_v45_review.sh').read_text()
    assert 'V4_4 V4_5' in shell and 'V2_8' in shell
    assert '127.0.0.1::5432' in shell and 'docker rm -f' in shell
    assert 'scripts.run_postgres_isolation_ci_v45' in shell
    assert 'bash scripts/check_v44_review.sh' in check
    assert 'sha256sum --check --status V4_5_PG_GATE_SHA256.txt' in check
    assert 'git push' not in check and 'git push' not in shell
    assert 'app/main.py' not in check and 'pg_restore' not in check


def test_no_live_pg_or_customer_data_paths():
    root=Path(__file__).resolve().parents[1]
    runner=(root/'scripts/test_postgres_evidence_shadow_v45.py').read_text()
    app=(root/'app/pg_evidence_shadow_v45.py').read_text()
    assert "prefix='jw-v45-synthetic-'" in runner
    assert 'jw_v20_test_' in runner
    assert "'cutover_approved':False" in app
    assert '@lab.get(' in app and '@lab.post(' not in app
