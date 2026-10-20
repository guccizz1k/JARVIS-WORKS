"""V4.4 harness invariants; legacy callbacks and manifests remain untouched."""
from pathlib import Path
from types import ModuleType
import sys

import pytest

from scripts import run_postgres_isolation_ci_v44 as wrapper


def _setup(monkeypatch, outcome=0, new_outcome=0):
    monkeypatch.delenv('JW_ENV', raising=False)
    monkeypatch.setenv('JW_PG_CI_ALLOW', 'ONLY_EPHEMERAL_LOCAL_DATABASE')
    monkeypatch.setenv('JW_PG_LAB_V44', 'ONLY_DISPOSABLE_LAB')
    history=[]
    old=ModuleType('scripts.test_postgres_web_v43')
    nxt=ModuleType('scripts.test_postgres_cookie_shadow_v44')
    supervisor=ModuleType('scripts.run_postgres_isolation_ci_v43')
    old.run=lambda: (history.append('v43') or outcome)
    nxt.run=lambda: (history.append('v44') or new_outcome)
    supervisor.main=lambda: (history.append('supervisor') or old.run())
    saved=old.run
    for path, module in [('scripts.test_postgres_web_v43',old),
                         ('scripts.test_postgres_cookie_shadow_v44',nxt),
                         ('scripts.run_postgres_isolation_ci_v43',supervisor)]:
        monkeypatch.setitem(sys.modules,path,module)
    return history,old,saved


def test_chained_baseline_and_new_gate(monkeypatch):
    events,module,callback=_setup(monkeypatch)
    assert wrapper.main()==0
    assert events==['supervisor','v43','v44']
    assert module.run is callback


def test_failed_prior_gate_blocks_new_gate(monkeypatch):
    events,module,callback=_setup(monkeypatch,outcome=1)
    assert wrapper.main()==1
    assert events==['supervisor','v43']
    assert module.run is callback


def test_new_failure_blocks_pass(monkeypatch):
    events,module,callback=_setup(monkeypatch,new_outcome=1)
    assert wrapper.main()==1
    assert module.run is callback


def test_disallowed_production_is_not_run(monkeypatch):
    monkeypatch.setenv('JW_ENV','production')
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    monkeypatch.setenv('JW_PG_LAB_V44','ONLY_DISPOSABLE_LAB')
    assert wrapper.main()==2


def test_immutable_previous_harness_and_isolated_docker():
    runner=Path('scripts/run_pg17_codespaces_v44.sh').read_text()
    check=Path('scripts/check_v44_review.sh').read_text()
    assert 'V4_3' in runner and 'V4_4' in runner
    assert 'scripts.run_postgres_isolation_ci_v44' in runner
    assert '127.0.0.1::5432' in runner
    assert 'docker rm -f' in runner
    assert 'JW_PG_LAB_V44=ONLY_DISPOSABLE_LAB' not in check
    assert 'bash scripts/check_v43_review.sh' in check
    assert 'git push' not in runner and 'git push' not in check
    assert 'app/main.py' not in check


def test_no_write_routes_or_production_database_support():
    app_src=Path('app/pg_cookie_shadow_v44.py').read_text()
    assert '@review.get(' in app_src
    assert '@review.post(' not in app_src
    assert 'JW_ENV' in app_src and 'production' in app_src
    assert "'cutover_approved': False" in app_src
    assert 'verified_transaction(binding.pg_token, readonly=True)' in app_src
    assert 'JW_PG_LAB_V44' in app_src
