from pathlib import Path
import os
from types import SimpleNamespace
import pytest


def test_pg_supervisor_denies_missing_gate(monkeypatch):
    from scripts.run_postgres_isolation_ci_v53 import main
    monkeypatch.delenv('JW_PG_LAB_V53',raising=False)
    assert main()==2


def test_previous_failure_blocks_v53(monkeypatch):
    from scripts.run_postgres_isolation_ci_v53 import main
    from scripts import run_postgres_isolation_ci_v52 as prev_supervisor
    from scripts import test_postgres_outbox_relay_v52 as old
    from scripts import test_postgres_evidence_digest_v53 as new
    for k,v in [('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE'),
                ('JW_PG_LAB_V53','ONLY_DISPOSABLE_LAB'),
                ('JW_PG_LAB_V52','ONLY_DISPOSABLE_LAB')]:
        monkeypatch.setenv(k,v)
    monkeypatch.delenv('JW_ENV',raising=False)
    calls=[]
    def old_run():calls.append('old');return 1
    def new_run():calls.append('new');return 0
    monkeypatch.setattr(old,'run',old_run)
    monkeypatch.setattr(new,'run',new_run)
    monkeypatch.setattr(prev_supervisor,'main',lambda: old.run())
    assert main()==1
    assert calls==['old']
    assert old.run is old_run


def test_new_failure_propagates(monkeypatch):
    from scripts.run_postgres_isolation_ci_v53 import main
    from scripts import run_postgres_isolation_ci_v52 as prev_supervisor
    from scripts import test_postgres_outbox_relay_v52 as old
    from scripts import test_postgres_evidence_digest_v53 as new
    for k in ['JW_PG_CI_ALLOW','JW_PG_LAB_V52','JW_PG_LAB_V53']:
        monkeypatch.setenv(k,'ONLY_EPHEMERAL_LOCAL_DATABASE' if k=='JW_PG_CI_ALLOW' else 'ONLY_DISPOSABLE_LAB')
    monkeypatch.delenv('JW_ENV',raising=False)
    monkeypatch.setattr(old,'run',lambda:0)
    monkeypatch.setattr(new,'run',lambda:1)
    monkeypatch.setattr(prev_supervisor,'main',lambda:old.run())
    assert main()==1


def test_pg_shell_preserves_historical_gates():
    shell=(Path(__file__).parents[1]/'scripts'/'run_pg17_codespaces_v53.sh').read_text()
    assert 'V5_1 V5_2 V5_3;' in shell
    assert 'V5_3_PG_GATE_SHA256.txt' not in shell or 'manifest=' in shell
    assert 'JW_ENV_SAFE="${JW_ENV:-}"' in shell
    assert 'scripts.run_postgres_isolation_ci_v53' in shell
    assert '127.0.0.1::5432 postgres:17' in shell
    assert 'V5.3' in shell


def test_no_operational_paths_in_pg_test():
    s=(Path(__file__).parents[1]/'scripts'/'test_postgres_evidence_digest_v53.py').read_text()
    assert 'JW_PG_TEST_ADMIN_DSN' in s and 'JW_PG_TEST_APP_DSN' in s
    assert '_verified_lab_uri' in s
    assert 'CREATE SCHEMA jw_relay_v53' in s
    assert 'FORCE ROW LEVEL SECURITY' in s
