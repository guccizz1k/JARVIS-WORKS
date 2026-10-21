"""V5.6 gate order, subprocess environment, and regression-chain contracts."""
import os
from pathlib import Path
import subprocess
import pytest

ROOT=Path(__file__).resolve().parents[1]


def test_source_integrity_before_prior_regression():
    s=(ROOT/'scripts/check_v56_review.sh').read_text()
    assert 'sha256sum --check --status V5_6_PG_GATE_SHA256.txt' in s
    assert 'bash scripts/check_v55_review.sh' in s
    assert s.index('sha256sum --check') < s.index('bash scripts/check_v55_review.sh')


def test_old_manifests_and_v54_prerequisite_first():
    s=(ROOT/'scripts/run_pg17_codespaces_v56.sh').read_text()
    assert 'V5_4 V5_5 V5_6;' in s
    assert 'JW_PG_LAB_V56' in s
    assert 'scripts.run_postgres_isolation_ci_v56' in s
    assert s.index('scripts.test_mutation_snapshot_v54') < s.index('command -v docker')
    assert s.index('sha256sum --check') < s.index('scripts.run_postgres_isolation_ci_v56')
    assert '127.0.0.1' in s and 'cutover DENIED' in s


@pytest.mark.parametrize(('v','code'),[(None,0),('',0),('development',0),('production',2),('PRODUCTION',2),('PrOdUcTiOn',2)])
def test_environment_production_denied(v,code):
    s=(ROOT/'scripts/run_pg17_codespaces_v56.sh').read_text()
    start=s.index('JW_ENV_SAFE=')
    end=s.index('for version in 35',start)
    env=os.environ.copy();env.pop('JW_ENV',None)
    if v is not None:env['JW_ENV']=v
    p=subprocess.run(['bash','-c','set -Eeuo pipefail\n'+s[start:end]+'\nprintf "REACHED\\n"'],
                     cwd=ROOT,capture_output=True,text=True,timeout=5,env=env)
    assert p.returncode==code
    assert ('REACHED' in p.stdout)==(code==0)


def test_source_temp_authorization_does_not_leak_to_shell():
    s=(ROOT/'scripts/run_pg17_codespaces_v56.sh').read_text()
    assert 'JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE ' + chr(92) + '\n' + 'python3 -m scripts.test_mutation_snapshot_v54' in s
    assert 'export JW_PG_CI_ALLOW=' not in s
    test=s[s.index('JW_ENV_SAFE='):s.index('CONTAINER=""')]
    env=os.environ.copy();env.pop('JW_ENV',None);env.pop('JW_PG_CI_ALLOW',None)
    p=subprocess.run(['bash','-c','set -Eeuo pipefail\n'+test],cwd=ROOT,
                     capture_output=True,text=True,timeout=25,env=env)
    assert p.returncode==0, p.stderr+p.stdout
    assert 'PASS: V5.4 SQLite mutation-time' in p.stdout


def test_previous_pg_gate_runs_before_edit_proof(monkeypatch):
    from scripts import run_postgres_isolation_ci_v56 as new
    from scripts import run_postgres_isolation_ci_v55 as prior
    from scripts import test_postgres_message_payload_v55 as oldtest
    from scripts import test_postgres_edit_history_v56 as live
    for ver in (53,54,55,56):
        monkeypatch.setenv(f'JW_PG_LAB_V{ver}','ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    monkeypatch.delenv('JW_ENV',raising=False)
    events=[]
    monkeypatch.setattr(oldtest,'run',lambda:events.append('previous') or 0)
    monkeypatch.setattr(live,'run',lambda:events.append('added') or 0)
    monkeypatch.setattr(prior,'main',lambda:oldtest.run())
    assert new.main()==0 and events==['previous','added']
    events.clear()
    monkeypatch.setattr(oldtest,'run',lambda:events.append('previous_failed') or 1)
    assert new.main()==1 and events==['previous_failed']


def test_missing_authorization_blocks(monkeypatch):
    from scripts import run_postgres_isolation_ci_v56 as new
    monkeypatch.setenv('JW_ENV','Production')
    assert new.main()==2
