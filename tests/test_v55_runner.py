"""V5.5 wrapper security, ordered historical integration and failure contracts."""
import os
from pathlib import Path
import subprocess
import pytest

ROOT=Path(__file__).resolve().parents[1]


def test_source_check_first_and_previous_chain():
    data=(ROOT/'scripts/check_v55_review.sh').read_text()
    assert 'set -Eeuo pipefail' in data
    assert 'sha256sum --check --status V5_5_PG_GATE_SHA256.txt' in data
    assert 'bash scripts/check_v54_review.sh' in data
    assert data.index('sha256sum --check') < data.index('bash scripts/check_v54_review.sh')


def test_old_manifests_and_v54_before_pg():
    s=(ROOT/'scripts/run_pg17_codespaces_v55.sh').read_text()
    assert 'V5_3 V5_4 V5_5;' in s
    assert 'python3 -m scripts.test_mutation_snapshot_v54' in s
    assert s.index('scripts.test_mutation_snapshot_v54') < s.index('command -v docker')
    assert 'scripts.run_postgres_isolation_ci_v55' in s
    assert s.index('sha256sum --check') < s.index('scripts.run_postgres_isolation_ci_v55')
    assert 'BLOCKED' not in s or 'DENIED' in s


@pytest.mark.parametrize(('val','rc'),[(None,0),('',0),('dev',0),('production',2),('PRODUCTION',2),('PrOdUcTiOn',2)])
def test_env_guard_denies_production_and_allows_unset(val,rc):
    s=(ROOT/'scripts/run_pg17_codespaces_v55.sh').read_text()
    guard=s[s.index('JW_ENV_SAFE='):s.index('for version in 35')]
    env=os.environ.copy();env.pop('JW_ENV',None)
    if val is not None:env['JW_ENV']=val
    out=subprocess.run(['bash','-c','set -Eeuo pipefail\n'+guard+'\nprintf "REACHED\\n"'],
                       capture_output=True,text=True,env=env,timeout=6)
    assert out.returncode==rc
    assert ('REACHED' in out.stdout)==(rc==0)


def test_no_external_deployment_or_production_secret_exposure():
    scripts='\n'.join((ROOT/p).read_text() for p in [
        'scripts/run_pg17_codespaces_v55.sh', 'scripts/check_v55_review.sh'])
    for keyword in ('git push','kubectl apply','vercel deploy','eas build','--privileged','0.0.0.0::5432'):
        assert keyword not in scripts
    assert '127.0.0.1' in scripts and 'cutover DENIED' in scripts


def test_isolated_supervisor_restores_callback(monkeypatch):
    from scripts import run_postgres_isolation_ci_v55 as wrapper
    from scripts import run_postgres_isolation_ci_v53 as previous
    from scripts import test_postgres_evidence_digest_v53 as historical
    from scripts import test_postgres_message_payload_v55 as payload
    for key in ('JW_PG_LAB_V53','JW_PG_LAB_V54','JW_PG_LAB_V55'):
        monkeypatch.setenv(key,'ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    monkeypatch.delenv('JW_ENV',raising=False)
    original=historical.run
    events=[]
    monkeypatch.setattr(historical,'run',lambda:events.append('old') or 0)
    monkeypatch.setattr(payload,'run',lambda:events.append('new') or 0)
    monkeypatch.setattr(previous,'main',lambda:historical.run())
    assert wrapper.main()==0 and events==['old','new']
    assert historical.run is not original  # monkeypatch's fake restored by wrapper
    events.clear()
    monkeypatch.setattr(historical,'run',lambda:events.append('old_fail') or 1)
    assert wrapper.main()==1 and events==['old_fail']


def test_missing_authorization_blocks_before_previous(monkeypatch):
    from scripts import run_postgres_isolation_ci_v55 as wrapper
    monkeypatch.setenv('JW_ENV','production')
    assert wrapper.main()==2
