"""V5.7 CLI precondition, shell fail closed and historic PG17 order."""
import os
from pathlib import Path
import subprocess
import pytest

ROOT=Path(__file__).resolve().parents[1]

def test_historical_chain_and_sha256():
    sh=(ROOT/'scripts/run_pg17_codespaces_v57.sh').read_text()
    check=(ROOT/'scripts/check_v57_review.sh').read_text()
    assert 'sha256sum --check --status "$manifest"' in sh
    assert 'sha257sum' not in sh
    assert 'V5_5 V5_6 V5_7;' in sh
    assert '54 55 56 57;' in sh
    assert 'bash scripts/check_v56_review.sh' in check
    assert 'scripts.run_postgres_isolation_ci_v57' in sh
    assert sh.index('scripts.test_mutation_snapshot_v54')<sh.index('command -v docker')
    assert 'cutover DENIED' in sh and '127.0.0.1' in sh
    assert 'JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE' in sh
    assert 'export JW_PG_CI_ALLOW' not in sh

@pytest.mark.parametrize(('value','code'),[(None,0),('',0),('development',0),('production',2),('PRODUCTION',2),('PrOdUcTiOn',2)])
def test_pg17_environment_denial(value,code):
    sh=(ROOT/'scripts/run_pg17_codespaces_v57.sh').read_text()
    guard=sh[sh.index('JW_ENV_SAFE='):sh.index('for version in 35')]
    env=os.environ.copy();env.pop('JW_ENV',None)
    if value is not None:env['JW_ENV']=value
    p=subprocess.run(['bash','-c','set -Eeuo pipefail\n'+guard+'\nprintf "OK\\n"'],
                     env=env,cwd=ROOT,text=True,capture_output=True,timeout=5)
    assert p.returncode==code, (p.stdout,p.stderr)
    assert ('OK' in p.stdout)==(code==0)

def test_previous_live_gate_first(monkeypatch):
    from scripts import run_postgres_isolation_ci_v57 as current
    from scripts import run_postgres_isolation_ci_v56 as previous
    from scripts import test_postgres_edit_history_v56 as old
    from scripts import test_postgres_attachment_payload_v57 as added
    for x in (53,54,55,56,57):monkeypatch.setenv(f'JW_PG_LAB_V{x}','ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    monkeypatch.delenv('JW_ENV',raising=False)
    events=[]
    monkeypatch.setattr(old,'run',lambda:events.append('previous') or 0)
    monkeypatch.setattr(added,'run',lambda:events.append('attachment') or 0)
    monkeypatch.setattr(previous,'main',lambda:old.run())
    assert current.main()==0 and events==['previous','attachment']
    events.clear();monkeypatch.setattr(old,'run',lambda:events.append('fail') or 1)
    assert current.main()==1 and events==['fail']

def test_missing_authorization(monkeypatch):
    from scripts.run_postgres_isolation_ci_v57 import main
    monkeypatch.setenv('JW_ENV','Production')
    assert main()==2
