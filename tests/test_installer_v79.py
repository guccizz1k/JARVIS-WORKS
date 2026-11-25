"""Installer isolation tests. Uses only disposable temporary directories."""
from pathlib import Path
import shutil
import hashlib

import pytest
from scripts.install_v79 import install,InstallBlocked

ROOT=Path(__file__).resolve().parents[1]
OVERLAY=(ROOT.parent/'overlay' if (ROOT.parent/'overlay').is_dir() else ROOT.parent/'jw_v79_overlay')
BASE_FILES=('app/main.py','app/pg_rls_full_review_v78.py','scripts/release_audit_v78.py','pytest.ini','app/deployment_safety_v78.py')

@pytest.fixture
def stage(tmp_path):
    root=tmp_path/'stage';root.mkdir()
    for name in BASE_FILES:
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True)
        historical=(ROOT/'v78_addon/payload/app/main.py') if name=='app/main.py' else (ROOT/name)
        if name=='app/main.py':
            assert hashlib.sha256(historical.read_bytes()).hexdigest()=='e4584787c8ee97a417656e62297507caa7d618f4146398342dabc23c8a6ab25f'
        shutil.copy2(historical,p)
    return root

def test_clean_install_and_idempotent(stage):
    assert install(stage,OVERLAY)=={'status':'CHECK','changes':4}
    assert install(stage,OVERLAY,apply=True)=={'status':'APPLIED','changes':4}
    assert install(stage,OVERLAY,apply=True)=={'status':'APPLIED','changes':0}

def test_baseline_drift_blocked(stage):
    (stage/'app/main.py').write_text('tamper')
    with pytest.raises(InstallBlocked,match='baseline hash'):install(stage,OVERLAY,apply=True)
    assert not (stage/'app/pg_rls_gate_v79.py').exists()

def test_existing_target_conflict_blocked(stage):
    p=stage/'app/pg_rls_gate_v79.py';p.write_text('user changes')
    with pytest.raises(InstallBlocked,match='overwrite'):install(stage,OVERLAY,apply=True)

def test_production_blocked(stage,monkeypatch):
    monkeypatch.setenv('JW_ENV','production')
    with pytest.raises(InstallBlocked,match='production'):install(stage,OVERLAY,apply=True)

def test_target_symlink_blocked(stage):
    (stage/'app/pg_rls_gate_v79.py').symlink_to(stage/'app/main.py')
    with pytest.raises(InstallBlocked,match='Symlink'):install(stage,OVERLAY,apply=True)

def test_overlay_corruption_blocked(stage,tmp_path):
    altered=tmp_path/'altered';shutil.copytree(OVERLAY,altered)
    with (altered/'payload/app/pg_rls_gate_v79.py').open('ab') as out:out.write(b'bad')
    with pytest.raises(InstallBlocked,match='payload hash'):install(stage,altered,apply=True)

def test_partial_failure_rolls_back(stage,monkeypatch):
    import scripts.install_v79 as m
    replace=m.os.replace
    count={'i':0}
    def fail_second(src,dst):
        count['i']+=1
        if count['i']==2:raise OSError('Injected failure')
        return replace(src,dst)
    monkeypatch.setattr(m.os,'replace',fail_second)
    with pytest.raises(OSError,match='Injected'):install(stage,OVERLAY,apply=True)
    assert not (stage/'app/pg_rls_gate_v79.py').exists()
    assert not (stage/'scripts/check_pg_rls_v79.py').exists()
