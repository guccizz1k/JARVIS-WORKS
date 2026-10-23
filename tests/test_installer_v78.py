"""New review package installer regression; operates only on synthetic directories."""
import json
import os
from pathlib import Path
import shutil
import pytest
from scripts.install_v78 import inspect,apply,InstallBlocked

SOURCE=Path(__file__).resolve().parents[1]
BUNDLE=Path(os.getenv('JW_V78_ADDON_DIR', str(SOURCE/'v78_addon')))
BASE=BUNDLE/'fixtures/v77_baseline'


def fixture(tmp_path):
    root=tmp_path/'review';bundle=tmp_path/'package'
    for dirname in ('app','scripts','tests'):(root/dirname).mkdir(parents=True,exist_ok=True)
    addon=BUNDLE
    shutil.copytree(addon,bundle)
    baselines=json.loads((bundle/'BASE_SHA256.json').read_text())
    for rel in baselines:
        src=BASE/rel
        dest=root/rel
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(src,dest)
    return root,bundle


def test_apply_and_second_run_noop(tmp_path):
    root,bundle=fixture(tmp_path)
    assert len(inspect(root,bundle)['planned'])==11
    original_mode=(root/'app/main.py').stat().st_mode & 0o777
    assert apply(root,bundle)['changed']==11
    assert inspect(root,bundle)['planned']==[]
    assert apply(root,bundle)['changed']==0
    assert (root/'app/main.py').stat().st_mode & 0o777==original_mode


def test_original_and_package_tamper_blocked(tmp_path):
    root,bundle=fixture(tmp_path)
    (root/'app/main.py').write_text('unsafe modification')
    with pytest.raises(InstallBlocked,match='baseline differs'):
        apply(root,bundle)
    root,bundle=fixture(tmp_path/'second')
    (bundle/'payload/app/main.py').write_text('tampered')
    with pytest.raises(InstallBlocked,match='Payload integrity failure'):
        apply(root,bundle)


def test_midinstall_failure_rolls_back(tmp_path,monkeypatch):
    root,bundle=fixture(tmp_path)
    old=(root/'app/main.py').read_bytes()
    monkeypatch.setenv('JW_INSTALL_TEST_MODE','SYNTHETIC_V78_ONLY')
    with pytest.raises(InstallBlocked,match='INJECTED_FAILURE'):
        apply(root,bundle,inject_failure_after=4)
    assert (root/'app/main.py').read_bytes()==old
    assert not (root/'app/deployment_safety_v78.py').exists()
    assert len(inspect(root,bundle)['planned'])==11


def test_production_and_symlink_blocked(tmp_path,monkeypatch):
    root,bundle=fixture(tmp_path)
    monkeypatch.setenv('JW_ENV','production')
    with pytest.raises(InstallBlocked,match='Production'):
        inspect(root,bundle)
    monkeypatch.delenv('JW_ENV')
    (root/'app/deployment_safety_v78.py').symlink_to(root/'app/main.py')
    with pytest.raises(InstallBlocked,match='Symlink'):
        apply(root,bundle)


def test_parent_symlink_and_missing_baseline_blocked(tmp_path):
    root,bundle=fixture(tmp_path)
    (root/'app/evidence_quality_v70.py').unlink()
    with pytest.raises(InstallBlocked,match='Missing V7.7'):
        inspect(root,bundle)
