"""Offline patch tests: reject unexpected baseline and recover on simulated failure."""
import json
from pathlib import Path
import shutil
import pytest
from scripts.install_v75 import run

ROOT=Path(__file__).resolve().parents[1]


def fixture(tmp_path):
    root=tmp_path/'root';bundle=tmp_path/'bundle'
    (root/'app').mkdir(parents=True)
    (root/'scripts').mkdir();(root/'tests').mkdir()
    (bundle/'payload').mkdir(parents=True)
    quality=(ROOT/'app/evidence_quality_v70.py').read_bytes()
    main=(Path('/mnt/data/jw_v70_release/payload/app/main.py') if Path('/mnt/data/jw_v70_release/payload/app/main.py').exists() else ROOT/'app/main.py')
    # Source golden V7.0 is built from the patch baseline: remove only the two additive lines.
    original=ROOT.joinpath('app/main.py').read_text()
    original=original.replace('from .ops_integrity_v71 import register_routes as register_ops_integrity_routes_v71\n','')
    original=original.replace("\nregister_ops_integrity_routes_v71(app,conn=conn,current_user=current_user,need_admin=need_admin,\n    retrieve_items=retrieve_items,money=money,adjusted_settlement=adjusted_settlement_v69)\n",'')
    assert __import__('hashlib').sha256(original.encode()).hexdigest()=='06dcb206a49e3d728ddff3a7154cc7c37ac36bcf867a73d4539ea172cdbca210'
    (root/'app/main.py').write_text(original)
    (root/'app/evidence_quality_v70.py').write_bytes(quality)
    addon=['app/main.py','app/ops_integrity_v71.py','app/ops_cutover_v71.py','scripts/recovery_gate_v72.py']
    digests={}
    for rel in addon:
        target=bundle/'payload'/rel
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes((ROOT/rel).read_bytes())
        digests[rel]=__import__('hashlib').sha256(target.read_bytes()).hexdigest()
    (bundle/'PAYLOAD_SHA256.json').write_text(json.dumps(digests))
    return root,bundle


def test_apply_idempotent_and_integrity(tmp_path):
    root,bundle=fixture(tmp_path)
    assert run(root,bundle)['planned_files']==4
    old_mode=(root/'app/main.py').stat().st_mode & 0o777
    assert run(root,bundle,apply=True)['changed_files']==4
    assert (root/'app/main.py').stat().st_mode & 0o777 == old_mode
    assert run(root,bundle)['planned_files']==0
    assert run(root,bundle,apply=True)['changed_files']==0


def test_preflight_rejects_modified_payload_and_original(tmp_path):
    root,bundle=fixture(tmp_path)
    (bundle/'payload/app/ops_cutover_v71.py').write_text('modified')
    with pytest.raises(RuntimeError,match='payload SHA256'):run(root,bundle,apply=True)
    assert not (root/'app/ops_integrity_v71.py').exists()
    root,bundle=fixture(tmp_path/'second')
    (root/'app/main.py').write_text('unrecognized')
    with pytest.raises(RuntimeError,match='not V7.0 original'):run(root,bundle,apply=True)


def test_simulated_fault_rolls_back_every_file(tmp_path,monkeypatch):
    root,bundle=fixture(tmp_path)
    original=(root/'app/main.py').read_bytes()
    monkeypatch.setenv('JW_INSTALL_TEST_MODE','ONLY_SYNTHETIC')
    with pytest.raises(RuntimeError,match='INJECTED_FAILURE'):
        run(root,bundle,apply=True,inject_failure_after=3)
    assert (root/'app/main.py').read_bytes()==original
    assert not (root/'app/ops_integrity_v71.py').exists()
    assert not (root/'app/ops_cutover_v71.py').exists()
    assert run(root,bundle)['planned_files']==4


def test_blocks_production_and_symlink(tmp_path,monkeypatch):
    root,bundle=fixture(tmp_path)
    monkeypatch.setenv('JW_ENV','production')
    with pytest.raises(RuntimeError,match='production'):run(root,bundle)
    monkeypatch.delenv('JW_ENV')
    path=tmp_path/'symlink';path.symlink_to(root, target_is_directory=True)
    with pytest.raises(RuntimeError,match='invalid root'):run(path,bundle)
