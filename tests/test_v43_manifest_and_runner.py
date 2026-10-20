"""V4.3 additive runner and immutable-history integration safety tests."""
from pathlib import Path
from unittest.mock import Mock
from types import ModuleType
import sys

import pytest

from scripts import build_v43_manifest as manifest
from scripts import run_postgres_isolation_ci_v43 as wrapper


def test_review_head_and_main_are_protected():
    assert manifest.BASE_COMMIT == '8e6c56bd35da5eaa698a2f12081c11ac115eae94'
    assert len(manifest.CHAIN) == 9
    assert 'V4_2' in manifest.CHAIN
    assert 'app/main.py' not in manifest.FILES
    assert 'V2_1_ORIGINAL_MANIFEST.sha256' not in manifest.FILES
    assert 'scripts/run_postgres_isolation_ci_v28.py' in manifest.FILES


def test_manifest_refuses_non_repo_without_writing(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert manifest.build() == 2
    assert not manifest.OUT.exists()


def test_manifest_refuses_invalid_base_before_checking_any_hash(monkeypatch,tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(manifest, '_git', lambda *args: 'not-the-baseline')
    assert manifest.build() == 2
    assert not manifest.OUT.exists()


def test_wrapper_blocks_unapproved_flags(monkeypatch):
    for key in ('JW_ENV','JW_PG_CI_ALLOW'):
        monkeypatch.delenv(key,raising=False)
    assert wrapper.main() == 2
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    monkeypatch.setenv('JW_ENV','production')
    assert wrapper.main() == 2


def test_wrapper_runs_baseline_first_and_web_only_on_success(monkeypatch):
    monkeypatch.delenv('JW_ENV',raising=False)
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    for n in ('35','36','37','38','39','40','41','42','43'):
        monkeypatch.setenv('JW_PG_LAB_V'+n,'ONLY_DISPOSABLE_LAB')
    calls=[]
    baseline=ModuleType('scripts.test_postgres_restore_v42')
    web=ModuleType('scripts.test_postgres_web_v43')
    supervisor=ModuleType('scripts.run_postgres_isolation_ci_v28')
    baseline.run=lambda: (calls.append('baseline') or 0)
    web.run=lambda: (calls.append('web') or 0)
    supervisor.main=lambda: (calls.append('supervisor') or baseline.run())
    original=baseline.run
    for name,module in (('scripts.test_postgres_restore_v42',baseline),
                        ('scripts.test_postgres_web_v43',web),
                        ('scripts.run_postgres_isolation_ci_v28',supervisor)):
        monkeypatch.setitem(sys.modules,name,module)
    assert wrapper.main()==0
    assert calls == ['supervisor','baseline','web']
    assert baseline.run is original


def test_wrapper_skips_v43_if_v42_failed(monkeypatch):
    monkeypatch.delenv('JW_ENV',raising=False)
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    for n in ('35','36','37','38','39','40','41','42','43'):
        monkeypatch.setenv('JW_PG_LAB_V'+n,'ONLY_DISPOSABLE_LAB')
    calls=[]
    baseline=ModuleType('scripts.test_postgres_restore_v42')
    web=ModuleType('scripts.test_postgres_web_v43')
    supervisor=ModuleType('scripts.run_postgres_isolation_ci_v28')
    baseline.run=lambda: (calls.append('baseline') or 1)
    web.run=lambda: (calls.append('web') or 0)
    supervisor.main=lambda: baseline.run()
    old=baseline.run
    for name, module in (('scripts.test_postgres_restore_v42',baseline),
                         ('scripts.test_postgres_web_v43',web),
                         ('scripts.run_postgres_isolation_ci_v28',supervisor)):
        monkeypatch.setitem(sys.modules,name,module)
    assert wrapper.main()==1
    assert calls==['baseline']
    assert baseline.run is old


def test_shell_runner_does_not_edit_historical_manifests_or_publish():
    script=Path('scripts/run_pg17_codespaces_v43.sh').read_text()
    assert 'V4_2' in script and 'V4_3' in script
    assert 'sha256sum --check' in script
    assert '-m scripts.run_postgres_isolation_ci_v43' in script
    assert '127.0.0.1::5432' in script
    assert 'git push' not in script and 'pg_restore' not in script
    assert 'sed -i' not in script


def test_v43_source_does_not_modify_app_main_or_old_pg_supervisor():
    files=set(manifest.FILES)
    assert 'app/main.py' not in files
    assert not any(n.endswith('_PG_GATE_SHA256.txt') for n in files if not n.startswith('V4_2'))
    assert 'scripts/run_postgres_isolation_ci_v28.py' in files  # hash only


def test_web_live_gate_covers_actual_http_concurrency_and_race():
    text=Path('scripts/test_postgres_web_v43.py').read_text()
    assert 'ThreadPoolExecutor(max_workers=2)' in text
    assert "[200,201]" in text
    assert "COUNT(DISTINCT message_seq)" in text
    assert "TestClient(create_lab_app(dsn))" in text


def test_wrapper_restores_original_callback_after_exception(monkeypatch):
    monkeypatch.delenv('JW_ENV',raising=False)
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    for n in ('35','36','37','38','39','40','41','42','43'):
        monkeypatch.setenv('JW_PG_LAB_V'+n,'ONLY_DISPOSABLE_LAB')
    baseline=ModuleType('scripts.test_postgres_restore_v42')
    web=ModuleType('scripts.test_postgres_web_v43')
    supervisor=ModuleType('scripts.run_postgres_isolation_ci_v28')
    baseline.run=lambda: 0
    old=baseline.run
    web.run=lambda: 0
    supervisor.main=lambda: (_ for _ in ()).throw(RuntimeError('injected failure'))
    for name,module in (('scripts.test_postgres_restore_v42',baseline),
                        ('scripts.test_postgres_web_v43',web),
                        ('scripts.run_postgres_isolation_ci_v28',supervisor)):
        monkeypatch.setitem(sys.modules,name,module)
    with pytest.raises(RuntimeError):
        wrapper.main()
    assert baseline.run is old


def test_manifest_builder_preserves_existing_checked_evidence(tmp_path,monkeypatch):
    import hashlib
    monkeypatch.chdir(tmp_path)
    Path('app').mkdir()
    Path('app/main.py').write_text('protected baseline')
    Path('app/candidate.py').write_text('v43 synthetic change')
    Path('runner.py').write_text('historical immutable runner')
    digest=lambda blob: hashlib.sha256(blob).hexdigest()
    original_runner=Path('runner.py').read_bytes()
    Path('V4_2_PG_GATE_SHA256.txt').write_text(
        digest(original_runner) + '  runner.py\n')
    original_manifest=Path('V4_2_PG_GATE_SHA256.txt').read_bytes()
    monkeypatch.setattr(manifest,'CHAIN',('V4_2',))
    monkeypatch.setattr(manifest,'FILES',('app/candidate.py','runner.py','V4_2_PG_GATE_SHA256.txt'))
    monkeypatch.setattr(manifest,'_git',lambda *a: '' if a[0]=='status' or a[0]=='branch' else manifest.BASE_COMMIT)
    assert manifest.build()==0
    assert Path('V4_3_PG_GATE_SHA256.txt').exists()
    assert Path('runner.py').read_bytes()==original_runner
    assert Path('V4_2_PG_GATE_SHA256.txt').read_bytes()==original_manifest
    assert manifest.build()==2  # no overwrite
    assert Path('V4_2_PG_GATE_SHA256.txt').read_bytes()==original_manifest


def test_manifest_builder_refuses_tampered_history(tmp_path,monkeypatch):
    import hashlib
    monkeypatch.chdir(tmp_path)
    Path('app').mkdir()
    Path('app/main.py').write_text('protected')
    Path('app/candidate.py').write_text('candidate')
    Path('runner.py').write_text('tampered content')
    Path('V4_2_PG_GATE_SHA256.txt').write_text(hashlib.sha256(b'correct').hexdigest()+'  runner.py\n')
    monkeypatch.setattr(manifest,'CHAIN',('V4_2',))
    monkeypatch.setattr(manifest,'FILES',('app/candidate.py','runner.py','V4_2_PG_GATE_SHA256.txt'))
    monkeypatch.setattr(manifest,'_git',lambda *a: '' if a[0]=='status' or a[0]=='branch' else manifest.BASE_COMMIT)
    assert manifest.build()==2
    assert not manifest.OUT.exists()
