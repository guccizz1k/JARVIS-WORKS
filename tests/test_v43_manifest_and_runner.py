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


@pytest.mark.parametrize('scenario,expected', [
    ('host_node', 0),
    ('docker_success', 0),
    ('docker_check_failure', 1),
    ('no_docker', 2),
    ('docker_pull_failure', 2),
])
def test_node_fallback_executes_or_fails_closed(tmp_path, scenario, expected):
    """Actual Bash preflight with fake tools, no image/network/PG side effects.

    Fake Python and SHA commands focus this test ONLY on Node fallback dispatch;
    normal full-repository testing still uses the real commands.
    """
    import os
    import shutil
    import subprocess

    lab = tmp_path / 'check with spaces'
    folder = lab / 'scripts'
    folder.mkdir(parents=True)
    (lab / 'app' / 'static').mkdir(parents=True)
    (lab / 'app' / 'static' / 'app.js').write_text('let x = 1;\n')
    script = folder / 'check_v43_review.sh'
    script.write_bytes(Path('scripts/check_v43_review.sh').read_bytes())
    (folder / 'run_pg17_codespaces_v43.sh').write_text('#!/bin/bash\n')
    fake = tmp_path / 'fakebin'
    fake.mkdir()
    for name in ('bash', 'dirname'):
        binary = shutil.which(name)
        assert binary is not None
        (fake / name).symlink_to(binary)
    for name in ('python3', 'sha256sum'):
        target = fake / name
        target.write_text('#!/bin/sh\nexit 0\n')
        target.chmod(0o755)
    trace = tmp_path / 'docker.trace'
    if scenario == 'host_node':
        node = fake / 'node'
        node.write_text('#!/bin/sh\nexit 0\n')
        node.chmod(0o755)
    if scenario not in ('no_docker', 'host_node'):
        docker = fake / 'docker'
        docker.write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$DOCKER_TRACE"
if [ "$1" = 'info' ]; then exit 0; fi
if [ "$1" = 'image' ]; then
  if [ "$DOCKER_SCENARIO" = 'docker_pull_failure' ]; then exit 1; fi
  exit 0
fi
if [ "$1" = 'pull' ]; then exit 1; fi
if [ "$1" = 'run' ]; then
  # The daemon cannot access a Codespaces worktree path in this fake.
  # The verifier must pass the actual JavaScript bytes through stdin.
  IFS= read -r first_line || exit 34
  [ "$first_line" = 'let x = 1;' ] || exit 35
  if [ "$DOCKER_SCENARIO" = 'docker_check_failure' ]; then exit 1; fi
  exit 0
fi
exit 1
''')
        docker.chmod(0o755)
    environment = {**os.environ, 'PATH': str(fake), 'DOCKER_TRACE': str(trace),
                   'DOCKER_SCENARIO': scenario}
    execution = subprocess.run([str(fake / 'bash'), str(script)],
                               cwd=lab, env=environment,
                               capture_output=True, text=True, timeout=10)
    assert execution.returncode == expected, (execution.stdout, execution.stderr)
    if scenario in ('host_node', 'docker_success'):
        assert 'PASS: local full-repository V4.3' in execution.stdout
    else:
        assert 'PASS: local full-repository V4.3' not in execution.stdout
    if scenario not in ('no_docker', 'host_node'):
        recorded = trace.read_text()
        assert 'info' in recorded and 'image inspect node:22-alpine' in recorded
        if scenario in ('docker_success', 'docker_check_failure'):
            assert 'run --rm -i --network none --read-only --cap-drop ALL' in recorded
            assert '--security-opt no-new-privileges' in recorded
            assert '--mount' not in recorded and '--volume' not in recorded
            assert 'node --check -' in recorded


def test_node_syntax_stdin_supported_by_real_node_when_available():
    """Node 22 syntax-only STDIN contract, independent of Docker mounts."""
    import subprocess
    import shutil
    import pytest
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node not installed in Python Codespaces')
    good = subprocess.run([node,'--check','-'],input='let count = 1;\n',
                          capture_output=True,text=True,timeout=5)
    bad = subprocess.run([node,'--check','-'],input='let = ;\n',
                         capture_output=True,text=True,timeout=5)
    assert good.returncode == 0
    assert bad.returncode != 0


def test_node_docker_fallback_never_uses_host_bind_mount():
    """Prevents regression to a path inaccessible inside Docker-in-Docker."""
    source = Path('scripts/check_v43_review.sh').read_text()
    assert 'node --check - < "$ROOT/app/static/app.js"' in source
    assert 'docker run --rm -i' in source
    assert '--network none' in source and '--read-only' in source
    assert '--mount' not in source and '-v "$ROOT' not in source
    assert 'node --check /source/app.js' not in source
