"""V4.9 mobile JW harness safety and end-to-end detached worktree regression."""
from __future__ import annotations
import os
import hashlib
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/jw.sh'


def call(cmd, cwd=None, env=None):
    return subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True, timeout=20)


def make_lab(tmp_path, check_rc=0, pg_rc=0):
    """Real local Git bare remote; shim only remote URL check, never git itself."""
    root=tmp_path/'worktree'
    bare=tmp_path/'origin.git'
    root.mkdir()
    subprocess.run(['git','init','--bare',str(bare)],check=True,capture_output=True)
    subprocess.run(['git','init',str(root)],check=True,capture_output=True)
    for cmd in [('git','-C',str(root),'config','user.email','qa@example.test'),
                ('git','-C',str(root),'config','user.name','Test QA'),
                ('git','-C',str(root),'remote','add','origin',str(bare))]:
        subprocess.run(cmd,check=True,capture_output=True)
    (root/'scripts').mkdir()
    (root/'scripts/check_v49_review.sh').write_text(f'#!/bin/bash\necho CHECK_V49\nexit {check_rc}\n')
    (root/'scripts/run_pg17_codespaces_v49.sh').write_text(f'#!/bin/bash\necho PG_V49\nexit {pg_rc}\n')
    shutil.copyfile(ROOT/'scripts/jw.sh',root/'scripts/jw.sh')
    shutil.copyfile(ROOT/'scripts/install_jw.sh',root/'scripts/install_jw.sh')
    digest=hashlib.sha256((root/'scripts/jw.sh').read_bytes()).hexdigest()
    (root/'V4_9_PG_GATE_SHA256.txt').write_text(f'{digest}  scripts/jw.sh\n')
    subprocess.run(['git','-C',str(root),'add','.'],check=True,capture_output=True)
    subprocess.run(['git','-C',str(root),'commit','-m','fixture'],check=True,capture_output=True)
    subprocess.run(['git','-C',str(root),'push','origin','HEAD:refs/heads/review/v49'],check=True,capture_output=True)
    (root/'sentinel').write_text('DO_NOT_TOUCH')
    shim=tmp_path/'shim';shim.mkdir()
    actual_git=shutil.which('git')
    assert actual_git
    (shim/'git').write_text('#!/bin/bash\n'
        'if [[ "$1" == -C && "$3" == remote && "$4" == get-url && "$5" == origin ]]; then\n'
        '  echo https://github.com/guccizz1k/JARVIS-WORKS\n  exit 0\nfi\n'
        'if [[ "$1" == -C && "$3" == worktree && "$4" == remove && "${FAKE_FAIL_REMOVE:-}" == 1 ]]; then\n'
        '  exit 17\nfi\n'
        f'exec "{actual_git}" "$@"\n')
    (shim/'git').chmod(0o755)
    home=tmp_path/'user';home.mkdir()
    env={**os.environ,'JW_REPO_DIR':str(root),'JW_LOG_DIR':str(home/'logs'),
        'HOME':str(home),'PATH':str(shim)+':'+os.environ['PATH'],'TMPDIR':str(tmp_path)}
    return root,env


def test_success_isolated_and_log_retained(tmp_path):
    root,env=make_lab(tmp_path)
    done=call(['bash',str(SCRIPT),'49'],env=env)
    assert done.returncode==0,(done.stdout,done.stderr)
    assert 'CHECK_V49' in done.stdout and 'PG_V49' in done.stdout
    assert 'PASS: jw 49 complete' in done.stdout
    assert (root/'sentinel').read_text()=='DO_NOT_TOUCH'
    assert not list(tmp_path.glob('jw-review-v49.*'))
    assert len(call(['git','-C',str(root),'worktree','list','--porcelain']).stdout.split('worktree '))==2
    latest=call(['bash',str(SCRIPT),'last'],env=env)
    assert latest.returncode==0 and 'PASS: jw 49 complete' in latest.stdout


def test_historical_gate_failure_blocks_pg(tmp_path):
    _,env=make_lab(tmp_path,check_rc=1)
    done=call(['bash',str(SCRIPT),'49'],env=env)
    assert done.returncode==1 and 'CHECK_V49' in done.stdout
    assert 'PG_V49' not in done.stdout and 'FAIL: jw 49 gate failed' in done.stderr
    assert not list(tmp_path.glob('jw-review-v49.*'))


def test_pg_failure_is_never_marked_pass(tmp_path):
    _,env=make_lab(tmp_path,pg_rc=1)
    done=call(['bash',str(SCRIPT),'49'],env=env)
    assert done.returncode==1 and 'PG_V49' in done.stdout
    assert 'PASS: jw 49 complete' not in done.stdout


def test_missing_review_branch_not_run(tmp_path):
    _,env=make_lab(tmp_path)
    done=call(['bash',str(SCRIPT),'50'],env=env)
    assert done.returncode==2 and 'NOT RUN: cannot fetch' in done.stderr


def test_production_disabled(tmp_path):
    _,env=make_lab(tmp_path)
    env['JW_ENV']='production'
    done=call(['bash',str(SCRIPT),'49'],env=env)
    assert done.returncode==2 and 'production environment blocked' in done.stderr


def test_invalid_input_does_not_execute(tmp_path):
    _,env=make_lab(tmp_path)
    for name in ('../../main','49;true','main','0','101','4 9'):
        done=call(['bash',str(SCRIPT),name],env=env)
        assert done.returncode==2,(name,done.stdout,done.stderr)


def test_rejects_unrelated_origin_without_fetch(tmp_path):
    root,env=make_lab(tmp_path)
    env['PATH']=env['PATH'].split(':',1)[1]
    done=call(['bash',str(SCRIPT),'49'],env=env)
    assert done.returncode==2 and 'unexpected GitHub origin' in done.stderr
    assert (root/'sentinel').read_text()=='DO_NOT_TOUCH'


def test_missing_local_bin_installer_does_not_overwrite_system():
    s=(ROOT/'scripts/install_jw.sh').read_text()
    assert 'ref=$(git' in s
    assert 'origin/review/v49' in s
    assert 'refusing to overwrite unrelated jw executable' in s
    assert 'sha256sum "$staging"' in s
    assert 'sudo ' not in s and 'curl ' not in s


def test_v49_wrapper_does_not_silently_skip_previous_gate():
    script=(ROOT/'scripts/run_pg17_codespaces_v49.sh').read_text()
    assert 'bash scripts/run_pg17_codespaces_v48.sh' in script
    assert script.index('bash scripts/run_pg17_codespaces_v48.sh') < script.index('PASS: V4.9')
    assert 'set -Eeuo pipefail' in script


def test_v49_preflight_checks_provenance():
    check=(ROOT/'scripts/check_v49_review.sh').read_text()
    assert 'sha256sum --check --status V4_9_PG_GATE_SHA256.txt' in check
    assert 'bash scripts/check_v48_review.sh' in check


def test_cleanup_failure_never_prints_pass(tmp_path):
    _,env=make_lab(tmp_path)
    env['FAKE_FAIL_REMOVE']='1'
    done=call(['bash',str(SCRIPT),'49'],env=env)
    assert done.returncode==1,(done.stdout,done.stderr)
    assert 'FAIL: review worktree cleanup failed' in done.stderr
    assert 'PASS: jw 49 complete' not in done.stdout


def test_bootstrap_installs_only_checked_jw_to_home(tmp_path):
    root,env=make_lab(tmp_path)
    # The install script is executed from the same fetched ref as the launcher.
    fetched=call(['git','-C',str(root),'fetch','origin',
                  'refs/heads/review/v49:refs/remotes/origin/review/v49'],env=env)
    assert fetched.returncode==0,fetched.stderr
    ran=call(['bash',str(ROOT/'scripts/install_jw.sh')],env=env)
    assert ran.returncode==0,(ran.stdout,ran.stderr)
    installed=Path(env['HOME'])/'.local/bin/jw'
    assert installed.is_file() and not installed.is_symlink()
    assert installed.read_bytes()==(ROOT/'scripts/jw.sh').read_bytes()
    assert (installed.stat().st_mode & 0o777)==0o700
    invoked=call(['bash',str(installed),'49'],env=env)
    assert invoked.returncode==0,(invoked.stdout,invoked.stderr)


def test_bootstrap_refuses_unrelated_executable(tmp_path):
    root,env=make_lab(tmp_path)
    assert call(['git','-C',str(root),'fetch','origin',
                 'refs/heads/review/v49:refs/remotes/origin/review/v49'],env=env).returncode==0
    installed=Path(env['HOME'])/'.local/bin/jw'
    installed.parent.mkdir(parents=True)
    installed.write_text('unrelated command')
    bad=call(['bash',str(ROOT/'scripts/install_jw.sh')],env=env)
    assert bad.returncode==2 and 'refusing to overwrite' in bad.stderr
    assert installed.read_text()=='unrelated command'


def test_jw_last_refuses_path_traversal(tmp_path):
    _,env=make_lab(tmp_path)
    d=Path(env['JW_LOG_DIR']);d.mkdir()
    (d/'latest').write_text('../../secret')
    got=call(['bash',str(SCRIPT),'last'],env=env)
    assert got.returncode==2 and 'invalid saved log' in got.stderr
