"""Block regressions that would overwrite/bypass previous source hashes."""
from pathlib import Path


def test_new_gate_runs_actual_http_tests_without_skips():
    script = Path('scripts/check_v59_review.sh').read_text()
    assert 'tests/test_v59_web_api.py' in script
    assert 'tests/test_read_actor_journal_v59.py' in script
    assert 'V5_9_SOURCE_SHA256.txt' in script
    assert 'bash scripts/check_v58_review.sh' not in script
    assert 'pytest.skip' not in script


def test_historical_pg17_on_immutable_base_not_mutated_tree():
    script = Path('scripts/run_pg17_codespaces_v59.sh').read_text()
    assert 'e8ea684c9af78debdfc26179641e3094f2d2ef20' in script
    assert 'git worktree add --detach "$work" "$V58_BASE"' in script
    assert 'git merge-base --is-ancestor "$V58_BASE" HEAD' in script
    assert 'bash scripts/check_v58_review.sh' in script
    assert 'bash scripts/run_pg17_codespaces_v58.sh' in script
    assert 'git worktree remove --force "$work"' in script
    assert 'trap cleanup EXIT' in script


def test_gates_fail_closed_and_no_prod_activation():
    for p in ['scripts/check_v59_review.sh','scripts/run_pg17_codespaces_v59.sh']:
        script=Path(p).read_text()
        assert 'set -Eeuo pipefail' in script
        assert '|| true' not in script
        assert 'exit 0' not in script
        assert 'JW_ENV=production' not in script


def test_real_git_worktree_cleanup_and_error_propagation(tmp_path):
    """Execute the shell gate with synthetic historical steps, not a live PG server."""
    import os
    import subprocess

    def run(*args, cwd=None, env=None):
        return subprocess.run(args,cwd=cwd,env=env,text=True,capture_output=True)

    for expected in (0, 7):
        repo=tmp_path / f'repo-{expected}'
        repo.mkdir()
        assert run('git','init','-q',str(repo)).returncode == 0
        assert run('git','config','user.email','verify@example.invalid',cwd=repo).returncode == 0
        assert run('git','config','user.name','Reviewer',cwd=repo).returncode == 0
        scripts=repo/'scripts';scripts.mkdir()
        (scripts/'check_v58_review.sh').write_text('#!/bin/bash\nexit 0\n')
        (scripts/'run_pg17_codespaces_v58.sh').write_text(f'#!/bin/bash\nexit {expected}\n')
        assert run('git','add','.',cwd=repo).returncode == 0
        assert run('git','commit','-qm','synthetic V58 baseline',cwd=repo).returncode == 0
        base=run('git','rev-parse','HEAD',cwd=repo).stdout.strip()
        (scripts/'run_pg17_codespaces_v59.sh').write_text(
            Path('scripts/run_pg17_codespaces_v59.sh').read_text().replace(
                'e8ea684c9af78debdfc26179641e3094f2d2ef20',base))
        assert run('git','add','.',cwd=repo).returncode == 0
        assert run('git','commit','-qm','synthetic V59 candidate',cwd=repo).returncode == 0
        env=os.environ.copy()
        path=tmp_path/f'temps-{expected}'
        path.mkdir()
        env['TMPDIR']=str(path)
        result=run('bash','scripts/run_pg17_codespaces_v59.sh',cwd=repo,env=env)
        assert result.returncode == expected, (expected,result.stdout,result.stderr)
        assert not list(path.iterdir()), 'detached historical worktree leaked'
        trees=run('git','worktree','list','--porcelain',cwd=repo).stdout
        assert trees.count('worktree ') == 1
