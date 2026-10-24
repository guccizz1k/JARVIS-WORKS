"""Real Git fixture tests. Use the recovered local checkout; never edit it."""
from pathlib import Path
import subprocess
import os
import pytest
from verify_v89_v90_ancestry import inspect, V89

SOURCE = Path(os.environ['JW_V89_V90_SOURCE_ROOT']).resolve() if os.environ.get('JW_V89_V90_SOURCE_ROOT') else None

@pytest.fixture(autouse=True)
def require_authoritative_bundle():
    if SOURCE is None or not (SOURCE/'.git').exists():
        pytest.fail('Set JW_V89_V90_SOURCE_ROOT to the extracted, Git-verified integrated checkout')

def command(root, *args):
    return subprocess.run(['git', '-c', f'safe.directory={root.resolve()}', '-C', str(root), *args],
                          check=True, capture_output=True, text=True).stdout.strip()

@pytest.fixture
def working_clone(tmp_path):
    target = tmp_path / 'checkout'
    subprocess.run(['git', '-c', f'safe.directory={SOURCE.resolve()}', 'clone', '-q',
                   '--no-hardlinks', str(SOURCE), str(target)], check=True, capture_output=True)
    command(target, 'config','user.name','QA fixture')
    command(target, 'config','user.email','qa@example.invalid')
    return target

def test_original_integrated_snapshot_passes():
    report = inspect(SOURCE)
    assert report['status'] == 'PASS'
    assert len(report['changed_files']) == 10
    assert not report['this_proves_remote_github_ancestry']

def test_missing_original_sha_is_blocked():
    report = inspect(SOURCE, expected_base='0'*40)
    assert report['status'] == 'BLOCKED'
    assert not report['checks']['v89_history_present']

def test_uncommitted_production_edit_is_blocked(working_clone):
    (working_clone/'app/main.py').write_text('# tampered\n')
    report = inspect(working_clone)
    assert report['status'] == 'BLOCKED'
    assert not report['checks']['no_uncommitted_tracked_changes']

def test_committed_production_edit_is_blocked(working_clone):
    (working_clone/'app/main.py').write_text('# tampered\n')
    command(working_clone, 'add', 'app/main.py')
    command(working_clone, 'commit','-qm','unapproved production change')
    report = inspect(working_clone)
    assert report['status'] == 'BLOCKED'
    assert not report['checks']['production_entrypoint_unchanged']
    assert not report['checks']['only_review_allowlisted_changes']

def test_unrelated_committed_file_is_blocked(working_clone):
    (working_clone/'unsafe_extra.py').write_text('x=1\n')
    command(working_clone, 'add','unsafe_extra.py')
    command(working_clone, 'commit','-qm','unapproved unrelated change')
    report = inspect(working_clone)
    assert report['status'] == 'BLOCKED'
    assert not report['checks']['only_review_allowlisted_changes']

def test_staged_edit_is_blocked(working_clone):
    (working_clone/'app/pg_messenger_bridge_v90.py').write_text('broken\n')
    command(working_clone, 'add','app/pg_messenger_bridge_v90.py')
    report = inspect(working_clone)
    assert report['status'] == 'BLOCKED'
    assert not report['checks']['no_staged_uncommitted_changes']
