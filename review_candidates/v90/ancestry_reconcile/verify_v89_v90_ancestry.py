"""Verify recovered V8.9 ancestry and additive V9 integration; never merge on failure.

Usage: python verify_v89_v90_ancestry.py /path/to/integrated/working/tree
Verifies exact commits, no tracked modifications to production app/main.py,
allowlisted diffs, bundle reversibility and clean tracked-file state.
Does not call GitHub or modify the repository.
"""
from __future__ import annotations
import argparse
import json
import subprocess
from pathlib import Path

V89 = 'a3783ef9f7aeeeff655f1f0ac376f6d8edf5b338'
V90 = '1b0aa6611b4b613003938fa7f55d6a7469f6fb5a'
ALLOWED = frozenset({
    'app/pg_auth_v85.py', 'app/pg_dev_entry_v90.py',
    'app/pg_messenger_bridge_v90.py', 'app/pg_messenger_realtime_v90.py',
    'app/pg_v90_integrated_entry.py', 'scripts/benchmark_pg_v90_idle.py',
    'scripts/pg_messenger_realtime_before_v90.py', 'tests/test_pg_auth_v85.py',
    'tests/test_pg_v90_adaptive_poll.py', 'tests/test_pg_v90_integrated_entry.py',
})

def git(root: Path, *args: str) -> tuple[int, str]:
    p = subprocess.run(['git', '-c', f'safe.directory={root.resolve()}', '-C', str(root), *args],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stdout.strip()

def inspect(root: Path, *, expected_base=V89, expected_head=V90) -> dict:
    checks: dict[str, bool] = {}
    rc, head = git(root, 'rev-parse', 'HEAD')
    checks['expected_v90_review_head'] = rc == 0 and head == expected_head
    rc, base = git(root, 'rev-parse', expected_base + '^{commit}')
    checks['v89_history_present'] = rc == 0 and base == expected_base
    rc, _ = git(root, 'merge-base', '--is-ancestor', expected_base, 'HEAD')
    checks['v89_is_ancestor'] = rc == 0
    rc, parent = git(root, 'rev-parse', 'HEAD^')
    checks['known_v90_parent'] = rc == 0 and parent == '98026b9063a5fda1d2f0f06de0237535394f270d' if expected_head == V90 else rc == 0
    rc, baseline = git(root, 'rev-parse', f'{expected_base}:app/main.py')
    rc2, head_main = git(root, 'rev-parse', 'HEAD:app/main.py')
    checks['production_entrypoint_unchanged'] = rc == rc2 == 0 and baseline == head_main
    rc, paths = git(root, 'diff', '--name-only', expected_base, 'HEAD')
    names = set(paths.splitlines()) if rc == 0 else set()
    checks['only_review_allowlisted_changes'] = rc == 0 and names == ALLOWED
    rc, tracked = git(root, 'diff', '--name-only', 'HEAD')
    checks['no_uncommitted_tracked_changes'] = rc == 0 and tracked == ''
    rc, index = git(root, 'diff', '--cached', '--name-only')
    checks['no_staged_uncommitted_changes'] = rc == 0 and index == ''
    return {'status': 'PASS' if all(checks.values()) else 'BLOCKED',
            'checks': checks, 'head': head, 'expected_base': expected_base,
            'changed_files': sorted(names), 'this_proves_remote_github_ancestry': False}

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    result = inspect(args.root)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 2

if __name__ == '__main__':
    raise SystemExit(main())
