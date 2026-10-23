"""Fail-closed local V9.0 review checks. No database or network side effects.

Only checks isolated review-candidate files; historical V8.9 565-test gate
remains NOT RUN and cannot be promoted to PASS by this script.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY_FILES = [
    'pg_messenger_bridge_v90.py', 'pg_messenger_realtime_v90.py',
    'migration_integrity_v90.py', 'test_pg_messenger_bridge_v90.py',
    'test_pg_messenger_realtime_v90.py', 'test_migration_integrity_v90.py',
    'test_commit_order_model_v90.py',
]
TESTS_PY = [n for n in PY_FILES if n.startswith('test_')]
TESTS_JS = ['test_stage_ui_race_v90.cjs', 'test_ui_submission_integrity_v90.cjs', 'test_client_edit_order_v90.cjs', 'test_ws_cursor_guard_v90.cjs']


def run(args: list[str], cwd: Path) -> dict[str, object]:
    try:
        r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=60)
        return {'status': 'PASS' if r.returncode == 0 else 'FAIL', 'exit': r.returncode,
                'stdout': r.stdout[-8000:], 'stderr': r.stderr[-4000:]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'status': 'BLOCKED', 'error': str(exc)}


def main() -> int:
    proof: dict[str, object] = {'suite': 'JARVIS_WORKS_V90_STAGING_ISOLATED',
                                'live_database': 'NOT RUN',
                                'browser_e2e': 'NOT RUN',
                                'v89_565_regression': 'NOT RUN'}
    missing = sorted(n for n in [*PY_FILES, *TESTS_JS, 'messenger_stage_v90.html'] if not (ROOT / n).is_file())
    if missing:
        print(json.dumps({'status': 'BLOCKED', 'missing': missing}, ensure_ascii=False))
        return 2
    proof['python_compile'] = run([sys.executable, '-m', 'compileall', '-q', *PY_FILES], ROOT)
    proof['python_pytest'] = run([sys.executable, '-m', 'pytest', '-q', *TESTS_PY], ROOT)
    proof['node_contract_tests'] = run(['node', '--test', *TESTS_JS], ROOT)
    html = (ROOT / 'messenger_stage_v90.html').read_text(encoding='utf-8')
    match = re.search(r'<script>([\s\S]*?)</script>', html)
    if not match:
        proof['browser_js_syntax'] = {'status': 'FAIL', 'reason': 'No inline script found'}
    else:
        with tempfile.TemporaryDirectory() as temp:
            js = Path(temp) / 'messenger.js'
            js.write_text(match.group(1), encoding='utf-8')
            proof['browser_js_syntax'] = run(['node', '--check', str(js)], ROOT)
    py = proof['python_pytest']
    node = proof['node_contract_tests']
    n_py = re.search(r'\b(\d+) passed\b', str(py.get('stdout', '')))
    n_node = re.search(r'(?m)^# tests (\d+)\s*$', str(node.get('stdout', '')))
    n_node_ok = re.search(r'(?m)^# pass (\d+)\s*$', str(node.get('stdout', '')))
    proof['observed_cases'] = {
        'python': int(n_py.group(1)) if n_py else None,
        'node': int(n_node_ok.group(1)) if n_node_ok and n_node and n_node_ok.group(1) == n_node.group(1) else None,
    }
    stages = ['python_compile', 'python_pytest', 'node_contract_tests', 'browser_js_syntax']
    ok = all(proof[key]['status'] == 'PASS' for key in stages)
    ok = ok and proof['observed_cases']['python'] is not None and proof['observed_cases']['node'] is not None
    proof['status'] = 'PASS' if ok else 'FAIL'
    proof['scope'] = 'LOCAL_STAGED_ONLY'
    print(json.dumps(proof, ensure_ascii=False, indent=2))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
