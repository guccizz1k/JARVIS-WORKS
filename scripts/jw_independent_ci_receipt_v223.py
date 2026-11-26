"""Run the two real, synthetic PG17 checks; fail closed on incomplete evidence.
No real backup, DB credentials, provider requests or release authorization.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys

CHECKS = (
    ('pg17_catalog_smoke.py', 'PASS_SYNTHETIC_PG17_CATALOG_MUTATIONS', {'catalog_mutations_passed': 10}),
    ('pg17_authorization_smoke.py', 'PASS_SYNTHETIC_PG17_AUTHZ_AND_RLS', {'authz_mutations_passed': 8, 'rls_runtime_assertions_passed': 16}),
)
ALLOWED_ENV = ('PATH', 'HOME', 'DOCKER_CONFIG', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'XDG_RUNTIME_DIR', 'TMPDIR', 'SYSTEMROOT')

def unique(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError('duplicate field')
        out[k] = v
    return out

def verified(returncode, raw, status, counts):
    if type(returncode) is not int or returncode != 0 or type(raw) is not bytes or not 0 < len(raw) <= 8192:
        return False
    try:
        obj = json.loads(raw.decode('ascii'), object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        return False
    if type(obj) is not dict or set(obj) != {'status', 'cleanup', 'overall', *counts}:
        return False
    return (obj['status'] == status and obj['cleanup'] == 'PASS' and obj['overall'] == 'BLOCKED'
            and all(type(obj[k]) is int and obj[k] == n for k,n in counts.items()))

def run(root=None, executor=subprocess.run):
    root = Path(__file__).resolve().parents[1] if root is None else Path(root)
    receipt = {'synthetic_pg17': 'BLOCKED', 'checks_passed': 0, 'overall': 'BLOCKED', 'real_backup_restore': 'NOT_RUN'}
    env = {k: os.environ[k] for k in ALLOWED_ENV if k in os.environ}
    env['PYTHONNOUSERSITE'] = '1'
    for path, status, counts in CHECKS:
        try:
            p = executor([sys.executable, '-I', str(root/'live_checks'/path)], cwd=root, env=env,
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         timeout=180, check=False)
            if not verified(p.returncode, p.stdout, status, counts):
                receipt['blocker'] = 'INCOMPLETE_OR_FAILED_SYNTHETIC_PG17_RECEIPT'
                return receipt
        except (OSError, subprocess.SubprocessError):
            receipt['blocker'] = 'SYNTHETIC_PG17_PROCESS_FAILED'
            return receipt
        receipt['checks_passed'] += 1
    receipt['synthetic_pg17'] = 'PASS_34_SYNTHETIC_ASSERTIONS'
    return receipt

def main():
    r = run()
    print(json.dumps(r, sort_keys=True))
    return 0 if r['synthetic_pg17'] == 'PASS_34_SYNTHETIC_ASSERTIONS' else 1

if __name__ == '__main__':
    raise SystemExit(main())
