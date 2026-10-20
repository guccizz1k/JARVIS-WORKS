"""Fail-closed source manifest builder for isolated V4.3 additive files only.

No edits to old source or V2.8 through V4.2 SHA256 historical manifests.
Call manually once from a clean review/v42-based checkout with new V4.3 files.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess

BASE_COMMIT='8e6c56bd35da5eaa698a2f12081c11ac115eae94'
CHAIN=('V2_8','V3_5','V3_6','V3_7','V3_8','V3_9','V4_0','V4_1','V4_2')
FILES=(
  'app/pg_web_bridge_v43.py',
  'scripts/test_postgres_web_v43.py',
  'scripts/run_postgres_isolation_ci_v43.py',
  'scripts/run_pg17_codespaces_v43.sh',
  'scripts/check_v43_review.sh',
  'scripts/build_v43_manifest.py',
  'tests/test_pg_web_bridge_v43.py',
  'tests/test_v43_manifest_and_runner.py',
  'docs/V4_3_WEB_PG17_REVIEW.md',
  'scripts/run_postgres_isolation_ci_v28.py',
  'V4_2_PG_GATE_SHA256.txt',
)
OUT=Path('V4_3_PG_GATE_SHA256.txt')


def _git(*args: str) -> str:
    return subprocess.check_output(('git',*args),text=True,stderr=subprocess.DEVNULL).strip()


def build() -> int:
    try:
        if (_git('rev-parse','HEAD') != BASE_COMMIT or
                _git('branch','--show-current') in ('main','master') or
                not Path('app/main.py').is_file() or
                OUT.exists()):
            raise ValueError('Refuse unsafe/non-review project')
        # Keep source history immutable and refuse dirty *tracked* changes.
        if _git('status','--porcelain','--untracked-files=no'):
            raise ValueError('Tracked review checkout is not clean')
        for version in CHAIN:
            file=Path(version+'_PG_GATE_SHA256.txt')
            if (not file.is_file() or subprocess.call(
                    ('sha256sum','--check','--status',str(file)),
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)):
                raise ValueError('Historical live gate differs from baseline')
        if any(not Path(name).is_file() for name in FILES):
            raise ValueError('V4.3 additive candidate incomplete')
        manifest=''.join(hashlib.sha256(Path(name).read_bytes()).hexdigest()
                         +'  '+name+'\n' for name in FILES)
        OUT.open('x', encoding='ascii').write(manifest)
        result=subprocess.call(('sha256sum','--check','--status',str(OUT)),
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if result:
            OUT.unlink(missing_ok=True)
            raise ValueError('Manifest self-verification failed')
    except (OSError,ValueError,subprocess.CalledProcessError) as exc:
        print('BLOCKED: V4.3 manifest creation preflight failed; no existing files changed')
        return 2
    print('PASS: V4.3 additive SHA256 manifest created; V2.8–V4.2 preserved')
    return 0


if __name__=='__main__':
    raise SystemExit(build())
