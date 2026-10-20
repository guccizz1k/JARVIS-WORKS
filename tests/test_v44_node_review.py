"""V4.4: the Python Codespaces Node check must not SKIP with Docker available.

No real Docker daemon, images, package installation, or PostgreSQL required:
these tests exercise the review Bash shim against deterministic fake executables.
The actual Codespaces/Docker validation must still be separately observed.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest


def _run(tmp_path, mode):
    root=tmp_path/'checkout with spaces'
    (root/'scripts').mkdir(parents=True)
    (root/'app/static').mkdir(parents=True)
    (root/'scripts/check_v44_review.sh').write_bytes(Path('scripts/check_v44_review.sh').read_bytes())
    (root/'scripts/run_pg17_codespaces_v44.sh').write_text('#!/bin/bash\n')
    (root/'V4_4_PG_GATE_SHA256.txt').write_text('checked-by-mock\n')
    (root/'app/static/app.js').write_text('let count = 1;\n' if mode!='bad_syntax' else 'let = ;\n')
    (root/'scripts/check_v43_review.sh').write_text('''#!/usr/bin/env bash
set -Eeuo pipefail
node --check app/static/app.js
node --check - <<< 'let count = 1;'
if node --check - <<< 'let = ;'; then
  echo 'FAIL: negative syntax accepted' >&2; exit 1
fi
printf 'PASS: synthetic V4.3 JavaScript syntax fixtures\\n'
''')
    fake=tmp_path/'bin'
    fake.mkdir()
    # Do not put real /usr/bin or the host Node binary on PATH.
    for tool in ('env','bash','dirname','mktemp','mkdir','chmod','rm','cat'):
        real=shutil.which(tool)
        assert real,tool
        (fake/tool).symlink_to(real)
    for tool,script in {
        'sha256sum':'#!/bin/sh\nexit 0\n',
        'docker':'''#!/bin/sh
case "$1" in
  info) [ "$JW_FAKE_DOCKER" != 'daemon_missing' ]; exit $? ;;
  image) exit 0 ;;
  run)
    [ "$JW_FAKE_DOCKER" != 'engine_failure' ] || exit 95
    input="$(cat)"
    case "$input" in
      'let count = 1;') exit 0 ;;
      'let = ;') exit 1 ;;
    esac
    exit 95 ;;
esac
exit 95
''',
    }.items():
        (fake/tool).write_text(script)
        (fake/tool).chmod(0o755)
    env={**os.environ,'PATH':str(fake),'JW_FAKE_DOCKER':mode,'TMPDIR':str(tmp_path)}
    assert shutil.which('node', path=env['PATH']) is None
    completed=subprocess.run(['/bin/bash',str(root/'scripts/check_v44_review.sh')],cwd=root,
                             env=env,capture_output=True,text=True,timeout=20)
    assert not list(tmp_path.glob('jw-v44-node.*')),'Temporary Node runner was not cleaned'
    return completed


@pytest.mark.parametrize('mode,expected', [
    ('success',0),('daemon_missing',2),('engine_failure',1),('bad_syntax',1)
])
def test_no_host_node_fallback_does_not_skip(tmp_path,mode,expected):
    result=_run(tmp_path,mode)
    assert result.returncode==expected,(result.stdout,result.stderr)
    assert ('PASS: V4.4 source integrity' in result.stdout) == (expected==0)
    if mode!='success':
        assert 'SKIP' not in result.stdout


def test_review_shim_never_changes_old_manifest_or_uses_bind_mount():
    src=Path('scripts/check_v44_review.sh').read_text()
    assert 'bash scripts/check_v43_review.sh' in src
    assert 'node:22-alpine node --check -' in src
    assert '--network none --read-only --cap-drop ALL' in src
    assert '--security-opt no-new-privileges' in src
    assert 'JW_V44_NODE_JS_FILE' in src
    assert '--mount' not in src and 'docker -v' not in src
    assert 'trap cleanup_node_shim EXIT' in src
    assert 'V4_3_PG_GATE_SHA256.txt' not in src
    assert 'pytest.skip' not in src
