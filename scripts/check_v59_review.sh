#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
# V5.8 source hash manifests belong to V5.8 source. They are verified on the
# immutable ancestor in run_pg17_codespaces_v59.sh, never against edited V5.9.
sha256sum -c V5_9_SOURCE_SHA256.txt
PYTHONPATH=. python3 -m compileall -q app/pg_read_actor_journal_v59.py tests/test_read_actor_journal_v59.py tests/test_v59_web_api.py tests/test_v59_runner.py
PYTHONPATH=. python3 -m pytest -q -rs tests/test_read_actor_journal_v59.py tests/test_v59_web_api.py tests/test_v59_runner.py
node --check app/static/app.js
printf '%s\n' 'PASS: V5.9 source integrity and actual authenticated FastAPI HTTP read-cursor regression'
