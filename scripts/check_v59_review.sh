#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
# Strictly preserve earlier source verification; no skips or fallback.
bash scripts/check_v58_review.sh
sha256sum -c V5_9_SOURCE_SHA256.txt
PYTHONPATH=. python -m compileall -q app/pg_read_actor_journal_v59.py tests/test_read_actor_journal_v59.py tests/test_v59_web_api.py
PYTHONPATH=. python -m pytest -q -rs tests/test_read_actor_journal_v59.py tests/test_v59_web_api.py
node --check app/static/app.js
printf '%s\n' 'PASS: V5.9 source, actual web HTTP integration and historical regression'
