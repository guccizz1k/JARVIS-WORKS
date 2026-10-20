#!/usr/bin/env bash
# Local, non-network review regression only. No live PG instance is launched.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v python3 >/dev/null 2>&1 || { echo 'NOT RUN: Python missing' >&2; exit 2; }
command -v node >/dev/null 2>&1 || { echo 'NOT RUN: Node missing' >&2; exit 2; }
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: sha256sum missing' >&2; exit 2; }
for version in V2_8 V3_5 V3_6 V3_7 V3_8 V3_9 V4_0 V4_1 V4_2 V4_3; do
  sha256sum --check --status "${version}_PG_GATE_SHA256.txt" || { echo 'FAIL: integrity gate failed' >&2; exit 1; }
done
python3 -m compileall -q app scripts tests
bash -n scripts/run_pg17_codespaces_v43.sh
node --check app/static/app.js
PYTHONPATH=. python3 -m pytest -q --disable-warnings
printf 'PASS: local full-repository V4.3 syntax, UI script and regression (not live PostgreSQL)\n'
