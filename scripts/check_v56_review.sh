#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null || { echo 'NOT RUN: sha256sum absent'; exit 2; }
sha256sum --check --status V5_6_PG_GATE_SHA256.txt || { echo 'FAIL: V5.6 source integrity'; exit 1; }
python3 -m compileall -q app scripts tests
bash -n scripts/check_v56_review.sh scripts/run_pg17_codespaces_v56.sh
bash scripts/check_v55_review.sh
python3 -m pytest -q -p no:cacheprovider tests/test_pg_edit_history_v56.py tests/test_v56_runner.py
printf 'PASS: V5.6 source integrity, prior regression, edit-chain failure injection (live PG17 separate)\n'
