#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
sha256sum --check --status V5_7_PG_GATE_SHA256.txt || { echo 'FAIL: V5.7 integrity'; exit 1; }
python3 -m compileall -q app scripts tests
bash -n scripts/run_pg17_codespaces_v57.sh scripts/check_v57_review.sh
bash scripts/check_v56_review.sh
python3 -m pytest -q -p no:cacheprovider tests/test_pg_attachment_payload_v57.py tests/test_v57_runner.py
printf 'PASS: V5.7 source integrity, full historical regression and attachment faults (live PG17 separate)\n'
