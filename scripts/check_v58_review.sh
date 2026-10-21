#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null || { echo 'NOT RUN: sha256sum'; exit 2; }
sha256sum --check --status V5_8_PG_GATE_SHA256.txt || { echo 'FAIL: V5.8 integrity'; exit 1; }
python3 -m compileall -q app scripts tests
bash -n scripts/check_v58_review.sh scripts/run_pg17_codespaces_v58.sh
bash scripts/check_v57_review.sh
python3 -m pytest -q -p no:cacheprovider tests/test_pg_receipt_identity_v58.py tests/test_v58_runner.py
printf 'PASS: V5.8 new source, historical regression and negative-receipt tests (PG17 separate)\n'
