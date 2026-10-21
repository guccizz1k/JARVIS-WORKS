#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null || { echo 'NOT RUN: sha256sum missing'; exit 2; }
sha256sum --check --status V5_5_PG_GATE_SHA256.txt || { echo 'FAIL: V5.5 source integrity mismatch'; exit 1; }
python3 -m compileall -q app scripts tests
bash -n scripts/check_v55_review.sh scripts/run_pg17_codespaces_v55.sh
bash scripts/check_v54_review.sh
printf 'PASS: V5.5 source integrity + historical regression (PG17 separate)\n'
