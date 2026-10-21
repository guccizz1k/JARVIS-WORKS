#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null || { echo 'NOT RUN: sha256sum unavailable'; exit 2; }
sha256sum --check --status V5_4_PG_GATE_SHA256.txt || { echo 'FAIL: V5.4 source integrity mismatch'; exit 1; }
python3 -m compileall -q app scripts tests
bash -n scripts/check_v54_review.sh scripts/run_pg17_codespaces_v54.sh
bash scripts/check_v53_review.sh
printf 'PASS: V5.4 source, strict historical regression and syntax (actual PG17 separate)\n'
