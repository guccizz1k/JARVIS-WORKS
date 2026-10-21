#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null || { echo 'NOT RUN: sha256sum missing'; exit 2; }
sha256sum --check --status V5_3_PG_GATE_SHA256.txt || { echo 'FAIL: V5.3 integrity mismatch'; exit 1; }
python3 -m compileall -q app scripts tests
bash -n scripts/check_v53_review.sh scripts/run_pg17_codespaces_v53.sh
bash scripts/check_v52_review.sh
printf 'PASS: V5.3 isolated source digest and full historical checks; PG17 separate\n'
