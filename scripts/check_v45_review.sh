#!/usr/bin/env bash
# V4.5 integrity and complete regression. V4.4 original remains unmodified.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null || { echo 'NOT RUN: sha256sum unavailable' >&2; exit 2; }
[[ -f V4_5_PG_GATE_SHA256.txt ]] || { echo 'NOT RUN: V4.5 manifest missing' >&2; exit 2; }
sha256sum --check --status V4_5_PG_GATE_SHA256.txt || { echo 'FAIL: V4.5 source integrity mismatch' >&2; exit 1; }
bash -n scripts/run_pg17_codespaces_v45.sh
python3 -m compileall -q app scripts tests
bash scripts/check_v44_review.sh
printf 'PASS: V4.5 source integrity and full regression (real PG17 separate)\n'
