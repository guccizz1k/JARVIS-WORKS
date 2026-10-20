#!/usr/bin/env bash
# V4.7 manifest + original complete V4.6 zero-SKIP regression, no cutover.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: sha256sum unavailable' >&2; exit 2; }
sha256sum --check --status V4_7_PG_GATE_SHA256.txt || { echo 'FAIL: V4.7 review file integrity' >&2; exit 1; }
python3 -m compileall -q app scripts tests
bash -n scripts/run_pg17_codespaces_v47.sh
bash scripts/check_v46_review.sh
printf 'PASS: V4.7 file integrity and historical strict full regression (PG17 separate)\n'
