#!/usr/bin/env bash
# V4.6: strict prior full regression + new schema gap unit tests; no cutover.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null || { echo 'NOT RUN: sha256sum unavailable' >&2; exit 2; }
sha256sum --check --status V4_6_PG_GATE_SHA256.txt || { echo 'FAIL: V4.6 sources altered' >&2; exit 1; }
python3 -m compileall -q app scripts tests
bash -n scripts/run_pg17_codespaces_v46.sh
# Existing V4.5 whole-suite test runs with strict no-SKIP enabled.
bash scripts/check_v45_review.sh
printf 'PASS: V4.6 source integrity and strict full regression (PG17 separate)\n'
