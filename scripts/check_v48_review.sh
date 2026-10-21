#!/usr/bin/env bash
# V4.8: new manifest + untouched prior V4.7 strict entire repository tests.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: sha256sum unavailable' >&2; exit 2; }
sha256sum --check --status V4_8_PG_GATE_SHA256.txt || { echo 'FAIL: V4.8 file hash mismatch' >&2; exit 1; }
python3 -m compileall -q app scripts tests
bash -n scripts/run_pg17_codespaces_v48.sh
bash scripts/check_v47_review.sh
printf 'PASS: V4.8 integrity and strict historical regression (live PG17 separate)\n'
