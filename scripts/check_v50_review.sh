#!/usr/bin/env bash
# V5.0 strict review source integrity and all historical regression checks.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: sha256sum unavailable' >&2; exit 2; }
sha256sum --check --status V5_0_PG_GATE_SHA256.txt || { echo 'FAIL: V5.0 file hash mismatch' >&2; exit 1; }
python3 -m compileall -q app scripts tests
bash -n scripts/run_pg17_codespaces_v50.sh
sha256sum --check --status V4_9_PG_GATE_SHA256.txt || { echo 'FAIL: V4.9 historical manifest mismatch' >&2; exit 1; }
bash scripts/check_v49_review.sh
printf 'PASS: V5.0 source integrity and strict historical regression; live PG17 separate\n'
