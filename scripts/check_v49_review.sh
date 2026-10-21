#!/usr/bin/env bash
# V4.9 is a verified mobile orchestration harness; reuses V4.8 PG17 gates.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: missing sha256sum' >&2; exit 2; }
sha256sum --check --status V4_9_PG_GATE_SHA256.txt || { echo 'FAIL: V4.9 changed code' >&2; exit 1; }
bash -n scripts/jw.sh scripts/install_jw.sh scripts/run_pg17_codespaces_v49.sh
python3 -m compileall -q tests
bash scripts/check_v48_review.sh
printf 'PASS: V4.9 JW mobile source integrity and full historical regression (PG17 separate)\n'
