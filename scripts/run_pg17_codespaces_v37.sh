#!/usr/bin/env bash
# V3.7: disposable PG17 operational-shape compatibility and RLS proof only.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: sha256sum unavailable' >&2; exit 2; }
[[ -f V3_7_PG_GATE_SHA256.txt ]] || { echo 'NOT RUN: V3.7 source manifest missing' >&2; exit 2; }
sha256sum --check --status V3_7_PG_GATE_SHA256.txt || { echo 'FAIL: V3.7 source integrity check failed' >&2; exit 1; }
export JW_PG_LAB_V37=ONLY_DISPOSABLE_LAB
exec bash scripts/run_pg17_codespaces_v36.sh
