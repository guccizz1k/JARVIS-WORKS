#!/usr/bin/env bash
# V3.8 extends the disposal-only PG17 pipeline with FastAPI typed read security.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: sha256sum unavailable' >&2; exit 2; }
[[ -f V3_8_PG_GATE_SHA256.txt ]] || { echo 'NOT RUN: V3.8 source manifest absent' >&2; exit 2; }
sha256sum --check --status V3_8_PG_GATE_SHA256.txt || { echo 'FAIL: V3.8 file integrity failed' >&2; exit 1; }
export JW_PG_LAB_V38=ONLY_DISPOSABLE_LAB
exec bash scripts/run_pg17_codespaces_v37.sh
