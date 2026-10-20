#!/usr/bin/env bash
# V4.0 opt-in, disposable-only Psycopg 3 write/retry/concurrency lab.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: sha256sum unavailable' >&2; exit 2; }
[[ -f V4_0_PG_GATE_SHA256.txt ]] || { echo 'NOT RUN: V4.0 manifest unavailable' >&2; exit 2; }
sha256sum --check --status V4_0_PG_GATE_SHA256.txt || { echo 'FAIL: V4.0 source integrity mismatch' >&2; exit 1; }
export JW_PG_LAB_V40=ONLY_DISPOSABLE_LAB
exec bash scripts/run_pg17_codespaces_v39.sh
