#!/usr/bin/env bash
# V4.2: disposable-only transactional logical mirror restore and integrity.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: sha256sum missing' >&2; exit 2; }
[[ -f V4_2_PG_GATE_SHA256.txt ]] || { echo 'NOT RUN: V4.2 source manifest unavailable' >&2; exit 2; }
sha256sum --check --status V4_2_PG_GATE_SHA256.txt || { echo 'FAIL: V4.2 source integrity failed' >&2; exit 1; }
export JW_PG_LAB_V42=ONLY_DISPOSABLE_LAB
exec bash scripts/run_pg17_codespaces_v41.sh
