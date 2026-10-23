#!/usr/bin/env bash
# Additional V3.5 FastAPI/PG17 gate. Disallow tampered review lab sources.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: sha256sum missing' >&2; exit 2; }
[[ -f V3_5_PG_GATE_SHA256.txt ]] || { echo 'NOT RUN: V3.5 manifest missing' >&2; exit 2; }
sha256sum --check --status V3_5_PG_GATE_SHA256.txt || { echo 'FAIL: V3.5 source hash mismatch' >&2; exit 1; }
export JW_PG_LAB_V35=ONLY_DISPOSABLE_LAB
exec bash scripts/run_pg17_codespaces_v28.sh
