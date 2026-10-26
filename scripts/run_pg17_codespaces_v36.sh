#!/usr/bin/env bash
# V3.6: synthetic shadow migration + atomic rollback on disposable PG17 only.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: checksum utility missing' >&2; exit 2; }
[[ -f V3_6_PG_GATE_SHA256.txt ]] || { echo 'NOT RUN: V3.6 source manifest missing' >&2; exit 2; }
sha256sum --check --status V3_6_PG_GATE_SHA256.txt || { echo 'FAIL: V3.6 source hash mismatch' >&2; exit 1; }
export JW_PG_LAB_V36=ONLY_DISPOSABLE_LAB
exec bash scripts/run_pg17_codespaces_v35.sh
