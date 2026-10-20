#!/usr/bin/env bash
# V3.9: disposable-only PostgreSQL 17 Psycopg 3 driver lifecycle.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: sha256sum missing' >&2; exit 2; }
[[ -f V3_9_PG_GATE_SHA256.txt ]] || { echo 'NOT RUN: V3.9 manifest missing' >&2; exit 2; }
sha256sum --check --status V3_9_PG_GATE_SHA256.txt || { echo 'FAIL: V3.9 source integrity mismatch' >&2; exit 1; }
export JW_PG_LAB_V39=ONLY_DISPOSABLE_LAB
exec bash scripts/run_pg17_codespaces_v38.sh
