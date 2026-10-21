#!/usr/bin/env bash
# V4.9 adds no unverified PG migration, and inherits V4.8 real PG17 gate.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
sha256sum --check --status V4_9_PG_GATE_SHA256.txt || { echo 'FAIL: V4.9 source integrity' >&2; exit 1; }
bash scripts/run_pg17_codespaces_v48.sh
printf 'PASS: V4.9 JW mobile wrapper with complete V4.8 PostgreSQL 17 integration (cutover DENIED)\n'
