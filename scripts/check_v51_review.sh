#!/usr/bin/env bash
# V5.1 application write-path outbox integration review; no production writes.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: sha256sum missing' >&2; exit 2; }
sha256sum --check --status V5_1_PG_GATE_SHA256.txt || { echo 'FAIL: V5.1 source hash mismatch' >&2; exit 1; }
python3 -m compileall -q app scripts tests
bash -n scripts/check_v51_review.sh scripts/run_pg17_codespaces_v51.sh
bash scripts/check_v50_review.sh
printf 'PASS: V5.1 actual SQLite B2B messenger outbox integration and historical full regression (PG17 separate)\n'
