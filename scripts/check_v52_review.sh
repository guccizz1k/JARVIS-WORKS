#!/usr/bin/env bash
# V5.2 review: all source, web and historical tests; lab PostgreSQL separate.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: sha256sum missing' >&2; exit 2; }
sha256sum --check --status V5_2_PG_GATE_SHA256.txt || { echo 'FAIL: V5.2 hash mismatch' >&2; exit 1; }
python3 -m compileall -q app scripts tests
bash -n scripts/check_v52_review.sh scripts/run_pg17_codespaces_v52.sh
bash scripts/check_v51_review.sh
printf 'PASS: V5.2 source, replay tests and historical full regression; actual PG17 separate\n'
