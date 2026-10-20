#!/usr/bin/env bash
# V4.4 immutable baseline manifests + complete local regression.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[[ -f V4_4_PG_GATE_SHA256.txt ]] || { echo 'NOT RUN: V4.4 manifest missing' >&2; exit 2; }
sha256sum --check --status V4_4_PG_GATE_SHA256.txt || { echo 'FAIL: V4.4 source integrity mismatch' >&2; exit 1; }
bash -n scripts/run_pg17_codespaces_v44.sh
bash scripts/check_v43_review.sh
printf 'PASS: V4.4 source integrity and full regression (actual PG17 separate)\n'
