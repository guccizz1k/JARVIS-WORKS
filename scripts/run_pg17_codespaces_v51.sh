#!/usr/bin/env bash
# V5.1 adds NO operational PG writer. Reuse strict V5.0 PG17 chain.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
sha256sum --check --status V5_1_PG_GATE_SHA256.txt || { echo 'FAIL: V5.1 hash mismatch' >&2; exit 1; }
bash scripts/run_pg17_codespaces_v50.sh
printf 'PASS: V5.1 lab-only SQLite transactional outbox regression + historical PG17 gates; PG relay and cutover NOT IMPLEMENTED\n'
