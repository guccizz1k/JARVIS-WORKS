#!/usr/bin/env bash
# V5.4 isolated source snapshot regression; PG17 source-ref relay is reused, not rewritten.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
JW_ENV_SAFE="${JW_ENV:-}"
[[ "${JW_ENV_SAFE,,}" != production ]] || { echo 'NOT RUN: production refused'; exit 2; }
export JW_PG_OUTBOX_V51=ONLY_DISPOSABLE_LAB
export JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE
export JW_PG_LAB_V54=ONLY_DISPOSABLE_LAB
python3 -m scripts.test_mutation_snapshot_v54 || { echo 'FAIL: V5.4 source snapshot rehearsal'; exit 1; }
bash scripts/run_pg17_codespaces_v53.sh || { echo 'FAIL: V5.3 historical PG17 gate'; exit 1; }
printf 'PASS: V5.4 source snapshots and historical PG17 gates; NEW PG payload relay NOT IMPLEMENTED; cutover DENIED\n'
