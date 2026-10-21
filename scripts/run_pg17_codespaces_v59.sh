#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
# V5.8 signed recipient PostgreSQL 17 tests must succeed first.
bash scripts/run_pg17_codespaces_v58.sh
# Actual FastAPI route tests are a separate mandatory gate, not a PG substitute.
PYTHONPATH=. python -m pytest -q -rs tests/test_read_actor_journal_v59.py tests/test_v59_web_api.py
printf '%s\n' 'PASS: V5.9 actual FastAPI read-actor persistence + historical PG17 gate; new PG cursor relay NOT IMPLEMENTED'
printf '%s\n' 'BLOCKED: historical unattributed reads, live PG migration and production cutover NOT AUTHORIZED'
