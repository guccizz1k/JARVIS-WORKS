#!/usr/bin/env bash
# Runs the existing V2.8 isolated test database, plus V3.5 FastAPI/API RLS gate.
set -Eeuo pipefail
export JW_PG_LAB_V35=ONLY_DISPOSABLE_LAB
exec bash "$(dirname "$0")/run_pg17_codespaces_v28.sh"
