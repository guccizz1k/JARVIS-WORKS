#!/usr/bin/env sh
set -eu
export DEMO_SEED=1
export JW_INSECURE_LOCAL_DEV=1
: "${JW_ENV:=development}"
export JW_ENV
exec python -m uvicorn app.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
