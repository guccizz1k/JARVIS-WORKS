#!/usr/bin/env bash
# Local review regression only. If Node is absent, a restricted Docker Node
# image is used for JS syntax validation; a one-time image pull may be needed.
# No live PostgreSQL instance is launched by this script.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v python3 >/dev/null 2>&1 || { echo 'NOT RUN: Python missing' >&2; exit 2; }
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: sha256sum missing' >&2; exit 2; }
for version in V2_8 V3_5 V3_6 V3_7 V3_8 V3_9 V4_0 V4_1 V4_2 V4_3; do
  sha256sum --check --status "${version}_PG_GATE_SHA256.txt" || { echo 'FAIL: integrity gate failed' >&2; exit 1; }
done
python3 -m compileall -q app scripts tests
bash -n scripts/run_pg17_codespaces_v43.sh
# A missing or replaced frontend asset must never be silently accepted.
[[ -f "$ROOT/app/static/app.js" && ! -L "$ROOT/app/static/app.js" ]] || { echo 'NOT RUN: expected JavaScript source missing or symlinked' >&2; exit 2; }
# Node is not a default dependency of the Python 3.12 Codespaces image.
# Never skip JavaScript verification: use a read-only, network-disabled,
# capability-free disposable Node container only when the host lacks Node.
if command -v node >/dev/null 2>&1; then
  node --check app/static/app.js
else
  command -v docker >/dev/null 2>&1 || { echo 'NOT RUN: Node and Docker unavailable for JS syntax check' >&2; exit 2; }
  docker info >/dev/null 2>&1 || { echo 'NOT RUN: Docker daemon unavailable for Node fallback' >&2; exit 2; }
  if ! docker image inspect node:22-alpine >/dev/null 2>&1; then
    docker pull node:22-alpine >/dev/null || { echo 'NOT RUN: verified Node image unavailable' >&2; exit 2; }
  fi
  # DinD's daemon may not share the Codespaces /tmp worktree filesystem.
  # Node reads syntax-only JS from stdin; no host bind mount or shared path.
  if ! docker run --rm -i --network none --read-only --cap-drop ALL \
      --security-opt no-new-privileges --pids-limit 128 --memory 256m \
      node:22-alpine node --check - < "$ROOT/app/static/app.js"; then
    echo 'FAIL: isolated Node syntax check failed' >&2
    exit 1
  fi
fi
PYTHONPATH=. python3 -m pytest -q --disable-warnings
printf 'PASS: local full-repository V4.3 syntax, UI script and regression (not live PostgreSQL)\n'
