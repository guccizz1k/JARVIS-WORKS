#!/usr/bin/env bash
# V4.4 immutable baseline manifests + complete local regression.
# The V4.3 pytest suite has a native-Node-only stdin test: when Codespaces
# has Docker rather than a host Node binary, supply the same restricted Docker
# Node tool to BOTH the JS syntax preflight and that pytest test.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[[ -f V4_4_PG_GATE_SHA256.txt ]] || { echo 'NOT RUN: V4.4 manifest missing' >&2; exit 2; }
sha256sum --check --status V4_4_PG_GATE_SHA256.txt || { echo 'FAIL: V4.4 source integrity mismatch' >&2; exit 1; }
bash -n scripts/run_pg17_codespaces_v44.sh

NODE_SHIM_DIR=""
cleanup_node_shim() {
  local result=$?
  trap - EXIT
  if [[ -n "$NODE_SHIM_DIR" ]]; then
    if ! rm -rf -- "$NODE_SHIM_DIR"; then
      echo 'FAIL: temporary Node shim cleanup failed' >&2
      result=1
    fi
  fi
  exit "$result"
}
trap cleanup_node_shim EXIT

# Never silently SKIP the positive/negative Node stdin syntax test when only
# the restricted Docker Node runtime is present. Preserve V4.3 hash manifests.
if ! command -v node >/dev/null 2>&1; then
  command -v docker >/dev/null 2>&1 || { echo 'NOT RUN: Node and Docker missing' >&2; exit 2; }
  docker info >/dev/null 2>&1 || { echo 'NOT RUN: Docker daemon unavailable' >&2; exit 2; }
  if ! docker image inspect node:22-alpine >/dev/null 2>&1; then
    docker pull node:22-alpine >/dev/null || { echo 'NOT RUN: Node image unavailable' >&2; exit 2; }
  fi
  NODE_SHIM_DIR="$(mktemp -d "${TMPDIR:-/tmp}/jw-v44-node.XXXXXXXX")" || { echo 'NOT RUN: Node test tool allocation failed' >&2; exit 2; }
  chmod 700 "$NODE_SHIM_DIR"
  mkdir "$NODE_SHIM_DIR/bin"
  cat > "$NODE_SHIM_DIR/bin/node" <<'SHIM'
#!/usr/bin/env bash
set -Eeuo pipefail
# Only the two syntax-check interfaces used by the original preflight/tests.
[[ $# -eq 2 && "$1" == '--check' ]] || { echo 'FAIL: unsupported isolated Node invocation' >&2; exit 2; }
case "$2" in
  -)
    if ! docker run --rm -i --network none --read-only --cap-drop ALL \
      --security-opt no-new-privileges --pids-limit 128 --memory 256m \
      node:22-alpine node --check -; then
      echo "FAIL: Docker Node syntax test failed" >&2
      exit 1
    fi
    ;;
  app/static/app.js)
    [[ -f "${JW_V44_NODE_JS_FILE:-}" && ! -L "$JW_V44_NODE_JS_FILE" ]] || { echo 'FAIL: frontend syntax input missing' >&2; exit 1; }
    if ! docker run --rm -i --network none --read-only --cap-drop ALL \
      --security-opt no-new-privileges --pids-limit 128 --memory 256m \
      node:22-alpine node --check -; then
      echo "FAIL: Docker Node syntax test failed" >&2
      exit 1
    fi < "$JW_V44_NODE_JS_FILE"
    ;;
  *) echo 'FAIL: isolated Node input is not whitelisted' >&2; exit 2 ;;
esac
SHIM
  chmod 700 "$NODE_SHIM_DIR/bin/node"
  export JW_V44_NODE_JS_FILE="$ROOT/app/static/app.js"
  export PATH="$NODE_SHIM_DIR/bin:$PATH"
fi

bash scripts/check_v43_review.sh
printf 'PASS: V4.4 source integrity and full regression (actual PG17 separate)\n'
