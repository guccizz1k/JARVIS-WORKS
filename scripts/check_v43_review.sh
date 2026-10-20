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
# The full repository has PDF test fixtures that construct PDFs with ReportLab.
# ReportLab is a test-only dependency; the Python devcontainer may not have it
# even when the application/pytest packages were installed earlier.
# Keep any missing dependency installation confined to a temporary venv.
TEST_PYTHON=python3
TEST_WORK=""
cleanup_test_env() {
  if [[ -n "$TEST_WORK" ]]; then
    rm -rf -- "$TEST_WORK" || { echo 'FAIL: temporary test environment cleanup failed' >&2; return 1; }
  fi
}
trap cleanup_test_env EXIT
if ! python3 -c 'from reportlab.pdfgen import canvas' >/dev/null 2>&1; then
  [[ -f requirements-dev.txt ]] || { echo 'NOT RUN: development dependency manifest missing' >&2; exit 2; }
  TEST_WORK="$(mktemp -d "${TMPDIR:-/tmp}/jw-v43-test-deps.XXXXXXXX")" || { echo 'NOT RUN: unable to allocate isolated Python environment' >&2; exit 2; }
  chmod 700 "$TEST_WORK"
  python3 -m venv --system-site-packages "$TEST_WORK/venv" || { echo 'NOT RUN: isolated Python venv unavailable' >&2; exit 2; }
  TEST_PYTHON="$TEST_WORK/venv/bin/python"
  "$TEST_PYTHON" -m pip --disable-pip-version-check --no-input install -r requirements-dev.txt \
      || { echo 'NOT RUN: PDF test dependency installation unavailable' >&2; exit 2; }
fi
"$TEST_PYTHON" -c 'from reportlab.pdfgen import canvas' >/dev/null 2>&1 \
  || { echo 'NOT RUN: ReportLab unavailable for full PDF regression' >&2; exit 2; }
# Codespaces' system image may lack NanumGothic.ttf. Historical PDF tests
# require its exact path; don't skip failed fixtures or proceed to PG17.
ensure_korean_pdf_font() {
  local font_file='/usr/share/fonts/truetype/nanum/NanumGothic.ttf'
  if [[ ! -s "$font_file" || ! -r "$font_file" ]]; then
    command -v apt-get >/dev/null 2>&1 || { echo 'NOT RUN: fonts-nanum package manager unavailable' >&2; return 2; }
    local -a apt_cmd
    if [[ "$(id -u)" == 0 ]]; then
      apt_cmd=(env DEBIAN_FRONTEND=noninteractive apt-get)
    else
      command -v sudo >/dev/null 2>&1 || { echo 'NOT RUN: font installation requires noninteractive sudo' >&2; return 2; }
      sudo -n true >/dev/null 2>&1 || { echo 'NOT RUN: noninteractive sudo denied for font setup' >&2; return 2; }
      apt_cmd=(sudo -n env DEBIAN_FRONTEND=noninteractive apt-get)
    fi
    echo 'INFO: installing missing Korean PDF fixture font (fonts-nanum)' >&2
    if ! "${apt_cmd[@]}" update -qq -o Acquire::Retries=2; then
      echo 'NOT RUN: system package metadata unavailable for Korean PDF font' >&2
      return 2
    fi
    if ! "${apt_cmd[@]}" install -y -qq --no-install-recommends fonts-nanum; then
      echo 'NOT RUN: Korean PDF fixture font installation failed' >&2
      return 2
    fi
  fi
  if [[ ! -s "$font_file" || ! -r "$font_file" ]]; then
    echo 'FAIL: NanumGothic.ttf absent or unreadable after setup' >&2
    return 1
  fi
  if ! "$TEST_PYTHON" -c 'from reportlab.pdfbase.ttfonts import TTFont; TTFont("JW_Korean_PDF_fixture", "/usr/share/fonts/truetype/nanum/NanumGothic.ttf")'; then
    echo 'FAIL: Korean PDF fixture font cannot be parsed by ReportLab' >&2
    return 1
  fi
  echo 'PASS: Korean PDF font readable and accepted by ReportLab' >&2
}
ensure_korean_pdf_font || exit $?
PYTHONPATH=. "$TEST_PYTHON" -m pytest -q --disable-warnings -rs
printf 'PASS: local full-repository V4.3 syntax, UI script and regression (not live PostgreSQL)\n'
