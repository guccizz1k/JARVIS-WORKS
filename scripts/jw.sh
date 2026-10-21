#!/usr/bin/env bash
# JARVIS-WORKS JW mobile CLI v4.9. Review only. Never merge, deploy or cut over.
set -Eeuo pipefail
umask 077
ROOT="${JW_REPO_DIR:-/workspaces/JARVIS-WORKS}"
LOG_DIR="${JW_LOG_DIR:-${HOME}/.local/state/jarvis-works}"
usage() { printf 'Usage: jw 49 | jw last\n' >&2; exit 2; }
if [[ ${1:-} == last && $# == 1 ]]; then
  [[ -d "$LOG_DIR" ]] || { echo 'NOT RUN: no prior JW run' >&2; exit 2; }
  if [[ ! -f "$LOG_DIR/latest" || -L "$LOG_DIR/latest" ]]; then echo 'NOT RUN: no saved JW log' >&2; exit 2; fi
  logname=$(cat "$LOG_DIR/latest")
  [[ "$logname" =~ ^v[0-9]{2}_[0-9]{8}_[0-9]{6}_[0-9]+\.log$ && -f "$LOG_DIR/$logname" && ! -L "$LOG_DIR/$logname" ]] || { echo 'NOT RUN: invalid saved log' >&2; exit 2; }
  tail -n 35 "$LOG_DIR/$logname"
  exit 0
fi
(( $# == 1 )) || usage
VERSION="$1"
[[ "$VERSION" =~ ^[0-9]{2}$ ]] || usage
(( 10#$VERSION >= 43 && 10#$VERSION <= 99 )) || usage
[[ "${JW_ENV:-}" != production && "${JW_ENV:-}" != PRODUCTION ]] || { echo 'NOT RUN: production environment blocked' >&2; exit 2; }
[[ -d "$ROOT" && ! -L "$ROOT" ]] || { echo 'NOT RUN: Codespaces repository unavailable' >&2; exit 2; }
for cmd in git bash mktemp tee date; do command -v "$cmd" >/dev/null 2>&1 || { echo "NOT RUN: $cmd missing" >&2; exit 2; }; done
[[ "$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null)" == "$(cd "$ROOT" && pwd -P)" ]] || { echo 'NOT RUN: invalid repository root' >&2; exit 2; }
remote=$(git -C "$ROOT" remote get-url origin 2>/dev/null) || { echo 'NOT RUN: missing origin' >&2; exit 2; }
case "$remote" in
  https://github.com/guccizz1k/JARVIS-WORKS|https://github.com/guccizz1k/JARVIS-WORKS.git|git@github.com:guccizz1k/JARVIS-WORKS|git@github.com:guccizz1k/JARVIS-WORKS.git) ;;
  *) echo 'NOT RUN: unexpected GitHub origin' >&2; exit 2 ;;
esac
branch="review/v$VERSION"
# Fetch only the requested review branch; never checkout or modify main.
if ! git -C "$ROOT" fetch --no-tags origin "refs/heads/$branch"; then
  echo "NOT RUN: cannot fetch $branch" >&2
  exit 2
fi
sha=$(git -C "$ROOT" rev-parse --verify 'FETCH_HEAD^{commit}') || { echo 'NOT RUN: no fetched commit' >&2; exit 2; }
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'NOT RUN: invalid fetched commit' >&2; exit 2; }
mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR"
logfile="v${VERSION}_$(date +%Y%m%d_%H%M%S)_$$.log"
log="$LOG_DIR/$logfile"
: > "$log"
chmod 600 "$log"
printf '%s\n' "$logfile" > "$LOG_DIR/latest"
work="$(mktemp -d "${TMPDIR:-/tmp}/jw-review-v${VERSION}.XXXXXXXX")" || { echo 'NOT RUN: temporary directory creation failed' >&2; exit 2; }
attached=0
cleanup() {
  local result=$?
  trap - EXIT INT TERM
  if (( attached )); then
    if ! git -C "$ROOT" worktree remove --force "$work" >/dev/null 2>&1; then
      echo 'FAIL: review worktree cleanup failed' | tee -a "$log" >&2
      result=1
    fi
  else
    if ! rmdir -- "$work" >/dev/null 2>&1; then
      echo 'FAIL: unused temp workdir cleanup failed' | tee -a "$log" >&2
      result=1
    fi
  fi
  if (( result == 0 )); then
    echo "PASS: jw $VERSION complete (isolated; operational cutover DENIED)" | tee -a "$log"
  elif (( result == 2 )); then
    echo "NOT RUN: jw $VERSION stopped before full verification" | tee -a "$log" >&2
  else
    echo "FAIL: jw $VERSION gate failed; no further stages executed" | tee -a "$log" >&2
  fi
  echo "Log: $log"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if ! git -C "$ROOT" worktree add --detach "$work" "$sha"; then
  echo 'FAIL: isolated worktree creation failed' >&2
  exit 1
fi
attached=1
check="$work/scripts/check_v${VERSION}_review.sh"
pg="$work/scripts/run_pg17_codespaces_v${VERSION}.sh"
[[ -f "$check" && -f "$pg" && ! -L "$check" && ! -L "$pg" ]] || { echo 'NOT RUN: expected verification scripts unavailable' >&2; exit 2; }
echo "INFO: jw $VERSION detached at ${sha:0:12}; main untouched"
# Gate exit status is the first pipeline status; tee failures also block success.
set +e
( cd "$work" && bash "$check" && bash "$pg" ) 2>&1 | tee -a "$log"
pipeline_status=("${PIPESTATUS[@]}")
result=${pipeline_status[0]}
pipe_result=${pipeline_status[1]:-1}
set -e
if (( pipe_result != 0 )); then echo 'FAIL: log write failed' >&2; exit 1; fi
exit "$result"
