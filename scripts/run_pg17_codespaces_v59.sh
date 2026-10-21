#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
# Historical hash files permanently attest to ORIGINAL source; V5.9 modifies
# messenger.py and must never update/ignore those historic checksums.
V58_BASE='e8ea684c9af78debdfc26179641e3094f2d2ef20'
command -v git >/dev/null || { echo 'NOT RUN: git missing' >&2; exit 2; }
git cat-file -e "${V58_BASE}^{commit}" || { echo 'NOT RUN: original V5.8 commit unavailable' >&2; exit 2; }
git merge-base --is-ancestor "$V58_BASE" HEAD || { echo 'FAIL: untrusted review ancestry' >&2; exit 1; }
work="$(mktemp -d "${TMPDIR:-/tmp}/jw-v59-historical.XXXXXXXX")"
attached=0
cleanup() {
  result=$?
  trap - EXIT
  if (( attached )); then
    git worktree remove --force "$work" || result=1
  else
    rmdir -- "$work" || result=1
  fi
  exit "$result"
}
trap cleanup EXIT
# Full prior source checks + real PostgreSQL 17 tests execute on exact V5.8
# ancestor, so old manifests retain their original protective meaning.
git worktree add --detach "$work" "$V58_BASE"
attached=1
(
  cd "$work"
  bash scripts/check_v58_review.sh
  bash scripts/run_pg17_codespaces_v58.sh
)
# New HTTP test ran in V5.9 check_v59_review.sh, not against historical code.
printf '%s\n' 'PASS: V5.9 web actor journal + unmodified V5.8 full regression and live PG17 baseline'
printf '%s\n' 'BLOCKED: operational PG cutover, pre-V5.9 actor backfill and PG actor relay NOT IMPLEMENTED'
