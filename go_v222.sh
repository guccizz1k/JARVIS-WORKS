#!/usr/bin/env bash
# Authorized owner-side exact-SHA promotion. No workflow-permission workaround.
set -Eeuo pipefail
BASE="d8ee0e70daa0674fdefbf7df2e5a7c42ffcd5ed9"
TARGET="19c5a6771b8d0925d1bb32d0119f6ad186b57fd4"
TREE="ff6de1ca8bac6ebb3507c17e08f78b6ca1603a47"
BRANCH="candidate/jw-v222-root-ui-20261106"
EXPECTED_DIFF_SHA256="bc9d6b22c01ed5d9e5e16ad8ca7daeca648445a44261ba8474310d849701eff2"
SOURCE="$(git rev-parse --show-toplevel)"
URL="$(git -C "$SOURCE" remote get-url origin)"
case "$URL" in
  https://github.com/guccizz1k/JARVIS-WORKS|https://github.com/guccizz1k/JARVIS-WORKS.git|git@github.com:guccizz1k/JARVIS-WORKS.git|git@github.com:guccizz1k/JARVIS-WORKS) ;;
  *) echo "BLOCKED: unexpected origin URL"; exit 3;;
esac
command -v git >/dev/null
command -v sha256sum >/dev/null
command -v base64 >/dev/null
export GIT_LFS_SKIP_SMUDGE=1
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git init -q "$work/repo"
git -C "$work/repo" remote add origin "$URL"
git -C "$work/repo" fetch --quiet --no-tags origin \
  "+refs/heads/review/jw-cinema-pg-engine-20261104:refs/remotes/origin/review/jw-cinema-pg-engine-20261104" \
  "+refs/heads/$BRANCH:refs/remotes/origin/$BRANCH"
remote_stage="$(git -C "$work/repo" rev-parse "refs/remotes/origin/$BRANCH")"
if test "$remote_stage" = "$TARGET"; then
  echo "PASS: candidate already points to original SHA $TARGET"
  exit 0
fi
test "$(git -C "$work/repo" rev-parse refs/remotes/origin/review/jw-cinema-pg-engine-20261104)" = "$BASE" || { echo "BLOCKED: review branch moved"; exit 3; }
git -C "$work/repo" merge-base --is-ancestor "$BASE" "$remote_stage" || { echo "BLOCKED: candidate ancestry"; exit 3; }
git -C "$work/repo" show "$remote_stage:.github/jw-cinema-pg-bootstrap/approved.diff" > "$work/approved.diff"
git -C "$work/repo" show "$remote_stage:.github/jw-cinema-pg-bootstrap/approved-commit.b64" | base64 -d > "$work/original-commit.raw"
test "$(sha256sum "$work/approved.diff" | cut -d' ' -f1)" = "$EXPECTED_DIFF_SHA256" || { echo "BLOCKED: approved diff hash"; exit 3; }
test "$(git -C "$work/repo" hash-object -t commit --stdin < "$work/original-commit.raw")" = "$TARGET" || { echo "BLOCKED: original SHA"; exit 3; }
test "$(sed -n '1s/^tree //p' "$work/original-commit.raw")" = "$TREE" || { echo "BLOCKED: original tree"; exit 3; }
test "$(grep -a '^parent ' "$work/original-commit.raw" | cut -d' ' -f2)" = "$BASE" || { echo "BLOCKED: original parent"; exit 3; }
git -C "$work/repo" checkout -q --detach "$BASE"
git -C "$work/repo" apply --check "$work/approved.diff"
git -C "$work/repo" apply "$work/approved.diff"
git -C "$work/repo" add -A
test "$(git -C "$work/repo" write-tree)" = "$TREE" || { echo "BLOCKED: generated tree mismatch"; exit 3; }
test "$(git -C "$work/repo" hash-object -t commit -w --stdin < "$work/original-commit.raw")" = "$TARGET" || { echo "BLOCKED: cannot reconstruct original"; exit 3; }
test "$(git -C "$work/repo" show -s --format=%P "$TARGET")" = "$BASE" || { echo "BLOCKED: parent mismatch"; exit 3; }
current="$(git -C "$work/repo" ls-remote origin "refs/heads/$BRANCH" | cut -f1)"
test "$current" = "$remote_stage" || { echo "BLOCKED: candidate changed since fetch; no push"; exit 3; }
# Owner's authenticated GitHub session must have workflow-file write permission.
# GitHub itself enforces this permission. Never substitute another token here.
git -C "$work/repo" push origin "$TARGET:refs/heads/$BRANCH" "--force-with-lease=refs/heads/$BRANCH:$current"
final="$(git -C "$work/repo" ls-remote origin "refs/heads/$BRANCH" | cut -f1)"
test "$final" = "$TARGET" || { echo "FAIL: remote SHA differs"; exit 1; }
echo "PASS_CANDIDATE_EXACT_ORIGINAL_SHA $final"
echo "NEXT: inspect GitHub Actions for the candidate branch; no DB, main, PR or Render changed."
