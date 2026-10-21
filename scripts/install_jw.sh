#!/usr/bin/env bash
# One-time installer for JW mobile CLI, read directly from fetched review/v49.
set -Eeuo pipefail
umask 077
ROOT="${JW_REPO_DIR:-/workspaces/JARVIS-WORKS}"
[[ -d "$ROOT" ]] || { echo 'NOT RUN: Codespaces repository missing' >&2; exit 2; }
origin=$(git -C "$ROOT" remote get-url origin 2>/dev/null) || exit 2
case "$origin" in
  https://github.com/guccizz1k/JARVIS-WORKS|https://github.com/guccizz1k/JARVIS-WORKS.git|git@github.com:guccizz1k/JARVIS-WORKS|git@github.com:guccizz1k/JARVIS-WORKS.git) ;;
  *) echo 'NOT RUN: unexpected GitHub origin' >&2; exit 2 ;;
esac
head=$(git -C "$ROOT" rev-parse --verify 'FETCH_HEAD^{commit}') || { echo 'NOT RUN: no fetched review commit' >&2; exit 2; }
# Verify the fetched ref is the intended review branch before extracting bytes.
ref=$(git -C "$ROOT" rev-parse --verify refs/remotes/origin/review/v49 2>/dev/null) || {
  echo 'NOT RUN: expected review/v49 remote tracking ref missing' >&2; exit 2;
}
[[ "$ref" == "$head" ]] || { echo 'NOT RUN: unexpected fetched commit' >&2; exit 2; }
mkdir -p "$HOME/.local/bin"
staging=$(mktemp "$HOME/.local/bin/.jw.XXXXXXXX")
trap 'rm -f -- "$staging"' EXIT
git -C "$ROOT" show "$head:scripts/jw.sh" > "$staging"
manifest=$(git -C "$ROOT" show "$head:V4_9_PG_GATE_SHA256.txt") || { echo 'NOT RUN: V4.9 manifest missing' >&2; exit 2; }
expected=$(printf '%s\n' "$manifest" | awk '$2=="scripts/jw.sh"{print $1}')
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo 'NOT RUN: malformed JW checksum' >&2; exit 2; }
actual=$(sha256sum "$staging" | cut -d' ' -f1)
[[ "$actual" == "$expected" ]] || { echo 'FAIL: JW command checksum differs from manifest' >&2; exit 1; }
bash -n "$staging"
if [[ -e "$HOME/.local/bin/jw" && ! -L "$HOME/.local/bin/jw" ]]; then
  grep -q 'JARVIS-WORKS JW mobile CLI' "$HOME/.local/bin/jw" || { echo 'NOT RUN: refusing to overwrite unrelated jw executable' >&2; exit 2; }
fi
[[ ! -L "$HOME/.local/bin/jw" ]] || { echo 'NOT RUN: refusing to replace symlink' >&2; exit 2; }
chmod 700 "$staging"
mv -f -- "$staging" "$HOME/.local/bin/jw"
trap - EXIT
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  touch "$HOME/.bashrc"
  if ! grep -Fq '# JARVIS-WORKS mobile jw PATH' "$HOME/.bashrc"; then
    printf '\n# JARVIS-WORKS mobile jw PATH\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$HOME/.bashrc"
  fi
  echo 'PASS: JW installed. Open a new terminal to run: jw 49'
else
  echo 'PASS: JW installed. Run: jw 49'
fi
