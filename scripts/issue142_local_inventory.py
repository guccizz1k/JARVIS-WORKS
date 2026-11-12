#!/usr/bin/env python3
"""Read-only, offline metadata inventory for JARVIS-WORKS owner Codespaces.

NEVER opens local backup contents, ciphertext, JSON contents, keys or environment
variables; NEVER connects to network or databases; NEVER changes a git index.
Prints only aggregate counts and commit/branch identifiers.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
from collections import Counter
from pathlib import Path

EXPECTED_LEGACY_BRANCH = "jwb"
LEGACY_SAFE_UNTRACKED = frozenset({".github/supabase-root-2021.cer"})
LOCAL_EVIDENCE_PREFIX = "docs/review/issue142-"
CANDIDATE_COMMITS = ("c296b0e", "449d49a", "11d860a")


def git(repo: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(["git", "-C", str(repo), "-c", "core.fsmonitor=false", *args],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
                                timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("GIT_COMMAND_UNAVAILABLE_OR_TIMEOUT") from exc
    if result.returncode:
        raise RuntimeError("GIT_COMMAND_FAILED")
    return result.stdout


def parse_porcelain_z(data: bytes) -> list[tuple[str, str]]:
    """Parse porcelain-v1 NUL names, including rename/copy's extra NUL field."""
    parts = data.split(b"\x00")
    out: list[tuple[str, str]] = []
    index = 0
    while index < len(parts) and parts[index]:
        entry = parts[index]
        if len(entry) < 4 or entry[2:3] != b" ":
            raise RuntimeError("UNEXPECTED_PORCELAIN_FORMAT")
        status = entry[:2].decode("ascii", "replace")
        path = os.fsdecode(entry[3:])
        out.append((status, path))
        index += 1
        if "R" in status or "C" in status:
            if index >= len(parts) or not parts[index]:
                raise RuntimeError("TRUNCATED_RENAME_ENTRY")
            index += 1
    return out


def collect(repo: Path) -> dict:
    repo = repo.resolve()
    root = Path(os.fsdecode(git(repo, "rev-parse", "--show-toplevel").strip())).resolve()
    if root != repo:
        raise RuntimeError("WRONG_REPOSITORY_ROOT")
    branch = os.fsdecode(git(repo, "branch", "--show-current").strip())
    head = os.fsdecode(git(repo, "rev-parse", "HEAD").strip())
    entries = parse_porcelain_z(git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all"))
    untracked = [path for status, path in entries if status == "??"]
    tracked = [path for status, path in entries if status != "??"]
    issues = [path for path in untracked if path.startswith(LOCAL_EVIDENCE_PREFIX)]

    unsafe_permissions = 0
    symlinks = 0
    missing = 0
    for path in untracked:
        # lstat: examine the inode itself, never follow a link or open contents.
        try:
            mode = (repo / path).lstat().st_mode
        except OSError:
            missing += 1
            continue
        if stat.S_ISLNK(mode):
            symlinks += 1
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            unsafe_permissions += 1

    objects: dict[str, bool] = {}
    for prefix in CANDIDATE_COMMITS:
        try:
            result = subprocess.run(["git", "-C", str(repo), "cat-file", "-t", prefix],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
                                    timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("GIT_OBJECT_CHECK_UNAVAILABLE_OR_TIMEOUT") from exc
        objects[prefix] = result.returncode == 0 and result.stdout.strip() == b"commit"

    legacy_allowed = (branch == EXPECTED_LEGACY_BRANCH and not tracked
                      and set(untracked).issubset(LEGACY_SAFE_UNTRACKED))
    return {
        "kind": "OFFLINE_METADATA_ONLY",
        "branch": branch,
        "head": head,
        "tracked_changes_count": len(tracked),
        "untracked_count": len(untracked),
        "issue142_untracked_evidence_count": len(issues),
        "issue142_evidence_extensions": dict(sorted(Counter(Path(p).suffix.lower() for p in issues).items())),
        "untracked_symlinks_count": symlinks,
        "untracked_group_or_world_permission_count": unsafe_permissions,
        "untracked_missing_at_check_count": missing,
        "candidate_commits_present": objects,
        "legacy_go_launcher_worktree_prereqs_only": legacy_allowed,
        "codespaces_archive_offsite_proven": False,
        "independent_recovery_key_proven": False,
        "privacy": "No file contents, env, credentials, archive bytes, DSNs or database connections accessed",
        "safety": "No git writes, no network, no database writes",
    }


def main() -> int:
    try:
        report = collect(Path.cwd())
    except RuntimeError as exc:
        print(json.dumps({"kind": "OFFLINE_METADATA_ONLY", "status": "BLOCKED", "code": str(exc)}))
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
