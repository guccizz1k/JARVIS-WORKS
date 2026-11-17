#!/usr/bin/env python3
"""Preserve the owner's dirty Codespace checkout while running exact-SHA P1/P0.

The owner may have valuable local changes, e.g. pg17_rls_gate_result.txt.
Never stash, reset, clean, overwrite, or copy the owner's untracked files.
Instead check out a temporary detached worktree at the EXACT current remote
review HEAD and launch the already reviewed fail-closed owner driver there.
Existing owner secrets are read only through their established environment and
private HOME paths, never copied to GitHub, worktree, or process arguments.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BRANCH = "review/jw-v223-p1p0-b2b3-20261117"
SCRIPT = "scripts/ci_cinema_pg_v223_owner_worktree_20261117.py"
DRIVER = "scripts.ci_cinema_pg_v223_owner_live_20261117"


class Blocked(Exception):
    pass


def git(*args: str, cwd: Path = ROOT) -> str:
    done = subprocess.run(("git", *args), cwd=cwd, capture_output=True,
                          text=True, timeout=40, check=False)
    if done.returncode:
        raise Blocked("local_git_preflight_failed")
    return done.stdout.strip()


def verify_input_checkout() -> str:
    if os.environ.get("CODESPACES") != "true":
        raise Blocked("codespaces_required")
    if git("rev-parse", "--show-toplevel") != str(ROOT):
        raise Blocked("wrong_repo_root")
    if git("branch", "--show-current") != BRANCH:
        raise Blocked("wrong_review_branch")
    current = git("rev-parse", "HEAD")
    remote = git("rev-parse", "refs/remotes/origin/" + BRANCH)
    if current != remote:
        raise Blocked("fetch_and_fast_forward_review_branch")
    if git("hash-object", SCRIPT) != git("rev-parse", "HEAD:" + SCRIPT):
        raise Blocked("local_launcher_was_modified")
    return current


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("check", "run"))
    args = parser.parse_args(argv)
    try:
        commit = verify_input_checkout()
    except (Blocked, OSError, subprocess.TimeoutExpired) as exc:
        print("BLOCKED ORIGINAL_CHECKOUT_" + type(exc).__name__)
        print("NO_ROLE_CHANGE_NO_BACKUP")
        return 2

    # The original owner workspace can be dirty; it remains completely untouched.
    parent = Path(tempfile.mkdtemp(prefix="jw-v223-p1p0-isolated-"))
    isolated = parent / "checkout"
    attached = False
    try:
        cmd = subprocess.run(
            ["git", "worktree", "add", "--detach", "--quiet",
             str(isolated), commit],
            cwd=ROOT, capture_output=True, text=True, timeout=100, check=False,
        )
        if cmd.returncode:
            print("BLOCKED CANNOT_CREATE_ISOLATED_WORKTREE")
            return 2
        attached = True

        # Double-check the detached checkout before letting it read credentials.
        if (git("rev-parse", "HEAD", cwd=isolated) != commit
                or git("status", "--porcelain", "--untracked-files=all", cwd=isolated)):
            print("BLOCKED ISOLATED_SOURCE_SHA_OR_CLEANLINESS")
            return 2

        print("PASS CLEAN_ISOLATED_EXACT_SHA; ORIGINAL_WORKTREE_PRESERVED", flush=True)
        # Preserve stdin and stdout: the owner must approve explicitly on their
        # own terminal; no secret appears in argv or in this wrapper's logs.
        child = subprocess.run(
            [sys.executable, "-m", DRIVER, args.action],
            cwd=isolated, stdin=None, stdout=None, stderr=None, check=False,
        )
        return child.returncode if child.returncode == 0 else 2
    except (OSError, subprocess.TimeoutExpired) as exc:
        print("BLOCKED ISOLATED_EXECUTOR_" + type(exc).__name__)
        return 2
    finally:
        if attached:
            # Without --force this refuses to erase any unknown/untracked owner
            # data that an interrupted child may have left in the isolated tree.
            try:
                done = subprocess.run(
                    ["git", "worktree", "remove", str(isolated)],
                    cwd=ROOT, capture_output=True, text=True,
                    timeout=50, check=False,
                )
                if done.returncode:
                    print("ISOLATED_WORKTREE_PRESERVED_FOR_INSPECTION")
            except (OSError, subprocess.TimeoutExpired):
                print("ISOLATED_WORKTREE_PRESERVED_FOR_INSPECTION")
        try:
            parent.rmdir()  # only remove an empty directory; no recursive delete
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
