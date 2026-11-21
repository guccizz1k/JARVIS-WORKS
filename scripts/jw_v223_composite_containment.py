"""Verify the exact, separately reviewed V22.3 composite scope."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess

BASELINE = "08ea29867e962d4ac5be0e942fc1488528494428"
IMPORTED = "0dd37b2bb3a7abda7a306505cae70216cae523a0"
CONTROL = "e22f66dde4ed552a75ce504147875733d4671ab2"
INVENTORY = "docs/review/v223-composite-inventory.json"
LEGACY_GUARD = "scripts/ci_cinema_pg_guard.py"
POLICY_PATHS = frozenset({
    INVENTORY,
    "docs/review/v223-composite-containment.md",
    "scripts/ci_cinema_pg_v222_root_browser.py",
    "scripts/jw_v223_composite_containment.py",
    "scripts/jw_v223_pg17_required.py",
    "tests/test_jw_v223_composite_containment.py",
})
GROUPS = frozenset({
    "approved-v222-css", "v223-review-ui-assets", "legacy-cinema-workflows",
    "v223-review-workflows", "inherited-single-purpose-workflows", "approval-boundary",
    "review-sql", "isolated-review-application", "cinema-regression",
    "v223-and-pg17-regression", "inherited-regression", "cinema-diagnostics-and-gates",
    "local-test-harness", "recorded-review-evidence", "review-operations-runbooks",
    "dependency-pins", "inherited-agent-and-acceptance-tooling",
})


def git(root, *args):
    env = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    return subprocess.check_output(
        ["git", "--no-replace-objects", "-C", str(root), *args], env=env,
    )


def tree(root, revision):
    entries = {}
    for record in git(root, "ls-tree", "-rz", revision).split(b"\0"):
        if record:
            metadata, path = record.split(b"\t", 1)
            mode, _, oid = metadata.decode("ascii").split()
            entries[os.fsdecode(path)] = (mode, oid)
    return entries


def changes(before, after):
    return {path for path in before.keys() | after.keys() if before.get(path) != after.get(path)}


def require_same_tree(reviewed, actual):
    changed = changes(reviewed, actual)
    if changed:
        raise ValueError(f"unreviewed tree paths: {sorted(changed)!r}")


def require_clean(root):
    status = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    if status:
        raise ValueError(f"worktree has staged, unstaged, or untracked paths: {os.fsdecode(status)!r}")
    flags = git(root, "ls-files", "-v", "-z").split(b"\0")
    if any(entry and not entry.startswith(b"H ") for entry in flags):
        raise ValueError("worktree index has nonstandard tracked-file flags")


def require_inventory(baseline, imported, document):
    if (document["baseline"], document["source"]) != (BASELINE, IMPORTED):
        raise ValueError("inventory source or baseline mismatch")
    expected = {}
    counts = Counter()
    for path, status, mode, oid, group, legacy_allowed in document["paths"]:
        if path in expected or group not in GROUPS or type(legacy_allowed) is not bool:
            raise ValueError(f"duplicate or unexplained inventory entry: {path!r}")
        if status != ("M" if path in baseline else "A"):
            raise ValueError(f"inventory status mismatch: {path!r}")
        expected[path] = (mode, oid)
        counts["outside_legacy_whitelist"] += not legacy_allowed
        counts["foreign_workflows"] += path.startswith(".github/") and not path.startswith(
            ".github/workflows/jw-cinema-pg-"
        )
        counts["new_static_assets"] += path.startswith("app/static/") and status == "A"
    actual = {path: imported[path] for path in changes(baseline, imported) if path in imported}
    if len(actual) != len(changes(baseline, imported)):
        raise ValueError("the reviewed composite contains an unexplained deletion")
    require_same_tree(expected, actual)
    counts["classified_paths"] = len(expected)
    if counts != dict(outside_legacy_whitelist=248, foreign_workflows=30,
                      new_static_assets=18, classified_paths=433):
        raise ValueError(f"inventory totals differ from the reviewed scope: {dict(counts)}")
    return dict(counts)


def verify(root, policy_commit):
    if not re.fullmatch(r"[0-9a-f]{40}", policy_commit):
        raise ValueError("an independently selected full policy commit SHA is required")
    parents = git(root, "show", "-s", "--format=%P", policy_commit).decode().split()
    if parents != [IMPORTED]:
        raise ValueError("policy commit must be a single child of the verified integration")
    require_clean(root)
    baseline, imported, control, approved, actual = (
        tree(root, revision) for revision in (BASELINE, IMPORTED, CONTROL, policy_commit, "HEAD")
    )
    if changes(imported, approved) != POLICY_PATHS or not POLICY_PATHS <= approved.keys():
        raise ValueError("policy commit changes paths outside its exact implementation scope")
    if any(approved[path][0] != "100644" for path in POLICY_PATHS):
        raise ValueError("policy implementation paths must be ordinary non-executable files")
    require_same_tree(approved, actual)
    if actual[LEGACY_GUARD] != imported[LEGACY_GUARD]:
        raise ValueError("legacy guard differs from the verified integration")
    protected = {path: entry for path, entry in control.items() if path.startswith("app/static/")}
    if len(protected) != 37:
        raise ValueError("approved V22.2 file inventory differs")
    require_same_tree(protected, {path: actual[path] for path in protected if path in actual})
    for path in (*protected, LEGACY_GUARD):
        checkout = root / path
        if checkout.is_symlink() or checkout.read_bytes() != git(root, "cat-file", "blob", f"HEAD:{path}"):
            raise ValueError(f"protected worktree bytes differ: {path!r}")
    document = json.loads(git(root, "show", f"{policy_commit}:{INVENTORY}"))
    counts = require_inventory(baseline, imported, document)
    return {"status": "PASS", "policy_commit": policy_commit,
            "candidate_commit": git(root, "rev-parse", "HEAD").decode().strip(),
            "candidate_tree": git(root, "rev-parse", "HEAD^{tree}").decode().strip(),
            "protected_v222_files": len(protected), "policy_paths": len(POLICY_PATHS), **counts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--policy-commit", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.root.resolve(), args.policy_commit), indent=2))
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"FAIL: {exc}\n")


if __name__ == "__main__":
    main()
