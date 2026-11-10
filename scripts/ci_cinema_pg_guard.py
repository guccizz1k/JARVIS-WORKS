#!/usr/bin/env python3
"""Change-containment guard for the CINEMA/PostgreSQL integration task.

Standard library only. Compares the current work tree against the pinned
baseline commit and fails when anything outside the approved whitelist moved.

Checks (each reported separately; any FAIL => exit status 1):
  1. HEAD ancestry contains the pinned baseline commit.
  2. CINEMA original HTML Git blob SHA unchanged.
  3. app/main.py Git blob SHA unchanged.
  4. app/static/ tree unchanged, except the single pinned V22.2 CSS blob.
  5. Every changed/added/untracked path is on the restricted whitelist.
  6. Whitelisted *existing* files are only modified, never deleted/renamed.
  7. No test file was deleted or renamed.
  8. No new skip/xfail marker was added to any test.
  9. No change touches main or workflow files outside jw-cinema-pg-*.yml.

This script does not verify business assertions. A PASS here means only that
the diff is contained; it is not a release approval.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

BASELINE = "08ea29867e962d4ac5be0e942fc1488528494428"
PROTECTED_BLOBS = {
    "app/static/cinema/JARVIS_WORKS_CINEMA.html": "9bedf97fe718a94f07861e23670685af00619ca8",
    "app/main.py": "775f500c8a7549d434ce196a8e0763aea33e1c67",
}
PROTECTED_TREES = {"app/static": "3c8834eb4f44bd56cbe5683c9fc0e5e696add48e"}

# Explicitly approved V22.2 layout-only exception. All other app/static blobs,
# including the protected CINEMA original and UI business scripts, stay pinned.
V222_CSS_PATH = "app/static/cinematic_v222.css"
APPROVED_V222_CSS_BLOB = "c7c5e796688582d27ab4322f0dd5cfd25b16226a"

# Existing files that may be edited (modify only).
MODIFIABLE_EXISTING = frozenset({
    "app/pg_review_integrated_v202.py",
    "app/cinema_entry_v1.py",
    # Exception limited to this pre-reviewed CSS blob; other static files immutable.
    V222_CSS_PATH,
    # The guard file was added after BASELINE and remains authorized by the
    # existing ci_cinema_pg_*.py new-file rule (status A), preserving tests.
    # The only three historical fixture repairs. Never permit other old tests.
    "tests/test_installer_v75.py",
    "tests/test_installer_v79.py",
    "tests/test_pg_auth_v85.py",
})

# Immutable hashes of the three repaired historical fixture tests. Changes
# to assertions or test scenarios now fail even when path remains allowed.
APPROVED_LEGACY_TEST_BLOBS = {
    "tests/test_installer_v75.py": "d8b274a5455a74cced64579e2146c34837a72e0f",
    "tests/test_installer_v79.py": "2f498ec592d315e2791f5d5915af691b4371068c",
    "tests/test_pg_auth_v85.py": "c7df1d7bb6a749a064ea8b8611ae7df19132a046",
}
# V22.3 P0-1 approval is confined to these exact, already reviewed Git blobs.
# A changed backup tool or test must be reaudited and repinned; this is NOT a
# wildcard exemption from original CINEMA/PostgreSQL change containment.
APPROVED_V223_BACKUP_BLOBS = {
    "scripts/pg_backup_v223.py": "e8c21e8bdb5b9fbf4e5e1882926859d305456f07",
    "tests/test_v223_pg_backup.py": "5fd569823f38ad83b8780bf9c9bd2782b3eaf916",
    "docs/ops/V223_PG_BACKUP_RESTORE.md": "6ce80a02d7ef7676f3dc68270b2e5abfcd922c8a",
    "docs/ops/V223_SYNTHETIC_CI.md": "5649d0a127cf516d994752dc8804bad7a0af46f2",
}

# New files: single path segment below the directory, strict names.
NEW_FILE_PATTERNS = tuple(re.compile(p) for p in (
    r"^app/pg_cinema_[A-Za-z0-9_]+\.py$",
    r"^app/cinema_bridge_v3\.js$",
    r"^tests/test_cinema_pg_[A-Za-z0-9_]+\.py$",
    r"^scripts/ci_cinema_pg_[A-Za-z0-9_]+\.py$",
    r"^scripts/review/cinema_pg_[A-Za-z0-9_]+\.sql$",
    r"^\.github/workflows/jw-cinema-pg-[A-Za-z0-9_-]+\.yml$",
    r"^docs/review/cinema-pg-[A-Za-z0-9_-]+\.md$",
    r"^scripts/pg_backup_v223\.py$",
    r"^tests/test_v223_pg_backup\.py$",
    r"^docs/ops/V223_PG_BACKUP_RESTORE\.md$",
    r"^docs/ops/V223_SYNTHETIC_CI\.md$",
))
SKIP_MARKERS = re.compile(
    r"(pytest\.mark\.(skip|skipif|xfail)|pytest\.(skip|xfail)\(|unittest\.skip|\bskipTest\()"
)


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                          text=True).stdout


def classify_path(path: str, status: str) -> tuple[bool, str]:
    """Return (allowed, reason) for one changed path. Pure function (unit-tested)."""
    if path in MODIFIABLE_EXISTING:
        if status != "M":
            return False, f"whitelisted existing file must only be modified (status {status})"
        return True, "modified whitelisted existing file"
    if any(p.match(path) for p in NEW_FILE_PATTERNS):
        if status not in ("A", "M", "?"):
            return False, f"new-file whitelist path with unexpected status {status}"
        return True, "new whitelisted file"
    return False, "outside whitelist"


def changed_paths(root: Path) -> list[tuple[str, str]]:
    """(status, path) for commits since baseline, staged, unstaged and untracked."""
    seen: dict[str, str] = {}
    out = git("diff", "--name-status", "--no-renames", BASELINE, "HEAD", cwd=root)
    for line in out.splitlines():
        status, _, path = line.partition("\t")
        seen[path] = status[0]
    out = git("diff", "--name-status", "--no-renames", "HEAD", cwd=root)
    for line in out.splitlines():
        status, _, path = line.partition("\t")
        seen.setdefault(path, status[0])
    out = git("ls-files", "--others", "--exclude-standard", cwd=root)
    for path in out.splitlines():
        seen.setdefault(path, "?")
    return sorted((s, p) for p, s in seen.items())


def run(root: Path) -> dict:
    results: list[dict] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        results.append({"check": name, "result": "PASS" if ok else "FAIL", "detail": detail})

    try:
        git("merge-base", "--is-ancestor", BASELINE, "HEAD", cwd=root)
        add("baseline_is_ancestor", True, BASELINE)
    except subprocess.CalledProcessError:
        add("baseline_is_ancestor", False, "baseline commit is not an ancestor of HEAD")

    # Compare the actual work-tree bytes (not just HEAD) with `git hash-object`.
    for path, expected in PROTECTED_BLOBS.items():
        file = root / path
        if not file.is_file():
            add(f"blob:{path}", False, "missing")
            continue
        actual = git("hash-object", "--", path, cwd=root).strip()
        add(f"blob:{path}", actual == expected, f"expected {expected} actual {actual}")

    for path, expected in APPROVED_V223_BACKUP_BLOBS.items():
        file = root / path
        if not file.is_file():
            add(f"approved_v223_backup:{path}", False, "missing")
            continue
        actual = git("hash-object", "--", path, cwd=root).strip()
        add(f"approved_v223_backup:{path}", actual == expected,
            f"expected {expected} actual {actual}")

    for path, expected in APPROVED_LEGACY_TEST_BLOBS.items():
        file = root / path
        if not file.is_file():
            add(f"approved_legacy_fixture:{path}", False, "missing")
            continue
        actual = git("hash-object", "--", path, cwd=root).strip()
        add(f"approved_legacy_fixture:{path}", actual == expected,
            f"expected {expected} actual {actual}")

    for path, expected in PROTECTED_TREES.items():
        actual = git("rev-parse", f"HEAD:{path}", cwd=root).strip()
        dirty = git("status", "--porcelain", "--", path, cwd=root).strip()
        if actual == expected:
            add(f"tree:{path}", not dirty,
                f"unchanged original static tree {expected} dirty={bool(dirty)}")
            continue
        # Preserve the pinned baseline AND every protected static Git blob,
        # allowing ONLY the exact approved CSS blob hash. Never skip the tree
        # check, even when the working tree is clean.
        baseline_tree = git("rev-parse", f"{BASELINE}:{path}", cwd=root).strip()
        def remaining_static(revision: str) -> dict[str, str]:
            result: dict[str, str] = {}
            for line in git("ls-tree", "-r", revision, "--", path, cwd=root).splitlines():
                metadata, filename = line.split("\t", 1)
                if filename != V222_CSS_PATH:
                    result[filename] = metadata
            return result
        protected_blobs_identical = (
            remaining_static(BASELINE) == remaining_static("HEAD")
        )
        css_head_blob = git("rev-parse", f"HEAD:{V222_CSS_PATH}", cwd=root).strip()
        css_work_blob = git("hash-object", "--", V222_CSS_PATH, cwd=root).strip()
        approved_exception = (
            path == "app/static"
            and baseline_tree == expected
            and protected_blobs_identical
            and css_head_blob == APPROVED_V222_CSS_BLOB
            and css_work_blob == APPROVED_V222_CSS_BLOB
            and not dirty
        )
        add(f"tree:{path}", approved_exception,
            f"baseline={baseline_tree} current={actual} "
            f"protected_blobs_identical={protected_blobs_identical} "
            f"css_head={css_head_blob} css_worktree={css_work_blob} "
            f"approved_css={APPROVED_V222_CSS_BLOB} dirty={bool(dirty)}")

    changes = changed_paths(root)
    bad = []
    for status, path in changes:
        ok, reason = classify_path(path, status)
        if not ok:
            bad.append(f"{status} {path}: {reason}")
    add("changed_files_within_whitelist", not bad,
        "; ".join(bad) if bad else f"{len(changes)} changed file(s), all whitelisted")

    deleted_tests = [p for s, p in changes if p.startswith("tests/") and s in ("D", "R")]
    add("no_deleted_tests", not deleted_tests, ", ".join(deleted_tests))

    added_skips: list[str] = []
    diff = git("diff", "--unified=0", BASELINE, "--", "tests", cwd=root)
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++") and SKIP_MARKERS.search(line):
            added_skips.append(line[:120])
    for status, path in changes:
        if status == "?" and path.startswith("tests/"):
            for number, line in enumerate((root / path).read_text(encoding="utf-8").splitlines(), 1):
                if SKIP_MARKERS.search(line):
                    added_skips.append(f"{path}:{number}")
    add("no_new_skips", not added_skips, "; ".join(added_skips))

    workflows = [p for s, p in changes if p.startswith(".github/")
                 and not re.match(r"^\.github/workflows/jw-cinema-pg-[A-Za-z0-9_-]+\.yml$", p)]
    add("no_foreign_workflow_changes", not workflows, ", ".join(workflows))

    branch = git("branch", "--show-current", cwd=root).strip()
    add("not_on_main", branch not in ("main", "master", ""), branch)

    failed = [r for r in results if r["result"] == "FAIL"]
    return {"baseline": BASELINE, "branch": branch, "overall": "FAIL" if failed else "PASS",
            "checks": results, "changed": [f"{s} {p}" for s, p in changes]}


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    report = run(root)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["overall"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
