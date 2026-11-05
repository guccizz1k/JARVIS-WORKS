#!/usr/bin/env python3
"""Classify EXACT historic Gitleaks false positives without weakening scanning.

Never suppress an unreviewed finding. All five historical findings below were
manually mapped to immutable Git blob hashes and synthetic test lines.
Gitleaks must still scan --all Git history on every run. The private/redacted
report stays in a temporary directory and is never uploaded or printed.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

# The pinned historical commits are looked up in THIS repository, never in whatever directory the caller happens to be in.
# (A classifier run from another working directory used to find no commit, mark every finding "unreviewed" and report BLOCKED
#  although the findings were the five reviewed ones. Fail-closed is kept: an unreachable repository still means BLOCKED.)
REPO_ROOT = Path(__file__).resolve().parents[1]

# (rule, exact commit SHA, exact path, exact line): (immutable Git blob SHA, class)
REVIEWED: dict[tuple[str,str,str,int], tuple[str,str]] = {
    (
        "generic-api-key",
        "92f7185cea72cf9d32592f3fd91c4ce7f4593616",
        "scripts/ci_cinema_pg_guard.py", 51,
    ): (
        "aae303c1da6b3d52424c6e6eb3ff0339b7d950cd",
        "git_blob_sha_constant",
    ),
    (
        "generic-api-key",
        "793cd3beab225f9c31feeac6f81d7378ebefa15e",
        "tests/test_messenger_v22.py", 70,
    ): (
        "2817b8d2c69224dde4ac518118f4d61913285bd2",
        "synthetic_invalid_test_account",
    ),
    (
        "generic-api-key",
        "0446138c10e52d81d99a7592da06e45af269aa77",
        "tests/test_messenger_v22.py", 70,
    ): (
        "2817b8d2c69224dde4ac518118f4d61913285bd2",
        "synthetic_invalid_test_account",
    ),
    (
        "generic-api-key",
        "793cd3beab225f9c31feeac6f81d7378ebefa15e",
        "tests/test_pg_auth_v85.py", 136,
    ): (
        "ae240a85dce3bdda41b4e8dbfccd0bb4905a8ac3",
        "password_verifier_monkeypatch",
    ),
    (
        "generic-api-key",
        "cb2c05037654a72ac14a6be106967268d168fd73",
        "scripts/ci_cinema_pg_history_classifier.py", 65,
    ): (
        "30a52212849d67c561ad6e8c6caf80204cd08592",
        "semantic_source_reference",
    ),
}

def semantic_fixture_guard(kind: str, line: str) -> bool:
    """Check the actual historic line, not a user-supplied finding label."""
    if kind == "git_blob_sha_constant":
        return bool(re.fullmatch(
            r'\s*"tests/test_pg_auth_v85\.py": "[0-9a-f]{40}",\s*', line
        )) and "c7df1d7bb6a749a064ea8b8611ae7df19132a046" in line
    if kind == "synthetic_invalid_test_account":
        return ("client.post('/api/login'" in line
                and "'third@example.test'" in line
                and "'Pass123456789'" in line)
    if kind == "password_verifier_monkeypatch":
        return ("monkeypatch.setattr(auth," in line
                and "'verify_" in line and "legacy_pbkdf2'" in line
                and "lambda pw,pw_hash:track.append(pw_hash)" in line
                and "original(pw,pw_hash)" in line)
    if kind == "semantic_source_reference":
        # Exact immutable source line from the verifier's historical commit.
        # The underlying token is a source-code function name, never a key.
        return (line.lstrip().startswith('return ("monkeypatch.setattr(auth,')
                and "legacy_pbkdf2" in line and "in line" in line)
    return False

def exact_classification(row: dict) -> str | None:
    try:
        key = (
            row["RuleID"], row["Commit"], row["File"], int(row["StartLine"])
        )
    except (KeyError, TypeError, ValueError):
        return None
    expected = REVIEWED.get(key)
    if expected is None:
        return None
    blob, kind = expected
    # Read only the pinned historical commit; no user input reaches a shell.
    try:
        actual = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", f"{key[1]}:{key[2]}"],
            capture_output=True, text=True, check=True, timeout=10,
        ).stdout.strip()
        if actual != blob:
            return None
        raw = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "show", f"{key[1]}:{key[2]}"],
            capture_output=True, check=True, timeout=10,
        ).stdout.decode("utf-8")
        lines = raw.splitlines()
        if not 1 <= key[3] <= len(lines):
            return None
        if not semantic_fixture_guard(kind, lines[key[3] - 1]):
            return None
    except (subprocess.SubprocessError, UnicodeError, OSError):
        return None
    return kind

def classify_report(path: Path, scan_exit: int) -> tuple[bool, dict]:
    if scan_exit not in (0, 1) or not path.is_file():
        return False, {"status": "BLOCKED", "reason": "scanner_error_or_missing_report"}
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError, OSError):
        return False, {"status": "BLOCKED", "reason": "unreadable_report"}
    if not isinstance(rows, list):
        return False, {"status": "BLOCKED", "reason": "invalid_report_structure"}
    if (scan_exit == 0) != (len(rows) == 0):
        return False, {"status": "BLOCKED", "reason": "inconsistent_scanner_exit"}
    classes = Counter()
    unreviewed = 0
    unknown_metadata: list[dict] = []
    seen: set[tuple] = set()
    for row in rows:
        if not isinstance(row, dict):
            unreviewed += 1
            continue
        key = tuple(row.get(k) for k in ("RuleID", "Commit", "File", "StartLine"))
        if key in seen:
            unreviewed += 1
            continue
        seen.add(key)
        result = exact_classification(row)
        if result is None:
            unreviewed += 1
            # Public CI logs get a path fingerprint, never paths, secret
            # matches, source context, or secret-containing reports.
            h=2166136261
            for ch in str(row.get("File","")).encode("utf-8"):
                h=((h^ch)*16777619)&0xffffffff
            unknown_metadata.append({
                "rule":row.get("RuleID","unknown"),
                "commit":row.get("Commit",""),
                "line":row.get("StartLine",0),
                "path_ref":format(h,"08x"),
            })
        else:
            classes[result] += 1
    accepted = unreviewed == 0
    return accepted, {
        "status": "PASS" if accepted else "BLOCKED",
        "scanner_exit": scan_exit,
        "total_findings": len(rows),
        "reviewed_exact_historical_false_positives": sum(classes.values()),
        "unreviewed_findings": unreviewed,
        "unreviewed_safe_refs": unknown_metadata,
        "reviewed_classes": dict(sorted(classes.items())),
    }

def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("BLOCKED: scanner report and exit code required")
        return 1
    try:
        accepted, summary = classify_report(Path(argv[1]), int(argv[2]))
    except ValueError:
        print("BLOCKED: invalid scanner exit code")
        return 1
    # No secret text, matched strings, paths or data leave the runner.
    print("FULL_HISTORY_SECRET_SCAN_REVIEW", json.dumps(summary, sort_keys=True))
    return 0 if accepted else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv))
