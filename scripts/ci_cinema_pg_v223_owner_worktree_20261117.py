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
import re
import stat
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


def classify_private_backup_log(raw: str) -> tuple[str, str]:
    """Stable legacy API: report only known finite classifications, never raw text.

    Retains the two-element return contract for independent QA consumers.
    The source log is untrusted even after source-engine redaction.
    """
    stderr = raw.split("--- stderr (tail) ---", 1)[-1] if "--- stderr (tail) ---" in raw else raw
    fixed_engine_codes = frozenset((
        "BLOCKED_V223_BACKUP_AUTH_FAILED",
        "BLOCKED_V223_BACKUP_BAD_CHUNK_LENGTH",
        "BLOCKED_V223_BACKUP_BAD_HEADER",
        "BLOCKED_V223_BACKUP_KEY_INVALID",
        "BLOCKED_V223_BACKUP_KEY_MUST_BE_32_BYTES",
        "BLOCKED_V223_BACKUP_KEY_REQUIRED",
        "BLOCKED_V223_BACKUP_TRUNCATED",
        "BLOCKED_V223_BAD_SCHEMA_NAME",
        "BLOCKED_V223_DSN_MUST_BE_POSTGRESQL_URL",
        "BLOCKED_V223_ENCRYPTED_ARTIFACT_TOO_SHORT",
        "BLOCKED_V223_INVALID_CATALOG_IDENTIFIER",
        "BLOCKED_V223_MARKER_REFUSED_CLUSTER_NOT_EMPTY",
        "BLOCKED_V223_OUTPUT_EXISTS_OR_SYMLINK",
        "BLOCKED_V223_PARTIAL_DUMP_SOURCE_TRUNCATED",
        "BLOCKED_V223_REAL_SOURCE_HOST_NOT_VERIFIED",
        "BLOCKED_V223_SIGNATURE_STATEMENT_TIMEOUT",
        "BLOCKED_V223_SOURCE_IDENTITY_NOT_VERIFIED",
        "BLOCKED_V223_SOURCE_REQUIRES_VERIFY_FULL_AND_ROOT_CERT",
        "BLOCKED_V223_SOURCE_ROLE_NOT_LEAST_PRIVILEGE",
        "BLOCKED_V223_TABLE_OVER_ROW_CAP",
        "BLOCKED_V223_TABLE_TOO_LARGE_FOR_ROW_DIGEST",
        "BLOCKED_V223_TARGET_EQUALS_SOURCE",
        "BLOCKED_V223_TARGET_MUST_BE_LOCAL",
        "BLOCKED_V223_TARGET_NOT_DECLARED_EPHEMERAL",
        "BLOCKED_V223_TARGET_NOT_PROVEN_EPHEMERAL",
        "BLOCKED_V223_TOKEN_REQUIRED_MIN_16_CHARS",
        "BLOCKED_V223_TOOL_VERSION_UNKNOWN",
        "BLOCKED_V223_UNKNOWN_NEGATIVE_TEST",
        "FAIL_V223_BACKUP_DECRYPT_HASH_MISMATCH",
        "FAIL_V223_INTERRUPTED_BY_SIGNAL",
    ))
    for candidate in re.findall(r"\b(?:BLOCKED_V223|FAIL_V223)_[A-Za-z0-9_]+\b", stderr):
        if candidate in fixed_engine_codes:
            return candidate, "ENGINE_MACHINE_CODE"
        # Exception class names are finite and reviewed; never return arbitrary suffix.
        for name in ("OperationalError", "ProgrammingError", "IntegrityError",
                     "UndefinedTable", "UndefinedFunction", "ValueError", "TypeError",
                     "KeyError", "AttributeError", "PermissionError", "TimeoutError",
                     "TimeoutExpired", "FileNotFoundError", "UnicodeDecodeError"):
            if candidate == "FAIL_V223_UNEXPECTED_" + name:
                return candidate, "ENGINE_MACHINE_CODE"
    patterns = (
        ("TLS_OR_CERTIFICATE", r"certificate verify failed|certificate validation|ssl[^\n]{0,60}failed|hostname mismatch"),
        ("DNS_OR_TCP_CONNECT", r"could not translate host|name or service not known|connection refused|could not connect to server|connection timed out"),
        ("DATABASE_AUTHENTICATION", r"password authentication failed|authentication failed|role [^\n]{0,80}is not permitted to log in"),
        ("DATABASE_PERMISSION", r"permission denied|insufficientprivilege"),
        ("RESTORE_ENGINE_ERROR", r"pg_restore[^\n]{0,50}(failed|error|could not|fatal)"),
        ("DUMP_ENGINE_ERROR", r"pg_dump[^\n]{0,50}(failed|error|could not|fatal)"),
        ("STORAGE_CAPACITY", r"no space left on device|disk full|quota exceeded"),
        ("PG_CLIENT_ERROR", r"psycopg\.errors\.|psycopg\.operationalerror"),
        ("PYTHON_EXCEPTION", r"traceback \(most recent call last\)|syntaxerror|typeerror|valueerror|keyerror"),
    )
    for label, pattern in patterns:
        if re.search(pattern, stderr, flags=re.I):
            return label, "COARSE_PATTERN"
    return "UNCLASSIFIED_BACKUP_FAILURE", "NO_MATCH"


def classify_private_backup_log_details(raw: str) -> list[str]:
    """Return ONLY hard-coded diagnostic labels, never source substrings.

    The error log is already scrubbed by the protected original engine. Even
    so, its contents are untrusted, and arbitrary exception/error text must
    never reach the user console or a GitHub artifact.
    """
    allowed = frozenset((
        "BLOCKED_V223_BACKUP_AUTH_FAILED",
        "BLOCKED_V223_BACKUP_BAD_CHUNK_LENGTH",
        "BLOCKED_V223_BACKUP_BAD_HEADER",
        "BLOCKED_V223_BACKUP_KEY_INVALID",
        "BLOCKED_V223_BACKUP_KEY_MUST_BE_32_BYTES",
        "BLOCKED_V223_BACKUP_KEY_REQUIRED",
        "BLOCKED_V223_BACKUP_TRUNCATED",
        "BLOCKED_V223_BAD_SCHEMA_NAME",
        "BLOCKED_V223_DSN_MUST_BE_POSTGRESQL_URL",
        "BLOCKED_V223_ENCRYPTED_ARTIFACT_TOO_SHORT",
        "BLOCKED_V223_INVALID_CATALOG_IDENTIFIER",
        "BLOCKED_V223_MARKER_REFUSED_CLUSTER_NOT_EMPTY",
        "BLOCKED_V223_OUTPUT_EXISTS_OR_SYMLINK",
        "BLOCKED_V223_PARTIAL_DUMP_SOURCE_TRUNCATED",
        "BLOCKED_V223_REAL_SOURCE_HOST_NOT_VERIFIED",
        "BLOCKED_V223_SIGNATURE_STATEMENT_TIMEOUT",
        "BLOCKED_V223_SOURCE_IDENTITY_NOT_VERIFIED",
        "BLOCKED_V223_SOURCE_REQUIRES_VERIFY_FULL_AND_ROOT_CERT",
        "BLOCKED_V223_SOURCE_ROLE_NOT_LEAST_PRIVILEGE",
        "BLOCKED_V223_TABLE_OVER_ROW_CAP",
        "BLOCKED_V223_TABLE_TOO_LARGE_FOR_ROW_DIGEST",
        "BLOCKED_V223_TARGET_EQUALS_SOURCE",
        "BLOCKED_V223_TARGET_MUST_BE_LOCAL",
        "BLOCKED_V223_TARGET_NOT_DECLARED_EPHEMERAL",
        "BLOCKED_V223_TARGET_NOT_PROVEN_EPHEMERAL",
        "BLOCKED_V223_TOKEN_REQUIRED_MIN_16_CHARS",
        "BLOCKED_V223_TOOL_VERSION_UNKNOWN",
        "BLOCKED_V223_UNKNOWN_NEGATIVE_TEST",
        "FAIL_V223_BACKUP_DECRYPT_HASH_MISMATCH",
        "FAIL_V223_INTERRUPTED_BY_SIGNAL",
    ))
    categories = []
    stderr = raw.split("--- stderr (tail) ---", 1)[-1] if "--- stderr (tail) ---" in raw else ""
    stdout = raw.split("--- stdout (tail) ---", 1)[-1].split("--- stderr (tail) ---", 1)[0] if "--- stdout (tail) ---" in raw else ""
    matches = set(re.findall(r"\b(?:BLOCKED_V223|FAIL_V223)_[A-Za-z0-9_]+\b", stderr))
    valid = sorted(matches & allowed)
    if valid:
        categories.extend("CODE_" + item for item in valid[:4])
    if "FAIL_V223_UNEXPECTED_" in stderr:
        # Only known exception classes, even if the arbitrary suffix contains
        # potentially sensitive text. No copy of that suffix is ever printed.
        fixed = (
            "OperationalError", "ProgrammingError", "IntegrityError",
            "UndefinedTable", "UndefinedFunction", "ValueError",
            "TypeError", "KeyError", "PermissionError", "TimeoutExpired",
            "TimeoutError", "AttributeError", "FileNotFoundError",
            "UnicodeDecodeError", "IndexError", "AssertionError",
        )
        kind = next((name for name in fixed if
                     re.search(r"\bFAIL_V223_UNEXPECTED_" + name + r"\b", stderr)), None)
        categories.append("UNEXPECTED_" + kind if kind else "UNEXPECTED_OTHER_CLASS")
    patterns = (
        ("PG_DUMP", r"\bpg_dump\b"),
        ("PG_RESTORE", r"\bpg_restore\b"),
        ("SOURCE_SNAPSHOT", r"\bpg_export_snapshot\b|invalid snapshot"),
        ("TLS_OR_CERTIFICATE", r"\bSSL\b|\bTLS\b|certificate verify"),
        ("AUTHENTICATION", r"password authentication failed|authentication failed"),
        ("PERMISSION_DENIED", r"permission denied|must be owner"),
        ("NETWORK_OR_DNS", r"connection refused|could not connect|name or service not known|temporary failure in name resolution"),
        ("SQL_SYNTAX", r"\bsyntax error\b"),
        ("TIMEOUT", r"\btimeout\b|timed out"),
        ("CONCURRENT_DDL", r"lock timeout|canceling statement due to lock"),
    )
    for label, pattern in patterns:
        if re.search(pattern, stderr, flags=re.IGNORECASE):
            categories.append("PATTERN_" + label)
    # A JSON report's presence/absence is diagnostic but NOT proof of PASS.
    if '"signature_mismatches"' in stdout:
        categories.append("STDOUT_SIGNATURE_CHECK_PRESENT")
    if '"verdict"' in stdout:
        categories.append("STDOUT_VERDICT_FIELD_PRESENT")
    if re.search(r"(?m)^exit_code=(?:1|2|3)\s*$", raw):
        categories.append("CHILD_NONZERO_EXIT")
    if not stderr.strip():
        categories.append("CHILD_STDERR_EMPTY")
    return list(dict.fromkeys(categories))[:10] or ["UNCLASSIFIED_BACKUP_FAILURE"]


def diagnose_owner_only() -> int:
    """Offline owner-private failure analysis; no source role or network action.

    Output contains ONLY fixed diagnostic categories. It never prints raw error
    data, user identifiers, source table names, credentials or ciphertext.
    """
    if os.environ.get("CODESPACES") != "true":
        print("BLOCKED OWNER_CODESPACE_REQUIRED")
        return 2
    base = Path.home() / ".local" / "share" / "jw-v223-restore"
    path = base / "last_backup_error.log"
    try:
        if path.is_symlink() or not path.is_file():
            print("B2_DIAG NO_PROTECTED_ERROR_LOG")
            return 2
        st = path.stat()
        if st.st_uid != os.getuid() or st.st_mode & (stat.S_IRWXG | stat.S_IRWXO) or st.st_size > 16384:
            print("B2_DIAG ERROR_LOG_ACCESS_REFUSED")
            return 2
        raw = path.read_text(encoding="utf-8")
    except (OSError, ValueError, UnicodeError):
        print("B2_DIAG ERROR_LOG_UNREADABLE")
        return 2
    label, mode = classify_private_backup_log(raw)
    print("B2_DIAG", label)
    # More granular, still allowlisted labels. Never copy file text.
    for category in classify_private_backup_log_details(raw):
        print("B2_DETAIL", category)
    # Identify stale logs relative to the latest PRIVATE run receipt without
    # disclosing its name, content or timestamps in the public response.
    try:
        reports = [p for p in base.glob("owner_b2b3_20261117_*.json")
                   if p.is_file() and not p.is_symlink()
                   and p.stat().st_uid == os.getuid()
                   and not p.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO)]
        if reports:
            latest = max(reports, key=lambda p: p.stat().st_mtime_ns)
            print("B2_LOG_RECENCY",
                  "PREDATES_LAST_OWNER_RUN" if path.stat().st_mtime_ns + 10_000_000_000 <
                  latest.stat().st_mtime_ns else "CONSISTENT_WITH_LAST_OWNER_RUN")
            print("PRIVATE_RUN_SUMMARY", "PRESENT")
            # Private receipts are not verified evidence. Only show fixed
            # status labels with REPORTED_ / NOT_CONFIRMED prefixes.
            st = latest.stat()
            if st.st_size <= 16384:
                import json
                receipt = json.loads(latest.read_text(encoding="utf-8"))
                if isinstance(receipt, dict):
                    print("OWNER_INCIDENT_VERDICT",
                          "BLOCKED" if receipt.get("verdict") == "BLOCKED" else "NOT_CONFIRMED")
                    stages = receipt.get("stages", {})
                    if isinstance(stages, dict):
                        for name in ("temporary_login", "restricted_tls_login",
                                     "real_encrypted_backup_independent_restore",
                                     "revoke", "closed_verified"):
                            print("OWNER_STAGE", name,
                                  "REPORTED_PASS" if stages.get(name) == "PASS" else "NOT_CONFIRMED")
    except (OSError, ValueError):
        print("B2_LOG_RECENCY UNAVAILABLE")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("check", "run", "diagnose"))
    args = parser.parse_args(argv)
    try:
        commit = verify_input_checkout()
    except (Blocked, OSError, subprocess.TimeoutExpired) as exc:
        print("BLOCKED ORIGINAL_CHECKOUT_" + type(exc).__name__)
        print("NO_ROLE_CHANGE_NO_BACKUP")
        return 2

    # Diagnose does NOT open a worktree, read credentials, or contact Supabase.
    if args.action == "diagnose":
        return diagnose_owner_only()

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
