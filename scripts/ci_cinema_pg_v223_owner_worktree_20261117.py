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
    """Classify prior scrubbed error text into fixed public labels only.

    The private log is not copied, returned or uploaded. Error data is
    untrusted: even labels are diagnostic hints, never evidence of a PASS.
    """
    tail = raw.split("--- stderr (tail) ---", 1)[-1] if "--- stderr (tail) ---" in raw else raw
    m = re.search(r"\b(BLOCKED_V223_[A-Za-z0-9_]{1,90}|FAIL_V223_[A-Za-z0-9_]{1,90})\b", tail)
    if m:
        return m.group(1), "ENGINE_MACHINE_CODE"
    # These are coarse diagnostic categories, not a replacement for actual
    # error analysis. Never include regex captures from the private file.
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
        if re.search(pattern, tail, flags=re.I):
            return label, "COARSE_PATTERN"
    return "UNCLASSIFIED_BACKUP_FAILURE", "NO_MATCH"


def diagnose_owner_only() -> int:
    """Read-only private incident triage. No DB access, login or backup.

    This output is deliberately limited to known code labels, immutable
    stage names and status enums. Never print raw logs, exception text,
    file paths, DSNs, hostnames, key material or table/customer names.
    """
    if os.environ.get("CODESPACES") != "true":
        print("BLOCKED OWNER_CODESPACE_REQUIRED")
        return 2
    private = Path.home() / ".local" / "share" / "jw-v223-restore"
    log_path = private / "last_backup_error.log"
    try:
        if log_path.is_symlink() or not log_path.is_file():
            print("B2_DIAG NO_PROTECTED_ERROR_LOG")
            return 2
        st = log_path.stat()
        if (st.st_uid != os.getuid() or st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
                or st.st_size > 16384):
            print("B2_DIAG ERROR_LOG_ACCESS_REFUSED")
            return 2
        raw = log_path.read_text(encoding="utf-8")
    except (OSError, ValueError, UnicodeError):
        print("B2_DIAG ERROR_LOG_UNREADABLE")
        return 2

    label, certainty = classify_private_backup_log(raw)
    print("B2_DIAG", label)
    print("B2_DIAG_CLASS", certainty)
    m = re.search(r"(?m)^exit_code=([0-9]{1,3})$", raw)
    if m:
        print("B2_CHILD_EXIT", m.group(1) if m.group(1) in {"0","1","2","124","126","127","137","139","143"} else "OTHER")
    else:
        print("B2_CHILD_EXIT", "UNKNOWN")
    print("B2_LOG_HAS_STDERR", "YES" if raw.split("--- stderr (tail) ---",1)[-1].strip() else "NO")
    # Stage outcomes are from our private, structured summary only, NOT
    # the raw untrusted backup log and NOT proof of DR success.
    permitted = ("temporary_login", "restricted_tls_login",
                 "real_encrypted_backup_independent_restore",
                 "revoke", "closed_verified")
    candidates = sorted(private.glob("owner_b2b3_20261117_*.json"), reverse=True)
    if not candidates:
        print("OWNER_INCIDENT_REPORT", "ABSENT")
        return 0
    candidate = candidates[0]
    try:
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError("invalid owner report")
        st = candidate.stat()
        if (st.st_uid != os.getuid() or st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
                or st.st_size > 16384):
            raise ValueError("unsafe owner report")
        import json
        report = json.loads(candidate.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ValueError("invalid owner report")
        print("OWNER_INCIDENT_REPORT", "PRESENT")
        status = report.get("verdict")
        print("OWNER_INCIDENT_VERDICT", "BLOCKED" if status != "PASS" else "CLAIMED_PASS_NOT_REVERIFIED")
        stages = report.get("stages")
        if not isinstance(stages, dict):
            stages = {}
        for stage in permitted:
            print("OWNER_STAGE", stage, "REPORTED_PASS" if stages.get(stage) == "PASS" else "NOT_CONFIRMED")
        lag = st.st_mtime - log_path.stat().st_mtime
        print("B2_LOG_RELATION", "POSSIBLY_STALE" if lag > 180 or lag < -60 else "NEAR_OWNER_RUN")
    except (OSError, ValueError, UnicodeError, TypeError):
        print("OWNER_INCIDENT_REPORT", "UNREADABLE_OR_UNSAFE")
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
