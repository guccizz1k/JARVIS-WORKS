"""Fail-closed environment-isolated launcher for the pinned native Backblaze read-only probe.

Run only in owner's Codespace. Never mutates caller os.environ, repository,
key store, original backups, bucket, or retention policy. Executes the
reviewed *pinned* probe in a separate Python -I -S process with ONLY two
existing B2 read-only credentials and CODESPACES=true (no source DB or
backup secrets). This is process-environment isolation only, NOT an
independent computer, sandboxed filesystem, or independent key custodian.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

# Exact immutable Git blob object instead of editable branch/working tree.
# The parent review SHA remains recorded in GitHub CI evidence.
PINNED_PROBE_SHA = "8f3b19ab652a846ad4f86c439f0103f40f55c88a"
PROBE_REF = PINNED_PROBE_SHA
B2_KEY_NAMES = ("JW_B2_AUDIT_KEY_ID", "JW_B2_AUDIT_APPLICATION_KEY")
ALLOWED_ENV_KEYS = frozenset((
    "CODESPACES", "JW_B2_AUDIT_KEY_ID", "JW_B2_AUDIT_APPLICATION_KEY",
    "LANG", "PYTHONIOENCODING", "PYTHONDONTWRITEBYTECODE", "PATH",
))
GIT_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/nonexistent",
    "LANG": "C",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
}
CHILD_ENV_FIXED = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "PYTHONIOENCODING": "utf-8",
    "PYTHONDONTWRITEBYTECODE": "1",
    "CODESPACES": "true",
}
MAX_SOURCE_BYTES = 30000
MAX_RECEIPT_BYTES = 4096

SAFE_FLAGS = (
    "bucket_scope_exactly_one", "key_has_no_write_or_delete",
    "key_expiry_checked", "bucket_private", "object_lock_enabled",
    "encryption_sse_b2", "keep_all_versions", "file_versions_empty",
)
# Never print untrusted strings or provider error bodies, only these codes.
SAFE_BLOCKERS = frozenset((
    "OWNER_CODESPACE_REQUIRED", "CODESPACE_SECRETS_NOT_VISIBLE_RESTART_REQUIRED",
    "PINNED_PROBE_SOURCE_UNAVAILABLE", "PINNED_PROBE_SOURCE_INVALID",
    "PROBE_TIMEOUT_OR_RUNTIME_ERROR", "PROBE_RETURNED_UNSAFE_RECEIPT",
    "PROBE_EXIT_STATUS_INCONSISTENT", "B2_PROVIDER_READ_FAILED_WITHOUT_SECRET_DISCLOSURE",
    "B2_PROVIDER_API_URL_NOT_TRUSTED", "UNEXPECTED_B2_REGION",
    "B2_KEY_MUST_BE_ONE_BUCKET_ONLY", "B2_KEY_BUCKET_IDENTITY_MISMATCH",
    "B2_KEY_FILE_PREFIX_UNEXPECTED", "B2_KEY_MISSING_REQUIRED_READ_CAPABILITY",
    "B2_KEY_EXCESSIVE_PRIVILEGES", "B2_KEY_EXPIRY_NOT_PROVEN_SHORT_LIVED",
    "B2_NATIVE_AUTH_TOKEN_INVALID", "B2_EXPECTED_BUCKET_NOT_RETURNED",
    "B2_BUCKET_IS_NOT_EXPECTED_PRIVATE_BUCKET",
    "B2_OBJECT_LOCK_NOT_ENABLED_OR_UNREADABLE",
    "B2_UNAPPROVED_DEFAULT_RETENTION",
    "B2_DEFAULT_ENCRYPTION_NOT_VERIFIED",
    "B2_UNEXPECTED_DELETION_LIFECYCLE",
    "B2_BUCKET_VERSION_INVENTORY_NOT_EMPTY", "UNTRUSTED_B2_API_ENDPOINT",
    "B2_UNEXPECTED_HTTP_REDIRECT", "B2_UNEXPECTED_PROVIDER_STATUS",
    "B2_PROVIDER_RESPONSE_TOO_LARGE", "B2_PROVIDER_RESPONSE_INVALID",
    "SOURCE_OR_BACKUP_CREDENTIALS_MUST_BE_ISOLATED",
    "INVALID_B2_AUDIT_KEY_FORMAT", "B2_AUTH_RESPONSE_INVALID",
    "B2_KEY_SCOPE_UNAVAILABLE", "B2_BUCKET_SCOPE_INVALID",
    "B2_AUTH_PAIR_INVALID_401", "B2_AUTH_VERSION_UNSUPPORTED_401",
    "B2_AUTH_401_UNCLASSIFIED", "B2_AUTH_ACCESS_DENIED_403",
    "B2_PROVIDER_RATE_LIMITED_429", "B2_PROVIDER_HTTP_REJECTED",
    "B2_PROVIDER_TLS_VERIFY_FAILED", "B2_PROVIDER_DNS_LOOKUP_FAILED",
    "B2_PROVIDER_NETWORK_TIMEOUT", "B2_PROVIDER_DIRECT_NETWORK_UNAVAILABLE",
))
DEFAULT_BLOCKER = "PROBE_RETURNED_UNSAFE_RECEIPT"


def _record(blocker=""):
    receipt = {
        "b2_owner_bucket_readonly": "BLOCKED",
        "blocker": blocker or DEFAULT_BLOCKER,
        "provider_calls": 0,
        "two_secrets_reused_without_reentry": False,
        "source_database_credentials_in_child": False,
        "source_backup_credentials_in_child": False,
        "child_env_whitelist_only": False,
        "repository_mutated": False,
        "remote_bucket_mutated": False,
        "independent_custodian": "NOT_ATTESTED",
        "actual_backup_objects_uploaded": 0,
        "overall_release": "BLOCKED",
    }
    return receipt


def _isolated_env(parent):
    if parent.get("CODESPACES", "").lower() != "true":
        return None, "OWNER_CODESPACE_REQUIRED"
    values = [parent.get(key) for key in B2_KEY_NAMES]
    if not all(isinstance(v,str) and v for v in values):
        return None, "CODESPACE_SECRETS_NOT_VISIBLE_RESTART_REQUIRED"
    if not all(4 <= len(v) <= 512 and "\n" not in v and "\r" not in v
               for v in values):
        return None, "INVALID_B2_AUDIT_KEY_FORMAT"
    child = {**CHILD_ENV_FIXED, **dict(zip(B2_KEY_NAMES, values))}
    if set(child) != ALLOWED_ENV_KEYS:
        return None, "PROBE_RETURNED_UNSAFE_RECEIPT"
    return child, None


def verify(*, parent=None, runner=None):
    """No network until a separate, whitelisted child reads the B2 auth API.

    runner is injectable solely for CI; production uses subprocess.run.
    """
    parent = os.environ if parent is None else parent
    runner = subprocess.run if runner is None else runner
    result = _record()
    child_env, problem = _isolated_env(parent)
    if problem:
        result["blocker"] = problem
        return result
    result["two_secrets_reused_without_reentry"] = True
    result["child_env_whitelist_only"] = True
    try:
        # Git show is LOCAL ONLY. This uses a content-addressed reviewed
        # Git blob SHA1, never the editable checkout or working tree.
        pin = runner(
            ["git", "show", PROBE_REF],
            env=GIT_ENV, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=12, check=False,
        )
        if pin.returncode != 0 or not isinstance(pin.stdout, bytes):
            result["blocker"] = "PINNED_PROBE_SOURCE_UNAVAILABLE"
            return result
        if (not 5000 <= len(pin.stdout) <= MAX_SOURCE_BYTES
                or b"def verify(" not in pin.stdout
                or b"def main(" not in pin.stdout):
            result["blocker"] = "PINNED_PROBE_SOURCE_INVALID"
            return result
        child = runner(
            [sys.executable, "-I", "-S", "-", "verify-readonly"],
            input=pin.stdout, env=child_env,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=35, check=False,
        )
        if (not isinstance(child.stdout, bytes)
                or len(child.stdout) > MAX_RECEIPT_BYTES):
            result["blocker"] = "PROBE_RETURNED_UNSAFE_RECEIPT"
            return result
        raw = json.loads(child.stdout.decode("utf-8"))
        if (not isinstance(raw, dict) or
                raw.get("overall_release") != "BLOCKED"
                or raw.get("real_backup_uploads") != 0):
            result["blocker"] = "PROBE_RETURNED_UNSAFE_RECEIPT"
            return result
        result["provider_calls"] = (
            raw.get("provider_calls") if type(raw.get("provider_calls")) is int
            and 0 <= raw["provider_calls"] <= 3 else 0
        )
        if raw.get("b2_owner_bucket_readonly") == "PASS_REAL_B2_EMPTY_LOCK_ENABLED":
            if (child.returncode != 0 or result["provider_calls"] != 3
                    or not all(raw.get(k) is True for k in SAFE_FLAGS)):
                result["blocker"] = "PROBE_EXIT_STATUS_INCONSISTENT"
                return result
            result["b2_owner_bucket_readonly"] = "PASS_REAL_B2_EMPTY_LOCK_ENABLED"
            result.pop("blocker")
            # Not a valid independent-custodian or WORM-copy proof.
            return result
        if child.returncode == 0:
            result["blocker"] = "PROBE_EXIT_STATUS_INCONSISTENT"
            return result
        blocker = raw.get("blocker")
        result["blocker"] = blocker if blocker in SAFE_BLOCKERS else DEFAULT_BLOCKER
    except (Exception, KeyboardInterrupt):
        # Provider raw errors, connection strings and credentials must never
        # be included in stdout or GitHub logs, even on unexpected failures.
        result["blocker"] = "PROBE_TIMEOUT_OR_RUNTIME_ERROR"
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args != ["verify-readonly"]:
        print("USAGE: python - scripts/p1_b2_isolated_launcher_v223.py verify-readonly",
              file=sys.stderr)
        return 2
    result = verify()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["b2_owner_bucket_readonly"] == (
        "PASS_REAL_B2_EMPTY_LOCK_ENABLED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
