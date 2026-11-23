"""Owner-only pre-upload 30-day COMPLIANCE gate; strictly NO remote writes.

Checks exactly 11 unmodified owner-local AES-GCM ciphertexts against the pinned
private Git backup vault (13 paths, 12 unique Git blobs), byte-for-byte
SHA-256 and Git blob SHA-1, plus current isolated Backblaze B2 empty-bucket
read-only readiness. Writer capability remains unverified until an independent
minimal upload key is provided. Never reads the AES key, backup plaintext,
PostgreSQL, or any production DSN; never uploads or changes Object Lock.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

VAULT_REPO = "repos/guccizz1k/jw-backup-vault-261111"
VAULT_SHA = "65d2d4b98badd8231d65bf8553cb434a4a5141f9"
B2_REVIEW_SHA = "af3fcae0384a07904e60f024f824cae2c8cea4f0"
B2_LAUNCHER = B2_REVIEW_SHA + ":scripts/p1_b2_isolated_launcher_v223.py"
ROOT_REL = ".local/share/jw-v223-restore/backups"
MAGIC = (b"JWPGBK1\n", b"JWPGBK2\n")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_SIZE = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
REMOTE_PATHS = 13
REMOTE_UNIQUE = 12
LOCAL_UNIQUE = 11
RETENTION_DAYS = 30
UPLOAD_PREFIX = "jw-v223/approved-30d-20261124/"
# Public repository pins identity by SHA256, not the owner's bucket name.
B2_BUCKET_NAME_SHA256 = "818b599eca5772d820b2b04ba3e192b5e40688fb9a715b4b1082d7b5aed2be5c"


class Blocked(Exception):
    pass


def _private_file(path):
    info = path.lstat()
    return (stat.S_ISREG(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.getuid())


def _private_dir(path):
    st = path.lstat()
    return (stat.S_ISDIR(st.st_mode)
            and stat.S_IMODE(st.st_mode) == 0o700
            and st.st_uid == os.getuid())


def _local_files(root=None):
    root = Path.home() / ROOT_REL if root is None else Path(root)
    try:
        if not _private_dir(root):
            raise Blocked("OWNER_PRIVATE_ARCHIVE_DIRECTORY_INVALID")
        paths, seen, count = [], set(), 0
        with os.scandir(root) as outer:
            for entry in outer:
                count += 1
                if count > 256:
                    raise Blocked("OWNER_BACKUP_SCAN_LIMIT")
                if entry.name.endswith(".jwpgbk"):
                    if not entry.is_file(follow_symlinks=False):
                        raise Blocked("OWNER_CIPHER_UNSAFE_FILE_TYPE")
                    if not _private_file(Path(entry.path)):
                        raise Blocked("OWNER_CIPHER_PERMISSIONS_INVALID")
                    paths.append(Path(entry.path))
                elif (entry.is_dir(follow_symlinks=False)
                      and entry.name.startswith("jw_v223_")
                      and _private_dir(Path(entry.path))):
                    with os.scandir(entry.path) as inner:
                        for item in inner:
                            count += 1
                            if count > 256:
                                raise Blocked("OWNER_BACKUP_SCAN_LIMIT")
                            if item.name.endswith(".jwpgbk"):
                                if not item.is_file(follow_symlinks=False):
                                    raise Blocked("OWNER_CIPHER_UNSAFE_FILE_TYPE")
                                if not _private_file(Path(item.path)):
                                    raise Blocked("OWNER_CIPHER_PERMISSIONS_INVALID")
                                paths.append(Path(item.path))
                if len(paths) > 16:
                    raise Blocked("OWNER_BACKUP_EXCESS_FILES")
        if len(paths) != LOCAL_UNIQUE:
            raise Blocked("OWNER_ELEVEN_ARCHIVES_REQUIRED")
        result = {}
        total = 0
        for path in paths:
            git_sha, strong, size = _hash_file(path)
            total += size
            if total > MAX_TOTAL:
                raise Blocked("OWNER_ENCRYPTED_TOTAL_OVER_LIMIT")
            if git_sha in seen:
                raise Blocked("OWNER_DUPLICATE_CIPHERTEXT")
            seen.add(git_sha)
            result[git_sha] = strong
        return result
    except (OSError, ValueError) as exc:
        raise Blocked("OWNER_LOCAL_ARCHIVE_ACCESS_FAILED") from None


def _hash_file(path):
    if not _private_file(path):
        raise Blocked("OWNER_CIPHER_PERMISSIONS_INVALID")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or
                stat.S_IMODE(before.st_mode) != 0o600 or
                before.st_uid != os.getuid() or
                not 24 < before.st_size <= MAX_SIZE):
            raise Blocked("OWNER_CIPHER_UNSAFE_AFTER_OPEN")
        header = stream.read(8)
        if header not in MAGIC:
            raise Blocked("OWNER_CIPHER_MAGIC_INVALID")
        g = hashlib.sha1(b"blob " + str(before.st_size).encode() + b"\0")
        h = hashlib.sha256()
        g.update(header)
        h.update(header)
        length = 8
        while block := stream.read(131072):
            length += len(block)
            if length > MAX_SIZE:
                raise Blocked("OWNER_CIPHER_TOO_LARGE")
            g.update(block)
            h.update(block)
        after = os.fstat(stream.fileno())
        ident = lambda x: (x.st_dev, x.st_ino, x.st_size,
                           x.st_mtime_ns, x.st_ctime_ns)
        if length != before.st_size or ident(after) != ident(before):
            raise Blocked("OWNER_CIPHER_CHANGED_DURING_READ")
        return g.hexdigest(), h.hexdigest(), length


def _gh_get(endpoint):
    if not (endpoint.startswith(VAULT_REPO + "/git/") and
            len(endpoint) < 200 and "\r" not in endpoint and
            "\n" not in endpoint and " " not in endpoint):
        raise Blocked("INVALID_PRIVATE_VAULT_READ_ENDPOINT")
    # GitHub-only CLI child. Never passes B2 keys, source DB connection
    # strings or owner recovery keys to the GitHub process environment.
    # Explicit allowlist; GH sees no B2 key, DB password, recovery secret,
    # HTTP(S) proxy, AWS config, or unrelated Codespaces secrets.
    env = {
        "HOME": str(Path.home()),
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    vaulted = os.environ.get("JW_VAULT_READ_TOKEN") or os.environ.get("GH_TOKEN")
    if vaulted:
        env["GH_TOKEN"] = vaulted
    try:
        p = subprocess.run(["gh", "api", endpoint, "--method", "GET",
                            "--header", "Accept: application/vnd.github+json"],
                           env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           check=False, timeout=75)
        if p.returncode or len(p.stdout) > 2 * MAX_SIZE + 8192:
            raise Blocked("PINNED_PRIVATE_VAULT_READ_UNAVAILABLE")
        doc = json.loads(p.stdout)
        if not isinstance(doc, dict):
            raise Blocked("PRIVATE_VAULT_RESPONSE_INVALID")
        return doc
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        raise Blocked("PINNED_PRIVATE_VAULT_READ_UNAVAILABLE") from None


def _verify_remote(local, get=None, pinned_scope_digest=None):
    get = _gh_get if get is None else get
    if len(local) != LOCAL_UNIQUE or not all(
            SHA1.fullmatch(k) and SHA256.fullmatch(v)
            for k, v in local.items()):
        raise Blocked("ELEVEN_LOCAL_CIPHER_SHA_REQUIRED")
    prefix = VAULT_REPO + "/git/"
    ref = get(prefix + "ref/heads/main")
    if ref.get("object", {}).get("sha") != VAULT_SHA:
        raise Blocked("PRIVATE_VAULT_MAIN_MOVED")
    commit = get(prefix + "commits/" + VAULT_SHA)
    tree = commit.get("tree", {})
    if commit.get("sha") != VAULT_SHA or not SHA1.fullmatch(tree.get("sha", "")):
        raise Blocked("PRIVATE_VAULT_PINNED_TREE_UNVERIFIED")
    listing = get(prefix + "trees/" + tree["sha"] + "?recursive=1")
    if listing.get("truncated") is not False or not isinstance(listing.get("tree"), list):
        raise Blocked("PRIVATE_VAULT_TREE_TRUNCATED")
    entries = [x for x in listing["tree"] if x.get("type") == "blob"]
    if (len(entries) != REMOTE_PATHS or
            any(x.get("mode") != "100644" or
                not isinstance(x.get("path"), str) or
                not x["path"].endswith(".jwpgbk") or
                not SHA1.fullmatch(x.get("sha", ""))
                for x in entries)):
        raise Blocked("PRIVATE_VAULT_13_CIPHER_TREE_CHANGED")
    remotes = [x["sha"] for x in entries]
    if len(set(remotes)) != REMOTE_UNIQUE:
        raise Blocked("PRIVATE_VAULT_12_UNIQUE_CIPHER_BASELINE_CHANGED")
    if not set(local).issubset(set(remotes)) or len(set(remotes) - set(local)) != 1:
        raise Blocked("ELEVEN_OWNER_CIPHERS_NOT_EXACT_VAULT_SUBSET")
    # A local 11-of-12 subset does not establish independent OWNER scope:
    # a changed local file can swap one historical cipher for another.
    # Require the owner's separately approved exact 11-blob commitment
    # BEFORE downloading or trusting ANY particular subset as authorized.
    scope = ("JW-WORM-OWNER-SCOPE-V1\n" + "\n".join(sorted(local)) + "\n").encode()
    fingerprint = hashlib.sha256(scope).hexdigest()
    if pinned_scope_digest is not None:
        if (not isinstance(pinned_scope_digest, str)
                or not SHA256.fullmatch(pinned_scope_digest)
                or fingerprint != pinned_scope_digest):
            raise Blocked("OWNER_APPROVED_SCOPE_PIN_MISMATCH")
    # Git blob identity and SHA256 must BOTH be computed from actual
    # provider bytes; don't trust a caller-supplied hash manifest.
    for blob, strong in sorted(local.items()):
        item = get(prefix + "blobs/" + blob)
        if (item.get("sha") != blob or item.get("encoding") != "base64"
                or type(item.get("size")) is not int
                or not 24 < item["size"] <= MAX_SIZE
                or not isinstance(item.get("content"), str)
                or len(item["content"]) > 2 * MAX_SIZE):
            raise Blocked("PRIVATE_VAULT_CIPHER_BLOB_METADATA_INVALID")
        try:
            raw = base64.b64decode("".join(item["content"].split()), validate=True)
        except (ValueError, UnicodeError):
            raise Blocked("PRIVATE_VAULT_CIPHER_BASE64_INVALID") from None
        if (len(raw) != item["size"] or raw[:8] not in MAGIC
                or hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != blob
                or hashlib.sha256(raw).hexdigest() != strong):
            raise Blocked("PRIVATE_VAULT_CIPHER_CONTENT_DIFFERENT")
    return {"owner_scope_digest": fingerprint,
            "verified_archive_count": LOCAL_UNIQUE,
            "vault_cipher_paths": REMOTE_PATHS,
            "vault_unique_cipher_blobs": REMOTE_UNIQUE,
            "excluded_extra_unique_blob": 1}


def _b2_readonly():
    # Code pinned to previously successful LIVE native B2 probe; use
    # 2 existing READ ONLY secrets only and no source credentials in
    # either child process. The B2 launcher is itself environment-isolated.
    try:
        p = subprocess.run(["git", "show", B2_LAUNCHER],
                           stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, timeout=15, check=False)
        if p.returncode or not 5000 < len(p.stdout) < 16000:
            raise Blocked("PINNED_B2_READONLY_CODE_UNAVAILABLE")
        safe = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
                "CODESPACES": "true", "PYTHONDONTWRITEBYTECODE": "1"}
        for key in ("JW_B2_AUDIT_KEY_ID", "JW_B2_AUDIT_APPLICATION_KEY"):
            value = os.environ.get(key)
            if not isinstance(value, str) or not value:
                raise Blocked("B2_EXISTING_READONLY_SECRETS_UNAVAILABLE")
            safe[key] = value
        child = subprocess.run([sys.executable, "-I", "-S", "-", "verify-readonly"],
                               input=p.stdout, env=safe, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, timeout=55, check=False)
        if child.returncode or len(child.stdout) > 4096:
            raise Blocked("REAL_B2_EMPTY_BUCKET_READONLY_FAILED")
        doc = json.loads(child.stdout)
        if (doc.get("b2_owner_bucket_readonly") != "PASS_REAL_B2_EMPTY_LOCK_ENABLED"
                or doc.get("provider_calls") != 3
                or doc.get("child_env_whitelist_only") is not True
                or doc.get("remote_bucket_mutated") is not False
                or doc.get("actual_backup_objects_uploaded") != 0):
            raise Blocked("REAL_B2_EMPTY_BUCKET_READONLY_FAILED")
        return True
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        raise Blocked("REAL_B2_EMPTY_BUCKET_READONLY_FAILED") from None


def validate_upload_key_capabilities(allowed, *, now_ms):
    """Contract for a *future* distinct short-lived uploader, no API writes.

    UI Write-Only credentials may still be broader than required; never
    auto-assume a key is safe merely because it is labeled Write Only.
    """
    if not isinstance(allowed, dict):
        return "UPLOAD_KEY_SCOPE_UNVERIFIABLE"
    bucket = allowed.get("buckets")
    if (not isinstance(bucket, list) or len(bucket) != 1
            or not isinstance(bucket[0], dict)
            or not isinstance(bucket[0].get("name"), str)
            or hashlib.sha256(bucket[0]["name"].encode("utf-8")).hexdigest()
                != B2_BUCKET_NAME_SHA256):
        return "UPLOAD_KEY_NOT_RESTRICTED_TO_OWNER_BUCKET"
    if allowed.get("namePrefix") != UPLOAD_PREFIX:
        return "UPLOAD_KEY_PREFIX_MISMATCH"
    caps = allowed.get("capabilities")
    if not isinstance(caps, list) or any(not isinstance(x, str) for x in caps):
        return "UPLOAD_KEY_CAPABILITIES_UNVERIFIABLE"
    c = set(caps)
    if not {"writeFiles", "writeFileRetentions"}.issubset(c):
        return "UPLOAD_KEY_MISSING_COMPLIANCE_OR_WRITE_PERMISSION"
    if any(x.startswith(("delete", "writeBucket", "writeKey")) or x in (
            "bypassGovernance", "writeFileLegalHolds", "listAllBucketNames",
            "readFiles", "shareFiles") for x in c):
        return "UPLOAD_KEY_UNNECESSARY_OR_DESTRUCTIVE_PERMISSION"
    return "UPLOAD_KEY_CAPABILITY_SCOPE_VALID"


def verify(*, local=None, get=None, b2=None, env=None):
    env = os.environ if env is None else env
    out = {
        "preupload": "BLOCKED",
        "retention_mode_approved": "COMPLIANCE",
        "approved_retention_days": RETENTION_DAYS,
        "owner_source_eleven_sha256": "NOT_RUN",
        "private_vault_readback": "NOT_RUN",
        "backblaze_empty_bucket_readonly": "NOT_RUN",
        "uploader_write_and_retention_scope": "NOT_CONFIGURED",
        "upload_count": 0,
        "compliance_object_versions_verified": 0,
        "original_archive_mutated": False,
        "recovery_key_accessed": False,
        "overall": "BLOCKED",
    }
    if env.get("CODESPACES", "").lower() != "true":
        out["blocker"] = "OWNER_CODESPACE_REQUIRED"
        return out
    try:
        selected = _local_files() if local is None else local
        owner_pin = env.get("JW_WORM_OWNER_SCOPE_SHA256") or None
        info = _verify_remote(selected, get=get, pinned_scope_digest=owner_pin)
        out["owner_source_eleven_sha256"] = "PASS"
        out["private_vault_readback"] = "PASS"
        out.update(info)
        if b2 is None:
            _b2_readonly()
        elif b2() is not True:
            raise Blocked("REAL_B2_EMPTY_BUCKET_READONLY_FAILED")
        out["backblaze_empty_bucket_readonly"] = "PASS"
        if owner_pin is None:
            # Report cryptographic candidate evidence only, do not upgrade
            # it to owner-APPROVED source scope or upload eligibility.
            out["owner_scope_selected_pin"] = "NOT_ATTESTED"
            out["preupload"] = "PASS_UNPINNED_PARITY_AND_B2_ONLY"
            out["blocker"] = "OWNER_ELEVEN_CIPHER_SCOPE_PIN_REQUIRED"
            return out
        out["owner_scope_selected_pin"] = "PASS_EXACT_OWNER_PIN"
        out["preupload"] = "PASS_OWNER_AND_B2_READ_ONLY"
        # No independent WRITER credential exists yet. Do not upload.
        out["blocker"] = "DISTINCT_MINIMAL_UPLOADER_KEY_NOT_CONFIGURED"
    except Blocked as exc:
        out["blocker"] = str(exc)
    except Exception:
        out["blocker"] = "PREUPLOAD_UNEXPECTED_FAILURE"
    return out


def main(argv=None):
    if (sys.argv[1:] if argv is None else argv) != ["preflight-30-days"]:
        print("USAGE: python - preflight-30-days", file=sys.stderr)
        return 2
    result = verify()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["preupload"] == "PASS_OWNER_AND_B2_READ_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
