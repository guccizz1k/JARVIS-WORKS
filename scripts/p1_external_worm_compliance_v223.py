"""Read-only independent S3 Object Lock evidence for pinned private cipher versions.

No object upload, retention-policy update, delete, custody key, or plaintext.
Provider S3 Compliance retention is a point-in-time version-level proof only;
this does NOT prove separate key custody, signed historic source identity,
continuous observability, legal certification or a released production system.

Usage is intentionally owner/custodian opt-in, not GitHub CI/Render autostart.
The 11-object manifest arrives from a separate OS pipe and is checked against
the pinned private vault tree. AWS credentials remain only in the custodian's
credential chain, never in argv, app logs or the public repository.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from scripts import p1_cleanroom_key_recovery_v223 as vault

ACK = "OWNER_APPROVES_EXTERNAL_WORM_READ_ONLY_AUDIT"
BLOB_LIMIT = 32 * 1024 * 1024
TOTAL_LIMIT = 128 * 1024 * 1024
MANIFEST_LIMIT = 16 * 1024
ENTRIES = 11
ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
BUCKET_RE = re.compile(r"^(?=.{3,63}$)[a-z0-9][a-z0-9.-]*[a-z0-9]$")
KEY_RE = re.compile(r"^[a-zA-Z0-9/_\-.]{1,256}$")
VERSION_RE = re.compile(r"^[a-zA-Z0-9._~+=/-]{1,256}$")
FORBIDDEN = (
    "JW_PG_BACKUP_KEY", "JW_PG_STAGE_DSN", "JW_PG_AUTH_STAGE_DSN",
    "JW_PG_ADMIN_DSN", "DATABASE_URL", "JW_PG_SOURCE_DSN",
    "JW_PG_TARGET_ADMIN_DSN", "SUPABASE_SERVICE_ROLE_KEY",
    "JW_PG_VAULT_READ_TOKEN",
)


class Blocked(RuntimeError):
    pass


def _timestamp(s):
    if not isinstance(s, str) or not re.fullmatch(
            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|\+00:00)", s):
        raise Blocked("OWNER_RETENTION_DATE_MISSING_OR_INVALID")
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise Blocked("OWNER_RETENTION_DATE_MISSING_OR_INVALID") from None


def preflight(env=None, *, now=None):
    env = os.environ if env is None else env
    now = datetime.now(timezone.utc) if now is None else now
    if env.get("JW_WORM_AUDIT_ACK") != ACK:
        return "READ_ONLY_AUDIT_CONSENT_REQUIRED"
    if env.get("CODESPACES", "").lower() == "true":
        return "INDEPENDENT_CUSTODIAN_RUNTIME_REQUIRED"
    if any(env.get(k) for k in FORBIDDEN):
        return "SOURCE_OR_BACKUP_SECRET_PRESENT"
    if any(env.get(k) for k in ("AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3",
                                  "AWS_ENDPOINT_URL_STS", "AWS_CA_BUNDLE")):
        return "CUSTOM_S3_ENDPOINT_NOT_ALLOWED"
    if not ACCOUNT_RE.fullmatch(env.get("JW_WORM_EXPECTED_AWS_ACCOUNT", "")):
        return "EXPECTED_BUCKET_OWNER_REQUIRED"
    if not BUCKET_RE.fullmatch(env.get("JW_WORM_BUCKET", "")):
        return "STRICT_BUCKET_NAME_REQUIRED"
    if not vault.SHA1.fullmatch(env.get("JW_WORM_VAULT_SHA", "")):
        return "PINNED_PRIVATE_VAULT_COMMIT_REQUIRED"
    try:
        expected = _timestamp(env.get("JW_WORM_MIN_UNTIL", ""))
    except Blocked as exc:
        return str(exc)
    if expected <= now:
        return "RETENTION_DEADLINE_NOT_FUTURE"
    if not env.get("JW_WORM_MANIFEST_FD"):
        return "INDEPENDENT_MANIFEST_PIPE_REQUIRED"
    return "PASS"


def _manifest(env):
    try:
        raw = vault._read_pipe(env.get("JW_WORM_MANIFEST_FD"),
                               MANIFEST_LIMIT, "INDEPENDENT_MANIFEST_PIPE_REQUIRED")
        doc = json.loads(raw)
    except (ValueError, UnicodeError, TypeError):
        raise Blocked("WORM_MANIFEST_INVALID") from None
    if (not isinstance(doc, dict) or
            doc.get("vault_commit_sha1") != env["JW_WORM_VAULT_SHA"] or
            not isinstance(doc.get("objects"), list) or
            len(doc["objects"]) != ENTRIES):
        raise Blocked("WORM_MANIFEST_ELEVEN_EXACT_VERSIONS_REQUIRED")
    seen_blobs, seen_objects = set(), set()
    checked = []
    for obj in doc["objects"]:
        if not isinstance(obj, dict):
            raise Blocked("WORM_MANIFEST_ENTRY_INVALID")
        blob, digest = obj.get("blob_sha1"), obj.get("cipher_sha256")
        key, version = obj.get("object_key"), obj.get("version_id")
        if (not isinstance(blob, str) or not vault.SHA1.fullmatch(blob)
                or not isinstance(digest, str) or not vault.SHA256.fullmatch(digest)
                or not isinstance(key, str) or not KEY_RE.fullmatch(key)
                or any(p in ("", ".", "..") for p in key.split("/"))
                or not isinstance(version, str) or not VERSION_RE.fullmatch(version)
                or version == "null"):
            raise Blocked("WORM_MANIFEST_ENTRY_INVALID")
        if blob in seen_blobs or (key, version) in seen_objects:
            raise Blocked("WORM_DUPLICATE_BLOB_OR_S3_VERSION")
        seen_blobs.add(blob)
        seen_objects.add((key, version))
        checked.append((blob, digest, key, version))
    return checked


def _provider_client_is_aws(client, *, service="s3"):
    endpoint = urlparse(getattr(getattr(client, "meta", None),
                                "endpoint_url", "") or "")
    return (endpoint.scheme == "https"
            and not endpoint.username and not endpoint.password
            and endpoint.port in (None, 443)
            and bool(re.fullmatch(
                rf"{service}(?:[.-][a-z0-9-]+)*\.amazonaws\.com(?:\.cn)?",
                endpoint.hostname or "")))


def _safe_s3_read(s3, *, bucket, key, version, owner, expected_sha):
    args = {"Bucket":bucket, "Key":key, "VersionId":version,
            "ExpectedBucketOwner":owner}
    retained = s3.get_object_retention(**args).get("Retention", {})
    # LegalHold ON is not a substitute for Compliance; governance can be
    # bypassed by privileged callers and must never qualify.
    if retained.get("Mode") != "COMPLIANCE":
        raise Blocked("OBJECT_VERSION_NOT_IN_COMPLIANCE_MODE")
    until = retained.get("RetainUntilDate")
    if not isinstance(until, datetime) or until.tzinfo is None:
        raise Blocked("PROVIDER_RETENTION_DATE_UNVERIFIABLE")
    if until.astimezone(timezone.utc) < expected_sha["min_until"]:
        raise Blocked("OBJECT_VERSION_RETENTION_TOO_SHORT")
    head = s3.head_object(**args)
    current = s3.head_object(Bucket=bucket, Key=key,
                             ExpectedBucketOwner=owner)
    if head.get("VersionId") != version or current.get("VersionId") != version:
        raise Blocked("PINNED_OBJECT_VERSION_NOT_CURRENT")
    size = head.get("ContentLength")
    if (type(size) is not int or not 24 <= size <= BLOB_LIMIT or
            current.get("ContentLength") != size):
        raise Blocked("ENCRYPTED_OBJECT_LENGTH_UNSAFE")
    response = s3.get_object(**args)
    if (response.get("VersionId") != version or
            response.get("ContentLength") != size):
        raise Blocked("S3_READBACK_VERSION_OR_LENGTH_MISMATCH")
    stream = response.get("Body")
    if stream is None or not hasattr(stream, "read"):
        raise Blocked("S3_RESPONSE_BODY_UNAVAILABLE")
    count = 0
    prefix = b""
    checksum = hashlib.sha256()
    try:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                raise Blocked("S3_RESPONSE_BODY_INVALID")
            count += len(chunk)
            if count > size:
                raise Blocked("S3_CIPHERTEXT_OVERSIZE")
            if len(prefix) < 8:
                prefix += chunk[:8-len(prefix)]
            checksum.update(chunk)
    finally:
        stream.close()
    if (count != size or prefix not in (b"JWPGBK1\n", b"JWPGBK2\n")
            or checksum.hexdigest() != expected_sha["cipher_sha256"]):
        raise Blocked("S3_CIPHERTEXT_SHA256_OR_MAGIC_MISMATCH")
    return count


def verify(*, s3=None, sts=None, env=None, now=None):
    env = os.environ if env is None else env
    now = datetime.now(timezone.utc) if now is None else now
    result = {
        "worm_readonly_audit": "BLOCKED",
        "compliance_version_count": 0,
        "actual_sha256_readback_count": 0,
        "private_vault_tree_verified": False,
        "ciphertext_or_key_exported": False,
        "decrypted_data_read": False,
        "independent_recovery_key_custody": "NOT_ATTESTED",
        "external_custodian_signature": "NOT_ATTESTED",
        "original_source_era_signature": "NOT_ATTESTED",
        "legal_compliance_certification": "NOT_ATTESTED",
        "release_ready": False,
        "overall": "BLOCKED",
    }
    check = preflight(env, now=now)
    if check != "PASS":
        result["blocker"] = check
        return result
    try:
        expected_date = _timestamp(env["JW_WORM_MIN_UNTIL"])
        entries = _manifest(env)
        pin = env["JW_WORM_VAULT_SHA"]
        trusted = vault._head_tree(pin)
        if set(row[0] for row in entries) != trusted:
            raise Blocked("WORM_MANIFEST_NOT_EXACT_PRIVATE_VAULT_TREE")
        result["private_vault_tree_verified"] = True
        if s3 is None or sts is None:
            import boto3
            session = boto3.session.Session()
            if s3 is None:
                s3 = session.client("s3")
            if sts is None:
                sts = session.client("sts")
        if not _provider_client_is_aws(s3):
            raise Blocked("AWS_PROVIDER_ENDPOINT_UNTRUSTED")
        if not _provider_client_is_aws(sts, service="sts"):
            raise Blocked("AWS_STS_PROVIDER_ENDPOINT_UNTRUSTED")
        owner = env["JW_WORM_EXPECTED_AWS_ACCOUNT"]
        if sts.get_caller_identity().get("Account") != owner:
            raise Blocked("AWS_CALLER_ACCOUNT_MISMATCH")
        bucket = env["JW_WORM_BUCKET"]
        versioning = s3.get_bucket_versioning(
            Bucket=bucket, ExpectedBucketOwner=owner)
        if versioning.get("Status") != "Enabled":
            raise Blocked("S3_BUCKET_VERSIONING_NOT_ENABLED")
        lock = s3.get_object_lock_configuration(
            Bucket=bucket, ExpectedBucketOwner=owner).get(
                "ObjectLockConfiguration", {})
        default = lock.get("Rule", {}).get("DefaultRetention", {})
        if (lock.get("ObjectLockEnabled") != "Enabled"
                or default.get("Mode") != "COMPLIANCE"
                or not any(type(default.get(k)) is int and default[k] > 0
                           for k in ("Days", "Years"))):
            raise Blocked("S3_BUCKET_DEFAULT_COMPLIANCE_MISSING")
        public = s3.get_public_access_block(
            Bucket=bucket, ExpectedBucketOwner=owner).get(
                "PublicAccessBlockConfiguration", {})
        if not all(public.get(k) is True for k in (
                "BlockPublicAcls", "IgnorePublicAcls",
                "BlockPublicPolicy", "RestrictPublicBuckets")):
            raise Blocked("S3_BUCKET_PUBLIC_ACCESS_NOT_BLOCKED")
        total = 0
        for blob, digest, key, version in entries:
            n = _safe_s3_read(s3, bucket=bucket, key=key, version=version,
                owner=owner, expected_sha={
                    "cipher_sha256":digest, "min_until":expected_date})
            total += n
            if total > TOTAL_LIMIT:
                raise Blocked("S3_TOTAL_CIPHERTEXT_LIMIT_EXCEEDED")
            result["actual_sha256_readback_count"] += 1
            result["compliance_version_count"] += 1
        if result["compliance_version_count"] != ENTRIES:
            raise Blocked("NOT_ALL_ELEVEN_VERSION_OBJECTS_VERIFIED")
        result["worm_readonly_audit"] = "PASS_ELEVEN_S3_COMPLIANCE_VERSIONS"
        # Deliberately BLOCKED overall: a point-in-time WORM read does not
        # prove separate custodian/key, future retention or production release.
    except Blocked as exc:
        result["blocker"] = str(exc)
    except Exception:
        # AWS errors must never echo HTTP body, bucket/keys, IAM tokens, IDs.
        result["blocker"] = "EXTERNAL_WORM_PROVIDER_READ_FAILED"
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv != ["verify-readonly"]:
        print("USAGE: python -m scripts.p1_external_worm_compliance_v223 verify-readonly",
              file=sys.stderr)
        return 2
    result = verify()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["worm_readonly_audit"] == (
        "PASS_ELEVEN_S3_COMPLIANCE_VERSIONS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
