"""Read-only Backblaze B2 readiness for an owner-created, empty WORM bucket.

No backup/key material is sent to ChatGPT/GitHub. No file upload, no retention
change, no file/key deletion, no bucket mutation, no backup decryption.
Use a dedicated bucket-restricted, short-lived B2 READ ONLY application key.
All provider identifiers and credentials arrive from protected local env.
DO NOT run this code in public GitHub Actions with real provider credentials.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import time
from urllib.request import Request, build_opener, HTTPRedirectHandler

ACK = "OWNER_APPROVES_B2_READ_ONLY_BUCKET_PREFLIGHT"
AUTH_URL = "https://api.backblazeb2.com/b2api/v4/b2_authorize_account"
BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9-]{4,62}")
ID_RE = re.compile(r"[a-z0-9]{20,40}")
S3_RE = re.compile(r"https://s3\.([a-z]{2}-[a-z]+-\d{3})\.backblazeb2\.com")
NATIVE_RE = re.compile(r"https://api\d{3}\.backblazeb2\.com")
SOURCE_SECRETS = (
    "JW_PG_BACKUP_KEY", "DATABASE_URL", "JW_PG_STAGE_DSN",
    "JW_PG_ADMIN_DSN", "JW_PG_SOURCE_DSN", "SUPABASE_SERVICE_ROLE_KEY",
)
REQUIRED_READ = frozenset((
    "listBuckets", "readBuckets", "listFiles", "readFiles",
    "readBucketRetentions", "readFileRetentions", "readBucketEncryption",
))
MAX_JSON = 65536


class Blocked(RuntimeError):
    pass


def preflight(env=None):
    env = os.environ if env is None else env
    if env.get("JW_B2_AUDIT_ACK") != ACK:
        return "EXPLICIT_READ_ONLY_APPROVAL_REQUIRED"
    if any(env.get(k) for k in SOURCE_SECRETS):
        return "SOURCE_OR_BACKUP_SECRET_NOT_ISOLATED"
    if any(env.get(k) for k in (
        "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3",
        "AWS_CA_BUNDLE", "BOTO_CONFIG", "AWS_SHARED_CREDENTIALS_FILE")):
        return "UNTRUSTED_ENDPOINT_OR_CA_OVERRIDE"
    if not env.get("JW_B2_AUDIT_KEY_ID") or not env.get("JW_B2_AUDIT_APPLICATION_KEY"):
        return "B2_READ_ONLY_CREDENTIALS_NOT_CONNECTED"
    if not BUCKET_RE.fullmatch(env.get("JW_B2_AUDIT_BUCKET", "")):
        return "OWNER_BUCKET_NAME_REQUIRED"
    if not ID_RE.fullmatch(env.get("JW_B2_AUDIT_BUCKET_ID", "")):
        return "OWNER_BUCKET_ID_REQUIRED"
    if not S3_RE.fullmatch(env.get("JW_B2_AUDIT_ENDPOINT", "")):
        return "PINNED_B2_S3_ENDPOINT_REQUIRED"
    return "PASS"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise Blocked("B2_PROVIDER_REDIRECT_DENIED")


def _transport(url, headers, body=None):
    """Default provider-only transport with no cross-host credential redirects."""
    if url != AUTH_URL and not re.fullmatch(
        r"https://api\d{3}\.backblazeb2\.com/b2api/v4/b2_list_buckets", url
    ):
        raise Blocked("B2_UNTRUSTED_NATIVE_API_URL")
    request = Request(url, data=body, headers=headers,
                      method="POST" if body is not None else "GET")
    opener = build_opener(_NoRedirect)
    with opener.open(request, timeout=12) as response:
        raw = response.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise Blocked("B2_RESPONSE_TOO_LARGE")
    return json.loads(raw)


def _native_attest(env, transport, now_ms):
    key_id = env["JW_B2_AUDIT_KEY_ID"]
    key = env["JW_B2_AUDIT_APPLICATION_KEY"]
    basic = base64.b64encode((key_id + ":" + key).encode("utf-8")).decode("ascii")
    auth = transport(AUTH_URL, {"Authorization": "Basic " + basic})
    api = auth.get("apiInfo", {}).get("storageApi", {})
    allowed = api.get("allowed", {})
    expected = env["JW_B2_AUDIT_ENDPOINT"]
    if api.get("s3ApiUrl") != expected:
        raise Blocked("B2_AUTH_REGION_ENDPOINT_MISMATCH")
    url = api.get("apiUrl", "")
    if not NATIVE_RE.fullmatch(url):
        raise Blocked("B2_NATIVE_ENDPOINT_UNTRUSTED")
    buckets = allowed.get("buckets")
    if not isinstance(buckets, list) or len(buckets) != 1 or not isinstance(buckets[0], dict):
        raise Blocked("B2_KEY_NOT_RESTRICTED_TO_ONE_BUCKET")
    if (buckets[0].get("id") != env["JW_B2_AUDIT_BUCKET_ID"]
            or buckets[0].get("name") != env["JW_B2_AUDIT_BUCKET"]):
        raise Blocked("B2_KEY_WRONG_BUCKET_SCOPE")
    if allowed.get("namePrefix") not in (None, ""):
        raise Blocked("B2_KEY_HAS_UNEXPECTED_PREFIX")
    caps = allowed.get("capabilities")
    if not isinstance(caps, list) or not all(isinstance(x, str) for x in caps):
        raise Blocked("B2_CAPABILITIES_UNVERIFIABLE")
    caps = frozenset(caps)
    if not REQUIRED_READ.issubset(caps):
        raise Blocked("B2_REQUIRED_READ_CAPABILITY_MISSING")
    if any(x.startswith(("write", "delete")) or x in (
            "bypassGovernance", "listKeys") for x in caps):
        raise Blocked("B2_KEY_HAS_EXCESSIVE_MUTATION_PERMISSIONS")
    expiry = auth.get("applicationKeyExpirationTimestamp")
    if (type(expiry) is not int or
            not now_ms < expiry <= now_ms + 31 * 24 * 60 * 60 * 1000):
        raise Blocked("B2_KEY_EXPIRY_NOT_SHORT_LIVED")
    token = auth.get("authorizationToken")
    account = auth.get("accountId")
    if not isinstance(token, str) or not token or not isinstance(account, str) or not account:
        raise Blocked("B2_PROVIDER_AUTH_RESPONSE_INVALID")
    native = transport(
        url + "/b2api/v4/b2_list_buckets",
        {"Authorization": token, "Content-Type": "application/json"},
        json.dumps({"accountId": account, "bucketId": env["JW_B2_AUDIT_BUCKET_ID"]}).encode()
    )
    found = native.get("buckets")
    if not isinstance(found, list) or len(found) != 1:
        raise Blocked("B2_PINNED_BUCKET_NOT_FOUND")
    info = found[0]
    if (info.get("bucketId") != env["JW_B2_AUDIT_BUCKET_ID"] or
            info.get("bucketName") != env["JW_B2_AUDIT_BUCKET"] or
            info.get("bucketType") != "allPrivate"):
        raise Blocked("B2_BUCKET_NOT_THE_EXPECTED_PRIVATE_BUCKET")
    lock = info.get("fileLockConfiguration", {})
    if (lock.get("isClientAuthorizedToRead") is not True or
            lock.get("value", {}).get("isFileLockEnabled") is not True):
        raise Blocked("B2_OBJECT_LOCK_NOT_ENABLED_OR_NOT_READABLE")
    default = lock["value"].get("defaultRetention", {})
    if default and (default.get("mode") is not None or default.get("period") is not None):
        raise Blocked("B2_UNAPPROVED_DEFAULT_RETENTION_SETTING")
    encryption = info.get("defaultServerSideEncryption", {})
    if (encryption.get("isClientAuthorizedToRead") is not True or
            encryption.get("value", {}).get("mode") != "SSE-B2" or
            encryption["value"].get("algorithm") != "AES256"):
        raise Blocked("B2_DEFAULT_ENCRYPTION_NOT_SSE_B2")
    lifecycle = info.get("lifecycleRules")
    if lifecycle != []:
        raise Blocked("B2_UNEXPECTED_AUTOMATIC_DELETION_RULES")
    return {"read_only_scope_attested": True,
            "provider_private_bucket_attested": True,
            "object_lock_enabled_attested": True,
            "sse_b2_enabled_attested": True,
            "owner_key_short_lived": True,
            "extra_share_files_capability": "shareFiles" in caps}


def _read_s3(env, s3):
    endpoint = getattr(getattr(s3, "meta", None), "endpoint_url", "")
    if endpoint != env["JW_B2_AUDIT_ENDPOINT"]:
        raise Blocked("B2_S3_CLIENT_ENDPOINT_MISMATCH")
    bucket = env["JW_B2_AUDIT_BUCKET"]
    if s3.get_bucket_versioning(Bucket=bucket).get("Status") != "Enabled":
        raise Blocked("B2_S3_VERSIONING_NOT_ENABLED")
    lock = s3.get_object_lock_configuration(Bucket=bucket).get(
        "ObjectLockConfiguration", {})
    if lock.get("ObjectLockEnabled") != "Enabled":
        raise Blocked("B2_S3_OBJECT_LOCK_NOT_ENABLED")
    if lock.get("Rule", {}).get("DefaultRetention", {}).get("Mode") not in (None, ""):
        raise Blocked("B2_S3_UNAPPROVED_DEFAULT_RETENTION")
    listing = s3.list_object_versions(Bucket=bucket, MaxKeys=2)
    if listing.get("IsTruncated") is not False:
        raise Blocked("B2_S3_OBJECT_VERSION_LIST_INCOMPLETE")
    if listing.get("Versions") or listing.get("DeleteMarkers"):
        raise Blocked("B2_BUCKET_NOT_EMPTY_REQUIRES_DIFFERENTIAL_REVIEW")
    return True


def verify(*, env=None, transport=None, s3=None, now_ms=None):
    env = os.environ if env is None else env
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    receipt = {
        "b2_readiness": "BLOCKED",
        "read_only_scope_attested": False,
        "provider_private_bucket_attested": False,
        "object_lock_enabled_attested": False,
        "sse_b2_enabled_attested": False,
        "owner_key_short_lived": False,
        "empty_bucket_version_listing_attested": False,
        "actual_11_archives_uploaded": False,
        "actual_compliance_versions_verified": 0,
        "independent_custodian": "NOT_ATTESTED",
        "ciphertext_or_key_exfiltrated": False,
        "provider_data_mutated": False,
        "overall": "BLOCKED",
    }
    guard = preflight(env)
    if guard != "PASS":
        receipt["blocker"] = guard
        return receipt
    try:
        receipt.update(_native_attest(env, transport or _transport, now_ms))
        if s3 is None:
            import boto3
            from botocore.config import Config
            region = S3_RE.fullmatch(env["JW_B2_AUDIT_ENDPOINT"]).group(1)
            s3 = boto3.session.Session().client(
                "s3",
                region_name=region,
                endpoint_url=env["JW_B2_AUDIT_ENDPOINT"],
                aws_access_key_id=env["JW_B2_AUDIT_KEY_ID"],
                aws_secret_access_key=env["JW_B2_AUDIT_APPLICATION_KEY"],
                config=Config(signature_version="s3v4",
                              retries={"max_attempts": 1},
                              s3={"addressing_style": "path"}),
            )
        _read_s3(env, s3)
        receipt["empty_bucket_version_listing_attested"] = True
        receipt["b2_readiness"] = "PASS_EMPTY_PRIVATE_B2_BUCKET_READ_ONLY"
        # Empty bucket readiness is not immutable 11-version backup proof.
    except Blocked as exc:
        receipt["blocker"] = str(exc)
    except Exception:
        # Intentionally never expose HTTP bodies, URLs, identifiers or tokens.
        receipt["blocker"] = "B2_EXTERNAL_READ_FAILED"
    return receipt


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv != ["verify-readonly-empty"]:
        print("USAGE: python -m scripts.p1_backblaze_b2_readonly_v223 verify-readonly-empty",
              file=sys.stderr)
        return 2
    result = verify()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["b2_readiness"] == "PASS_EMPTY_PRIVATE_B2_BUCKET_READ_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
