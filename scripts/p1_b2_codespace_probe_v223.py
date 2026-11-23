"""One-command Backblaze B2 READ-ONLY bucket acceptance in the owner's Codespace.

This tool reads exactly two pre-existing Codespaces secrets and calls only
Backblaze Native v4 GET/POST read APIs. No backup/recovery key, ciphertext,
bucket/object mutation, AWS credentials, GH Actions secret or signing key.
All provider tokens, bucket identifiers, file names and raw responses stay
in volatile process memory; stdout prints only finite receipt status flags.

Invocation (the CLI command itself is explicit consent for provider reads):
python -m scripts.p1_b2_codespace_probe_v223 verify-readonly
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import time
from urllib.request import (
    Request, ProxyHandler, HTTPRedirectHandler, build_opener,
)

AUTH = "https://api.backblazeb2.com/b2api/v4/b2_authorize_account"
EXPECTED_REGION = "https://s3.us-east-005.backblazeb2.com"
BUCKET_NAME_SHA256 = "818b599eca5772d820b2b04ba3e192b5e40688fb9a715b4b1082d7b5aed2be5c"
API_RE = re.compile(r"https://api[0-9]{3}\.backblazeb2\.com")
BUCKET_ID_RE = re.compile(r"[a-z0-9]{20,40}")
REQUIRED = frozenset({
    "listBuckets", "readBuckets", "readBucketRetentions",
    "readBucketEncryption", "listFiles", "readFiles", "readFileRetentions",
})
MAX_JSON = 65536
MAX_KEY_AGE_MS = 31 * 24 * 60 * 60 * 1000
FORBIDDEN_ENV = (
    "JW_PG_BACKUP_KEY", "DATABASE_URL", "JW_PG_ADMIN_DSN",
    "JW_PG_STAGE_DSN", "JW_PG_SOURCE_DSN",
    "SUPABASE_SERVICE_ROLE_KEY", "AWS_CA_BUNDLE",
)


class Blocked(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Blocked("B2_UNEXPECTED_HTTP_REDIRECT")


def transport(url, headers, body=None):
    if url != AUTH and not API_RE.fullmatch(
        url.removesuffix("/b2api/v4/b2_list_buckets")
           .removesuffix("/b2api/v4/b2_list_file_versions")
    ):
        raise Blocked("UNTRUSTED_B2_API_ENDPOINT")
    if url != AUTH and not (
        url.endswith("/b2api/v4/b2_list_buckets")
        or url.endswith("/b2api/v4/b2_list_file_versions")
    ):
        raise Blocked("UNTRUSTED_B2_API_ENDPOINT")
    data = None if body is None else json.dumps(
        body, separators=(",", ":")).encode("utf-8")
    req = Request(url, data=data, headers=headers,
                  method="GET" if data is None else "POST")
    # Ignore inherited HTTP(S)_PROXY variables so provider credentials cannot
    # silently route to an arbitrary proxy controlled by the environment.
    opener = build_opener(ProxyHandler({}), NoRedirect())
    with opener.open(req, timeout=12) as response:
        if response.status != 200:
            raise Blocked("B2_UNEXPECTED_PROVIDER_STATUS")
        raw = response.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise Blocked("B2_PROVIDER_RESPONSE_TOO_LARGE")
    doc = json.loads(raw)
    if not isinstance(doc, dict):
        raise Blocked("B2_PROVIDER_RESPONSE_INVALID")
    return doc


def verify(*, env=None, fetch=None, now_ms=None):
    env = os.environ if env is None else env
    fetch = transport if fetch is None else fetch
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    proof = {
        "b2_owner_bucket_readonly": "BLOCKED",
        "bucket_scope_exactly_one": False,
        "key_has_no_write_or_delete": False,
        "key_expiry_checked": False,
        "bucket_private": False,
        "object_lock_enabled": False,
        "encryption_sse_b2": False,
        "keep_all_versions": False,
        "file_versions_empty": False,
        "provider_calls": 0,
        "real_backup_uploads": 0,
        "real_object_retention_proof": "NOT_RUN",
        "independent_key_custody": "NOT_ATTESTED",
        "overall_release": "BLOCKED",
    }
    if env.get("CODESPACES", "").lower() != "true":
        proof["blocker"] = "OWNER_CODESPACE_REQUIRED"
        return proof
    if any(env.get(k) for k in FORBIDDEN_ENV):
        proof["blocker"] = "SOURCE_OR_BACKUP_CREDENTIALS_MUST_BE_ISOLATED"
        return proof
    key_id = env.get("JW_B2_AUDIT_KEY_ID", "")
    key_secret = env.get("JW_B2_AUDIT_APPLICATION_KEY", "")
    if not key_id or not key_secret:
        proof["blocker"] = "CODESPACE_SECRETS_NOT_VISIBLE_RESTART_REQUIRED"
        return proof
    if not all(isinstance(x,str) and 4 <= len(x) <= 512
               and "\r" not in x and "\n" not in x for x in (key_id, key_secret)):
        proof["blocker"] = "INVALID_B2_AUDIT_KEY_FORMAT"
        return proof
    try:
        basic = base64.b64encode((key_id + ":" + key_secret).encode()).decode()
        auth = fetch(AUTH, {"Authorization": "Basic " + basic})
        proof["provider_calls"] += 1
        if not isinstance(auth, dict):
            raise Blocked("B2_AUTH_RESPONSE_INVALID")
        storage = auth.get("apiInfo", {}).get("storageApi", {})
        if not isinstance(storage, dict):
            raise Blocked("B2_AUTH_RESPONSE_INVALID")
        if storage.get("s3ApiUrl") != EXPECTED_REGION:
            raise Blocked("UNEXPECTED_B2_REGION")
        url = storage.get("apiUrl")
        if not isinstance(url, str) or not API_RE.fullmatch(url):
            raise Blocked("B2_PROVIDER_API_URL_NOT_TRUSTED")
        allowed = storage.get("allowed", {})
        if not isinstance(allowed, dict):
            raise Blocked("B2_KEY_SCOPE_UNAVAILABLE")
        buckets = allowed.get("buckets")
        if not isinstance(buckets, list) or len(buckets) != 1:
            raise Blocked("B2_KEY_MUST_BE_ONE_BUCKET_ONLY")
        selected = buckets[0]
        if not isinstance(selected,dict):
            raise Blocked("B2_BUCKET_SCOPE_INVALID")
        bucket_id, bucket_name = selected.get("id"), selected.get("name")
        if (not isinstance(bucket_id,str) or not BUCKET_ID_RE.fullmatch(bucket_id)
            or not isinstance(bucket_name,str)
            or hashlib.sha256(bucket_name.encode()).hexdigest() != BUCKET_NAME_SHA256):
            raise Blocked("B2_KEY_BUCKET_IDENTITY_MISMATCH")
        if allowed.get("namePrefix") not in (None, ""):
            raise Blocked("B2_KEY_FILE_PREFIX_UNEXPECTED")
        proof["bucket_scope_exactly_one"] = True
        caps = allowed.get("capabilities")
        if not isinstance(caps, list) or any(not isinstance(c,str) for c in caps):
            raise Blocked("B2_KEY_CAPABILITIES_UNAVAILABLE")
        capset = set(caps)
        if not REQUIRED.issubset(capset):
            raise Blocked("B2_KEY_MISSING_REQUIRED_READ_CAPABILITY")
        if any(c.startswith(("write", "delete")) or c in (
                "bypassGovernance", "listAllBucketNames", "listKeys") for c in capset):
            raise Blocked("B2_KEY_EXCESSIVE_PRIVILEGES")
        proof["key_has_no_write_or_delete"] = True
        expiry = auth.get("applicationKeyExpirationTimestamp")
        if (type(expiry) is not int or
                not now_ms < expiry <= now_ms + MAX_KEY_AGE_MS):
            raise Blocked("B2_KEY_EXPIRY_NOT_PROVEN_SHORT_LIVED")
        proof["key_expiry_checked"] = True
        token,account_id = auth.get("authorizationToken"), auth.get("accountId")
        if not isinstance(token,str) or not token or not isinstance(account_id,str) or not account_id:
            raise Blocked("B2_NATIVE_AUTH_TOKEN_INVALID")
        headers = {"Authorization": token, "Content-Type":"application/json"}
        bucket_data = fetch(url + "/b2api/v4/b2_list_buckets",
                            headers, {"accountId":account_id, "bucketId":bucket_id})
        proof["provider_calls"] += 1
        found = bucket_data.get("buckets")
        if not isinstance(found,list) or len(found) != 1 or not isinstance(found[0],dict):
            raise Blocked("B2_EXPECTED_BUCKET_NOT_RETURNED")
        bucket = found[0]
        if (bucket.get("bucketId") != bucket_id
            or bucket.get("bucketName") != bucket_name
            or bucket.get("bucketType") != "allPrivate"):
            raise Blocked("B2_BUCKET_IS_NOT_EXPECTED_PRIVATE_BUCKET")
        proof["bucket_private"] = True
        lock = bucket.get("fileLockConfiguration", {})
        if (not isinstance(lock,dict)
            or lock.get("isClientAuthorizedToRead") is not True
            or not isinstance(lock.get("value"),dict)
            or lock["value"].get("isFileLockEnabled") is not True):
            raise Blocked("B2_OBJECT_LOCK_NOT_ENABLED_OR_UNREADABLE")
        default = lock["value"].get("defaultRetention")
        if (not isinstance(default,dict)
            or default.get("mode") is not None or default.get("period") is not None):
            raise Blocked("B2_UNAPPROVED_DEFAULT_RETENTION")
        proof["object_lock_enabled"] = True
        encryption = bucket.get("defaultServerSideEncryption", {})
        if (not isinstance(encryption,dict)
            or encryption.get("isClientAuthorizedToRead") is not True
            or not isinstance(encryption.get("value"),dict)
            or encryption["value"].get("mode") != "SSE-B2"
            or encryption["value"].get("algorithm") != "AES256"):
            raise Blocked("B2_DEFAULT_ENCRYPTION_NOT_VERIFIED")
        proof["encryption_sse_b2"] = True
        if bucket.get("lifecycleRules") != []:
            raise Blocked("B2_UNEXPECTED_DELETION_LIFECYCLE")
        proof["keep_all_versions"] = True
        versions = fetch(url + "/b2api/v4/b2_list_file_versions",
                         headers, {"bucketId":bucket_id,"maxFileCount":2})
        proof["provider_calls"] += 1
        if (not isinstance(versions.get("files"),list)
            or versions["files"]
            or versions.get("nextFileName") is not None
            or versions.get("nextFileId") is not None):
            raise Blocked("B2_BUCKET_VERSION_INVENTORY_NOT_EMPTY")
        proof["file_versions_empty"] = True
        proof["b2_owner_bucket_readonly"] = "PASS_REAL_B2_EMPTY_LOCK_ENABLED"
    except Blocked as exc:
        proof["blocker"] = str(exc)
    except Exception:
        proof["blocker"] = "B2_PROVIDER_READ_FAILED_WITHOUT_SECRET_DISCLOSURE"
    # Successful empty bucket readiness still is NOT WORM protection of 11
    # ciphertext archives, independent key custody or release authorization.
    return proof


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv != ["verify-readonly"]:
        print("USAGE: python -m scripts.p1_b2_codespace_probe_v223 verify-readonly",
              file=sys.stderr)
        return 2
    proof = verify()
    print(json.dumps(proof,sort_keys=True,separators=(",", ":")))
    return 0 if proof["b2_owner_bucket_readonly"] == "PASS_REAL_B2_EMPTY_LOCK_ENABLED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
