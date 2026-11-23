# V22.3 Backblaze B2 read-only readiness: owner-created third vault

**Scope and authority:** This is an additive, opt-in, READ ONLY probe for a
separately created and privately owned Backblaze B2 bucket. It does NOT
upload ciphertext, provision a bucket, alter Object Lock or Compliance
retention, modify credentials, or claim independent PG17 restore.
The original Git backup vault, Render staging, main and operational DB are
completely outside this probe. It must NOT run in public GitHub CI with
real keys. CI exercises synthetic provider fixtures ONLY.

## Why this is not the original AWS S3 verifier

Backblaze exposes an S3-compatible API but bucket-restricted read-only
application keys are NOT AWS STS/IAM identities. The existing AWS verifier
uses STS GetCallerIdentity, ExpectedBucketOwner and S3 Block Public Access,
which are inappropriate here. Backblaze uses a v4 Native API
b2_authorize_account response to attest the short-lived bucket-restricted
key's capabilities and native b2_list_buckets to verify actual bucketType,
server-side encryption, Object Lock and lifecycle policy. The S3 API then
cross-checks versioning, Object Lock and that the bucket is initially empty.

The currently selected B2 key does not include "Allow list all bucket names".
This is intentional; native b2_list_buckets is called with the exact bucket
ID, and S3 ListBuckets is NOT called. No new privilege grant is required.

## Protected runtime environment variables (never in GitHub source or logs)

- JW_B2_AUDIT_ACK: OWNER_APPROVES_B2_READ_ONLY_BUCKET_PREFLIGHT
- JW_B2_AUDIT_KEY_ID: owner-stored short-lived read-only application key ID
- JW_B2_AUDIT_APPLICATION_KEY: owner-stored application secret
- JW_B2_AUDIT_BUCKET: owner private bucket name (not in public repository)
- JW_B2_AUDIT_BUCKET_ID: owner pinned bucket ID
- JW_B2_AUDIT_ENDPOINT: owner pinned HTTPS regional endpoint

Use a separate isolated owner-controlled runtime without production DSNs
or source backup recovery key in its environment. Never place any of these
credential *values* in GitHub Actions, repository plaintext, chat, PR,
workflow_dispatch parameters or public issues. App key is deliberately
limited to 30 days; script checks the key's actual expiry date and that it
cannot upload/delete/change objects or provider configuration.

After secure environment configuration, owner executes:
python -m scripts.p1_backblaze_b2_readonly_v223 verify-readonly-empty

The structured receipt is deliberately free of credential values, bucket
identifiers, or object filenames. It reports only pass/blocker and boolean
proof flags. It produces PASS_EMPTY_PRIVATE_B2_BUCKET_READ_ONLY **only** if
all read-only provider checks actually finish. Its overall remains BLOCKED
because no 11 original owner-approved ciphertexts have been uploaded or
locked and no independent key custody/PG17 restore is evidenced.

## Next independent tasks requiring separately scoped approval

1. Derive original owner-held eleven-archive scope commitment in the
   existing protected Codespace and transfer digest separately (no key).
2. Create a DISTINCT minimal uploader credential with only specific
   bucket write capabilities; no user key in chat or GitHub CI.
3. Choose a concrete minimum COMPLIANCE retention period; this cannot
   be shortened on those protected object versions. Keep bucket default
   retention UNCONFIGURED until an explicit owner period is approved.
4. Encrypt-only upload of precisely approved 11 bytes-identical Git
   private-vault objects. Read back every S3 VersionId and full SHA256 and
   COMPLIANCE retain-until date with the independent read-only auditor.
5. Independently held restore key and actual isolated PG17 second-site
   restore, historical source provenance and signed custodian acceptance.

This probe is a prerequisite only and must not be reported as WORM proof.

Official references:
https://www.backblaze.com/apidocs/b2-authorize-account
https://www.backblaze.com/apidocs/b2-list-buckets
https://www.backblaze.com/docs/cloud-storage-s3-compatible-app-keys
https://www.backblaze.com/apidocs/s3-get-object-lock-configuration
https://www.backblaze.com/docs/cloud-storage-object-lock
