# Review only: external immutable storage validation

The private Git ciphertext vault has already passed its own integrity/readback
checks. Git history is NOT equivalent to a WORM retention guarantee.

This additive program is read-only and does not provision AWS resources,
change Object Lock configuration, upload ciphertext, move/reveal owner keys,
or read any production DB. Customer plaintext is never requested.

Requirements for a future *separately approved* real run:
- One owner-approved independent AWS S3 bucket with versioning enabled and
  Object Lock enabled. Default and EACH of 11 specific object versions must
  use COMPLIANCE retention, not GOVERNANCE or removable legal hold.
- A chosen UTC expiration threshold, appropriate storage budget/retention
  policy, block-public-access flags, pinned private vault commit, 11 stable
  version IDs, an independent custodian AWS identity, private Git read rights.
- Read-only S3/IAM permissions for bucket versioning, Object Lock configuration,
  public access block, HEAD/GET for explicit versions, object retention, and
  STS identity. All object versions must match ciphertext SHA-256 by streaming
  real bytes; object metadata/ETag alone cannot prove identity.
- Independently supplied manifest via preopened OS PIPE, JSON containing
  vault_commit_sha1 and 11 objects: blob_sha1, cipher_sha256, object_key,
  version_id. Contains no key, customer fields or access tokens.
- Environment names: JW_WORM_AUDIT_ACK, JW_WORM_EXPECTED_AWS_ACCOUNT,
  JW_WORM_BUCKET, JW_WORM_VAULT_SHA, JW_WORM_MIN_UNTIL,
  JW_WORM_MANIFEST_FD. Never put values in public GitHub, logs or chat.
- Only after those conditions and separate explicit permission:
  python -m scripts.p1_external_worm_compliance_v223 verify-readonly

All S3 reads verify the exact object VersionId and current HEAD, retention
mode and deadline, and full ciphertext SHA-256. The report omits bucket, key,
version, secret and ciphertext; release_ready remains false.

Even when S3 returns PASS, independent recovery-key custody, signer provenance
and true second-site owner-data PG17 recovery need different actual evidence.
S3 Object Lock protects pinned versions, not all future/latest versions,
and it does not retroactively sign historic backups.

Official AWS docs:
https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html
https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectRetention.html

A simulated S3 client in CI is NOT proof of a real AWS WORM bucket.

### Additional source-SHA256 parity requirement (2026-11-23)

A pinned Git tree confirms only object Git blob IDs, not arbitrary caller-supplied
cipher SHA-256 values. Before ANY S3 read, the verifier now uses the existing
private Git vault read-only blob retrieval to recompute both actual Git SHA-1
and actual ciphertext SHA-256 for all 11 pinned objects. The S3 stream must
then match the same independently provider-verified SHA-256. An attacker
replacing both the S3 version and its manifest SHA-256 cannot obtain PASS.
This adds 11 bounded private-vault readbacks per real WORM verification;
no source key, plaintext, production DB, provider write, or log of bytes.

### Inventory reconciliation and owner's approved 11-of-12 scope (2026-11-23)

The actual pinned private vault contains **13 encrypted file paths but 12
distinct Git ciphertext objects**: four historical files (three unique) plus
nine newly owner-approved ciphertexts. Existing owner backup selection contains
**eleven** unique encrypted archives. Checking that the 11-item manifest set
equals the 12-item private vault tree is incorrect (always BLOCKED).
Accept a SUBSET of the vault tree only if it matches a **separate
owner-Codespace-derived SHA-256 scope commitment** over sorted 11 Git object
identifiers. This digest is not a password or a digital signature; independently
deliver it outside the manifest pipe, and retain a signed custodian record
separately. Missing/wrong commitment blocks BEFORE any S3 operation.

Read-only owner Codespace command, with the pinned vault SHA supplied locally
in `JW_WORM_VAULT_SHA`:
`python -m scripts.p1_owner_vault_scope_pin_v223 derive-scope-pin`.
This prints the non-secret owner_scope_digest and counts only; it does not
read keys or plaintext or mutate the encrypted vault. External custodian
sets `JW_WORM_OWNER_SCOPE_SHA256` using this independent value.
The WORM audit reports vault_unique_cipher_count, and
vault_unscoped_unique_cipher_count = 1 for the current baseline.
Only the approved 11-item S3 object scope can receive a scoped PASS, NEVER
claim that the extra historical ciphertext is WORM-protected. The overall
release remains BLOCKED pending actual provider verification.
