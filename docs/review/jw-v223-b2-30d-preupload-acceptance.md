# JARVIS-WORKS V22.3 — 30-day COMPLIANCE pre-upload acceptance

## Owner consent and protected boundaries

Owner approved **30 days** COMPLIANCE retention for the exact original eleven
encrypted backups and required verifying their integrity and upload permissions
**before uploading**. This review commit prepares a read-only gate, NOT an
uploader. No Backblaze object write, 30-day lock, recovery-key disclosure,
new API key, private vault mutation, database access, main merge, UI or Render
deployment is authorized by this code.

- Existing owner Codespaces originals: exactly 11 local, owner-only mode
  0600 regular ciphertexts, under the historically verified 0700 private
  backup root; no broad filesystem search; no symlinks or arbitrary paths
  accepted, bounded scan/file sizes, no plaintext or decryption.
- Existing PRIVATE GitHub backup vault: repository main pinned to
  65d2d4b98badd8231d65bf8553cb434a4a5141f9.
  Exact 13 file paths / 12 unique ciphertext Git blob identities; approved
  owner local 11 must be a subset with exactly one out-of-scope historical
  unique blob. Read actual 11 remote Git blob bytes through GitHub GET-only
  to recompute both Git SHA1 and SHA256; local hashes checked against
  remote hash from the SAME actual blob, not a supplied manifest.
- Owner scope digest: canonical domain-separated SHA256 of sorted 11 Git
  blob identifiers, printed only as a non-secret fingerprint. It is not a
  legal signature, historical provenance or custody proof.
- Third Backblaze B2 bucket: reuses prior actually successful
  **read-only empty private Object-Lock-enabled SSE-B2** probe via its
  exact SHA-pinned implementation, in an isolated Python child with ONLY
  two pre-existing B2 read-only Codespaces Secrets, no owner DB/backup
  secrets or GitHub token. If bucket is no longer empty, default retention
  changed or read-only key invalid, gate BLOCKS.
- **Uploader policy analysis**: A distinct short-lived bucket/prefix-limited
  key must have *both* \`writeFiles\` and \`writeFileRetentions\`, while
  forbidding \`deleteFiles\`, \`bypassGovernance\`, bucket mutations,
  global list-all and other unnecessary privileges. Those distinct write
  credentials **do not exist/are not visible here**. Without an actual
  scoped key audit the upload remains BLOCKED — read-only key must never
  be changed to Read and Write just to bypass this.

Backblaze B2 native and S3-compatible API officially require writeFiles
for upload and writeFileRetentions for object-level COMPLIANCE.
COMPLIANCE retention is set **during the upload**, not on a copy briefly
left unprotected. An individual retained version's lock cannot be shortened.
Only after real preupload gate and upload credential PASS may an entirely
separate upload module be developed/reviewed. At real upload time use UTC
\`now + 30 days\` as minimum retained-until threshold, verify each
VersionId, COMPLIANCE mode, retain-until and full remote SHA256 by readback.
Never call read-only tests an actual WORM proof.

Official references:
- https://www.backblaze.com/docs/cloud-storage-object-lock
- https://www.backblaze.com/docs/cloud-storage-enable-object-lock-with-the-native-api
- https://www.backblaze.com/docs/cloud-storage-s3-compatible-app-keys
- https://www.backblaze.com/docs/cloud-storage-application-key-capabilities

## Owner's one-command check — NO write API

Fetch reviewed full commit and execute content-addressed script through stdin
from owner's existing Codespaces. This does not checkout or change the
worktree and needs no manually reentered secrets:

\`set -o pipefail; git fetch -q origin review/jw-v223-external-custodian-pg17-20261123 && git show <EXACT_REVIEW_SHA>:scripts/p1_b2_preupload_integrity_v223.py | python - preflight-30-days\`

Possible outcomes:
- \`preupload=PASS_OWNER_AND_B2_READ_ONLY\` with the eleven SHA256, private
  vault parity and B2 readiness all PASS: first three prerequisite gates
  succeeded for the OWNER environment, but \`overall=BLOCKED\` until a
  distinct least-privilege upload key passes provider audit.
- Any \`BLOCKED\`: do not upload; investigate the fixed generic failure
  code. Never show raw key contents, source backup paths, blob identifiers
  or plaintext in logs.
- The code uses Python standard library only and does NOT call a provider
  API that mutates B2 or GitHub data.

This preflight makes no claim that a backup has actually been uploaded,
protected by 30-day COMPLIANCE, or independently restored.
