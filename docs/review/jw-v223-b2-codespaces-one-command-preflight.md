# Backblaze B2 v4 Codespaces zero-copy, read-only owner preflight

This is the **one-command** alternative to the previously added S3/boto3
readiness adapter. Only two preexisting GitHub Codespaces secrets are needed:
- JW_B2_AUDIT_KEY_ID
- JW_B2_AUDIT_APPLICATION_KEY

No Bucket ID, bucket name, token, production database, backup key, plaintext,
or ciphertext needs to be typed, shared, saved or printed by the operator.

Owner action after selecting the JARVIS-WORKS Codespace and ensuring Codespaces
secrets are available:

python -m scripts.p1_b2_codespace_probe_v223 verify-readonly

This standalone module has only Python standard-library dependencies and
does not make changes to the checked-out Git branch, original Git vault,
Codespace backup files, Backblaze account, GitHub Secrets, or external data.
It requires CODESPACES=true and refuses an environment with source database
or backup recovery keys. It uses TLS, no proxy redirection and no HTTP
redirects; only b2_authorize_account, exact bucket-id b2_list_buckets and
b2_list_file_versions (maxFileCount=2) are invoked. A pinned SHA-256 of the
owner-selected bucket name prevents an unrelated new B2 key from qualifying.
The publicly reviewed source does not disclose actual bucket names/IDs,
credentials or provider object metadata.

Acceptance conditions:
1. B2 v4 response authorizes exactly one bucket matching the owner pin.
2. Expected Backblaze US East 005 region and approved native API endpoint.
3. App key expiry within 31 days, no write/delete/governance bypass/global-list
   privileges and required limited read capabilities.
4. Native bucket object is allPrivate, Object Lock enabled with no default
   retention yet, effective default SSE-B2 AES-256, no automatic-delete rules.
5. Native complete file-version listing is empty. Prevents hidden versions
   being falsely called an empty bucket.

The provider receipt is safe to paste: it contains boolean flags, counts,
and predefined generic blocker codes; never raw provider response fields.

This step *does not* attest that any encrypted backup has been uploaded.
Independent 11 archive SHA-256 readback, individual Object Lock Compliance
retention, owner approval of unshortenable retention, external custodian key
and PG17 restore require future evidence; remain BLOCKED or NOT RUN.

Official contract:
https://www.backblaze.com/apidocs/b2-authorize-account
https://www.backblaze.com/apidocs/b2-list-buckets
https://www.backblaze.com/apidocs/b2-list-file-versions
https://www.backblaze.com/docs/cloud-storage-application-key-capabilities
