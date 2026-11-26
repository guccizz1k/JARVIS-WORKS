# V22.3 — Owner Codespaces Backblaze read-only isolated process launcher

**Symptom:** The existing owner Codespace keeps PostgreSQL backup/source
credentials in its environment. The pinned B2 verifier intentionally returned
SOURCE_OR_BACKUP_CREDENTIALS_MUST_BE_ISOLATED with provider_calls=0,
preventing an accidental source-key / third-party-cloud credential mixture.

**No bypass:** Do not disable the original verifier's preflight, erase existing
secrets from the owner Codespace, or paste B2 keys into a shell command.

This additive launcher:
1. Refuses if running outside the owner's Codespace, or the two **already
   configured** read-only B2 Codespaces secrets are not present.
2. Loads the previously reviewed B2 verifier solely via local git show on
   pinned full SHA `fa93a675a0bc4a8adf18e566c5c4d7ab7419ffc7`.
   No checkout or main/branch reset.
3. Starts a NEW Python `-I -S` process with an **exact environment
   whitelist**. Child receives only CODESPACES=true, two B2 read-only secrets,
   a static PATH/LANG and Python hygiene flags. All PostgreSQL variables,
   backup keys, GH_TOKEN, HTTPS_PROXY, PYTHONPATH and other environment data
   remain in the parent and never appear in the child process environment.
   Local `git show` receives a separate environment with no keys at all.
4. Retains the verifier's *unaltered* full preflight. No filesystem reads of
   original encrypted backup files, no network to PostgreSQL, no GitHub secret
   reads, no B2 object uploads, no bucket configuration/retention changes.
5. Prints a strictly finite receipt comprising generic outcomes and booleans.
   No keys, bucket names, provider identifiers, bearer tokens or HTTP error
   contents are printed, including on errors or timeout.

This is **process environment segregation**, NOT cryptographic independence,
a separate filesystem, dedicated hardware, second-site key custody or audited
WORM storage. Owner's current Codespace remains a mixed-use host; it must never
be classified as an independent second custodian based on this launcher.

## Owner mobile-friendly terminal command

Use the JARVIS-WORKS owner's existing Codespace, *not GitHub Actions*.

`git fetch -q origin review/jw-v223-external-custodian-pg17-20261123 && git show <CURRENT_APPROVED_REVIEW_SHA>:scripts/p1_b2_isolated_launcher_v223.py | python - verify-readonly`

Replace CURRENT_APPROVED_REVIEW_SHA only with the **exact CI-verified commit**.
Do not export, paste, display or rotate any B2 key in the terminal.

Interpretation:
- PASS_REAL_B2_EMPTY_LOCK_ENABLED with provider_calls=3: read-only live B2
  private/locked/encrypted/empty-bucket preflight succeeded.
- CODESPACE_SECRETS_NOT_VISIBLE_RESTART_REQUIRED: restart Codespace to pick
  up newly created Codespaces secrets; do not print their values.
- B2_PROVIDER_READ_FAILED_WITHOUT_SECRET_DISCLOSURE: real authorization or
  network error; inspect provider account/access privately; never paste keys.
- Any other BLOCKED code: fail closed, investigate without relaxing guards.

**Separate work after readiness**: owner chooses Compliance retention duration,
approves a distinct least-privilege *write* credential, encrypted-only upload
of exactly 11 owner-approved ciphertext blobs, independent readback/retention,
second-site owner-key custodian and actual PG17 recovery.

No B2 service work is done from CI; tests use only synthetic credentials.

## Distinguishing the first live provider failure

Owner screenshot showed the isolated child correctly excluded backup/DB
credentials; `provider_calls=0` and a previous catch-all provider failure
could not distinguish rejected B2 credentials from HTTPS egress problems.

The original official B2 Native v4 GET `b2_authorize_account` endpoint is
correct; do not silently downgrade API versions or use the master key.
The current diagnostic probe is pinned by **content-addressed Git blob SHA1**
`3d94191e3df75998e5e36135e338fe8c56820b69` and only emits allowlisted safe codes:
- `B2_AUTH_KEY_REJECTED_401`: server rejected key ID/application key pair;
  verify source of Codespaces secrets privately, never paste/print values.
- `B2_AUTH_ACCESS_DENIED_403`: app key or account access denied.
- `B2_PROVIDER_RATE_LIMITED_429`: rate limit, don't retry blindly.
- `B2_PROVIDER_TLS_VERIFY_FAILED`: TLS/certificate validation failed.
- `B2_PROVIDER_DNS_LOOKUP_FAILED`: local resolver issue.
- `B2_PROVIDER_NETWORK_TIMEOUT`: direct HTTPS timeout.
- `B2_PROVIDER_DIRECT_NETWORK_UNAVAILABLE`: network routing/proxy
  configuration blocked direct HTTPS; **do not weaken TLS or automatically
  forward Basic authentication through untrusted proxies**.
- `B2_PROVIDER_HTTP_REJECTED`: other sanitized HTTP status.

No provider exception body, URLs, host routing, headers, key IDs or secrets
are included in receipt. Eight corresponding synthetic negative tests cover
all classes. All other original read-only guards remain intact.

## 2026-11-23: HTTP 401 root-cause correction

Backblaze's official native `b2_authorize_account` documentation makes two
different responses for HTTP 401: `code=unauthorized` (wrong application
key ID / secret pair) and `code=unsupported` (key version incompatible with
the called native API). The prior verifier incorrectly marked EVERY HTTP
401 as a wrong key, even when the provider error was `unsupported`.

The new audited pinned probe is content-addressed by Git blob SHA
`8f3b19ab652a846ad4f86c439f0103f40f55c88a` and reads at most 1,025 bytes from a 401 error response.
It accepts ONLY a JSON object with `status:401` and code in the tiny
allowlist `unauthorized` or `unsupported`; all other errors are
`B2_AUTH_401_UNCLASSIFIED`, **never assumed to be wrong credentials**.
It never outputs provider `message`, raw response, token, key ID, key
material, host or user context. This is strictly read-only; the existing
source DB/backup environment guard remains enabled inside the child.

Status meanings:
- `B2_AUTH_PAIR_INVALID_401`: Backblaze specifically reported wrong pair;
  without private Codespaces secret comparison one cannot identify which.
- `B2_AUTH_VERSION_UNSUPPORTED_401`: Backblaze specifically reported API
  incompatibility; do not rotate credentials prematurely.
- `B2_AUTH_401_UNCLASSIFIED`: no trustworthy provider code was readable;
  do not assert cause.
All preserve overall BLOCKED; actual third-site WORM backups NOT RUN.
