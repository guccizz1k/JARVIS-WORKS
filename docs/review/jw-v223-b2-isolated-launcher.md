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
