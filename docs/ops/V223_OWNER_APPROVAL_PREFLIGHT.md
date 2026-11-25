# V22.3 owner approval preflight

The review preflight consumes a signed approval for an independently selected Git
commit, exact manifest bytes, and one scope. Its success is a local verification
result. Historical backup, role, workflow, and release entry points retain their
own approval requirements. The review adapter is exercised with disposable local effects.

## Owner enrollment and signing

1. Use the approved owner identity and an authenticated channel separate from the
   approval submission. Provide only the **32 raw bytes** of the Ed25519 public key
   (64 lowercase hex characters when transferred as text) and separately confirm
   the **lowercase SHA-256 of those bytes**, not the digest of the hex or PEM
   representation. Identify the owner and the single permitted operation scope.
   Policy enrollment and key rotation require separate owner authorization.
2. Pin the full commit ID and resolve its tree using Git with replacement objects
   disabled. Approve the SHA-256 of the exact manifest bytes. Include the operation,
   environment and target, limits, cleanup, and stop conditions in the manifest.
   Leave the owner policy disabled until the key, fingerprint, and scope agree.
3. Provision new private store and ledger paths, recording their common store ID.
   Keep the ledger and its independently authenticated checkpoint authority
   outside the challenge store's restore domain. Use the authority's latest
   checkpoint, including store ID, revision, and full history SHA-256, for every
   issuance and consumption. Supply its compare-and-advance operation through
   the trusted publisher. The preflight returns only after the publisher confirms
   that it durably replaced the expected checkpoint with the new checkpoint.
   Never reconstruct the authority's latest checkpoint from restored files.
4. After review, issue a fresh challenge through the pinned preflight. Supply the
   canonical flat JSON bytes with precisely these fields:

   | Field | Value |
   | --- | --- |
   | `challenge` | Issued lowercase hex nonce |
   | `domain` | `jarvis-works/v22.3/approval/v1` |
   | `expires_at` | Issued integer UTC Unix seconds, within the five-minute challenge window |
   | `git_tree` | Full lower-hex Git tree ID for the pinned commit |
   | `key_fingerprint` | Separately confirmed SHA-256 of the raw key |
   | `manifest_sha256` | SHA-256 of the exact approved manifest bytes |
   | `scope` | The one approved operation scope |

   Encode as ASCII JSON with sorted keys, compact separators, and no trailing
   newline. The owner signs those bytes with the owner-held Ed25519 private key
   and returns the payload plus the detached **64-byte raw signature**. The private
   key stays in owner custody. Expired, changed, or already consumed approvals
   require a new challenge and signature.

Two SQLite paths can prove the local failure behavior. They cannot establish an
independent operational checkpoint authority. A coordinated restore of both files
is detected against an independently retained current checkpoint. Rolling back
that authority too, or publishing an old checkpoint as current, defeats this trust
model. An unavailable or refusing authority prevents a successful result, even
after local consumption committed. After a split commit or unverified
restore, quarantine both files, retain evidence, and have the authorized custodian
provision a new pair and explicitly enroll its new identity. Obtain a fresh
challenge and signature. Do not reset counters or backfill events to recover.

## Review adapter binding

Bind `PrivilegedEntry` to the trusted `ReviewPreflight` and a single execute and
rollback pair during operator configuration. The signed manifest is passed to
both callbacks as bytes. Supply the current checkpoint from the independent
authority. The entry dispatches only after confirmed consumption and a final
expiry check. An execution error invokes the bound rollback and leaves the
approval consumed. A rollback failure or process death requires reconciliation
before seeking fresh approval. The review tests use only disposable local
effects. Live launchers require separate adapter selection and authorization
for the exact target and rollback.

## Live acceptance prerequisites

- **Authorized environment and maintenance window.** Confirm the specific
  Supabase project, development or approved target, source and restore targets,
  exact tree, actions, stop time, operators, and written authorization. The
  November 17 owner launcher deadline has expired. Reuse neither that window nor
  its approval as authority for a new launcher or role change.
- **Verified TLS and least privilege.** Use an independently obtained official CA
  and verify hostname, project ref, database, session role, and independent
  schema fingerprint before source operations. Require `sslmode=verify-full`,
  PG17+ clients/server, and the existing least-privilege source checks. Any
  separately approved time-limited access must have a verified closure and
  session-termination check. Supply credentials through the approved secret
  channel only. [Existing PG17 backup and restore runbook](V223_PG_BACKUP_RESTORE.md)
- **Safe restore and cutover.** Use a marked, empty disposable PG17 target and
  approved backup encryption and custody. Require actual decrypt/restore, source
  and restore comparison (table digests, constraints, policies, FORCE RLS,
  privileges), adverse archive tests, measured RPO and RTO, cleanup, and a tested
  rollback/cutover plan. Record redacted evidence against the exact approved tree.
- **Product HTTPS.** Use an approved HTTPS endpoint and synthetic tenant fixtures
  with the approved UI. Complete authenticated cross-tenant positive and denial
  cases, role isolation, core trade and messenger flows, browser checks, and
  restore/cutover acceptance. Local Chromium/WebKit and disposable PG17 results
  remain synthetic evidence.

Minimal owner handoff is the separately confirmed public key/fingerprint, exact
scope and manifest, independent checkpoint custody, and written environment and
window approval. Then the owner supplies a fresh detached signature for that
specific challenge. This document creates no enrollment, authorization, or access.
