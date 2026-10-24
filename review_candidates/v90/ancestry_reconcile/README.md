# JARVIS WORKS — V8.9 → V9.0 Git ancestry reconciliation (2026-10-24)

## Truthful status
**Local source integration VERIFIED. Remote history NOT RESTORED / NOT READY TO MERGE.**

The original V8.9 repository is available in the user's verified ChatGPT Library artifact `JARVIS_WORKS_V89_AUTH_INTEGRITY_REVIEW.zip`. It is NOT missing. The authoritative commits in the original offline Git bundle are:

- Original V8.9: `a3783ef9f7aeeeff655f1f0ac376f6d8edf5b338`.
- Integrated V9.0 auth/member-boundary commit: `98026b9063a5fda1d2f0f06de0237535394f270d`.
- Integrated V9.0 bounded WS polling: `1b0aa6611b4b613003938fa7f55d6a7469f6fb5a`.

**Important:** the linked GitHub `main` at `4fe542b9c5676ae3ee5237504426a938e422cd42` does NOT include original `a3783ef`. A GitHub 422/commit-not-found was reproduced for all 3 local commits. This branch is deliberately based on the existing V9 review-only branch (which itself derives from older main); it holds **provenance gates and artifacts metadata only**. It is NOT a remote import of the full original V8.9 tree. Do not merge this branch into `main`.

## Checked immutable source bundle

- Bundle: `V89_V90_ADAPTIVE_REALTIME_HISTORY.bundle`.
- SHA256: `2f755fce302b502b739f750a3ea12a42aba52cc6321bd450c76fe0d24237165b`.
- `git bundle verify`: PASS / complete history.
- Fresh `git clone --branch review/v90-adaptive-realtime-20261024 <bundle> <destination>`: PASS.
- Fresh checkout: `1b0aa661...`, V8.9 ancestor `a3783ef...`.
- Original `app/main.py` Git blob matches exactly; only ten allowlisted files differ from V8.9.
- Fresh Git checkout WebSocket subset: **4 PASS**.
- Fresh combined V8.9+V9.0 source full regression: **589 PASS, 0 FAIL, 0 SKIP** (run after latest stage selection; full JUnit attached in the separate evidence ZIP).
- Ancestry gate `verify_v89_v90_ancestry.py`: 8 PASS local checks, producing `status: PASS`, while flagging `this_proves_remote_github_ancestry: false`.
- Gate's six *real Git repository* regression scenarios: **6 PASS**, including missing original SHA, unapproved production `app/main.py` edits, unrelated tracked changes, and dirty/staged changes.
- The two .py files above have Git blob hashes verified against tested local sources:
  `5d169ab34fd3f006cbf4a008a33bbea3b39951c6`,
  `a865ef33ca8bc2445321314b7405c9613773f037`.

### Restore commands on an authorized Git-capable machine

```bash
sha256sum V89_V90_ADAPTIVE_REALTIME_HISTORY.bundle
git bundle verify V89_V90_ADAPTIVE_REALTIME_HISTORY.bundle
git clone --branch review/v90-adaptive-realtime-20261024 V89_V90_ADAPTIVE_REALTIME_HISTORY.bundle recovered
cd recovered
git merge-base --is-ancestor a3783ef9f7aeeeff655f1f0ac376f6d8edf5b338 HEAD
git diff --exit-code a3783ef9f7aeeeff655f1f0ac376f6d8edf5b338 HEAD -- app/main.py
python ../verify_v89_v90_ancestry.py .
# only after review and explicit approval: push to a NEW remote review ref;
# NEVER force push main or merge a branch derived from older main.
```

Tests: set `JW_V89_V90_SOURCE_ROOT` to the recovered checkout and run `pytest -q test_verify_v89_v90_ancestry.py`. Missing source is a FAIL, never a SKIP.

## Developer DB integration gate (not passed)

Connected Supabase dev PostgreSQL 17 via read-only catalog inspection; 35 FORCE RLS tables. Candidate SQL `006_commit_order_cursor_guard_candidate.sql` was **compiled inside BEGIN and ROLLBACK on actual PG** and read-only count confirmed that send/editor functions remained unmodified. The staged transaction also ran the repo's existing A/B/C SQL regression `003_messenger_rpc_regression.sql` with synthetic rolled-back fixtures (messages, edit, edit-window, RLS/RPC cross-tenant deny, idempotency, delete denial); after rollback fixture org count 0 and installed guard count 0.

This is an **actual single PG session SQL functional gate**, not independent-credential tenant E2E.

Attempted concurrency using two different backend PIDs, but measured lock-claim windows did NOT overlap (first ended 06:16:14 UTC, second started 06:16:17 UTC); this connector serializes the requests. Therefore **concurrency/commit inversion remains BLOCKED**, not PASS. Dedicated nonprivileged LOGIN roles for business/auth are absent and the execution environment cannot directly resolve the Supabase DB host; never use `postgres`, `service_role` or BYPASSRLS as substitute for tenant E2E.

**Required before deployment:** secure secrets provisioning; separate nonprivileged, least-privilege SSL gateway credentials; two persistent independent PG sessions; real A/B/C sessions, concurrent lock and rollback tests; approved isolated migration application and test; HTTPS browser E2E; CI and rollback; remote source ancestry reconciliation.

**No remote main write, release, paid CI, auth role provision, persistent DB migration, or customer data mutation was performed.**
