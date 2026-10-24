# JARVIS WORKS V8.9 — verified historical source recovery control

> **Source status: original V8.9 git objects are NOT YET on GitHub.**
> This branch is a **recovery control/manifest branch, NOT the original V8.9 source branch**.
> Never merge this branch into `main` expecting a complete V8.9 application.

## Verified authoritative Git objects (offline, available to repository owner)

| Item | Verified |
|---|---|
| Original V8.9 commit | `a3783ef9f7aeeeff655f1f0ac376f6d8edf5b338` |
| Original V8.9 tree | `b784f252f53f6b806f8d4db0c9413b936bf0fd0b` |
| Restored V9 integration commit | `1b0aa6611b4b613003938fa7f55d6a7469f6fb5a` |
| V9 integration tree | `9dcfe1363a4b625e711bd4828908485134d822b0` |
| V8.9 tracked source files | **288** |
| V8.9→V9 changed tracked files | **10** |
| Full-history Git bundle SHA-256 | `2f755fce302b502b739f750a3ea12a42aba52cc6321bd450c76fe0d24237165b` |

The Git bundle was extracted from the verified owner artifact `JW_V90_ADAPTIVE_REALTIME_VERIFIED_20261024.zip`, included with the user's ChatGPT conversation. Verify source material before import; do not replace this with GitHub's older `main` source.

```bash
sha256sum V89_V90_ADAPTIVE_REALTIME_HISTORY.bundle
git bundle verify V89_V90_ADAPTIVE_REALTIME_HISTORY.bundle
git clone -b review/v90-adaptive-realtime-20261024 \
  V89_V90_ADAPTIVE_REALTIME_HISTORY.bundle offline-reviewed
git -C offline-reviewed merge-base --is-ancestor \
  a3783ef9f7aeeeff655f1f0ac376f6d8edf5b338 \
  1b0aa6611b4b613003938fa7f55d6a7469f6fb5a
git -C offline-reviewed diff --quiet \
  a3783ef9f7aeeeff655f1f0ac376f6d8edf5b338 \
  1b0aa6611b4b613003938fa7f55d6a7469f6fb5a \
  -- app/main.py
```

## GitHub remote state confirmed 2026-10-24

- GitHub repository: [guccizz1k/JARVIS-WORKS](https://github.com/guccizz1k/JARVIS-WORKS).
- Remote `main`: `4fe542b9c5676ae3ee5237504426a938e422cd42`, an older unrelated/partial snapshot (29 blob files on its tree).
- GitHub API returned **404/422** for original V8.9 `a3783ef` and integrated V9 `1b0aa66` commit objects.
- Existing [V9 Draft PR #1](https://github.com/guccizz1k/JARVIS-WORKS/pull/1) is based on old remote main, and must **not** merge until the original lineage is uploaded safely.
- Direct `git push` from this ChatGPT container is unavailable because external GitHub DNS/network is blocked; the GitHub connector can create branches/files but cannot import an offline .bundle / arbitrary binary tree in one operation.

## Safe import: two new refs, NEVER push main

On an **authorized networked Git client with existing GitHub write access**, after verifying the Git bundle:

```bash
git -C offline-reviewed remote add publication https://github.com/guccizz1k/JARVIS-WORKS.git
git -C offline-reviewed push --atomic publication \
  a3783ef9f7aeeeff655f1f0ac376f6d8edf5b338:refs/heads/review/v89-restored-a3783ef-20261024 \
  1b0aa6611b4b613003938fa7f55d6a7469f6fb5a:refs/heads/review/v90-on-v89-20261024
```

Push only to **new** refs. Do not force push, merge main, deploy or apply database migrations. Verify exact source tree after upload. GitHub's commit SHAs must match `a3783ef...` and `1b0aa66...` after true Git bundle publication. The import itself has **NOT** happened yet. Do not report GitHub original source restoration complete based only on this manifest branch.

### Associated remote review refs

- V8.9 recovery manifest: `review/v89-auth-source-recovery-20261024` (this branch; **not original source**)
- V8.9→V9 ancestry checks: `review/v89-v90-ancestry-reconcile-20261024`
- V9 staged code: `review/v90-secure-messenger-directory-20261023` (Draft PR #1)

**Security/release status:** source lineage confirmed offline; original Git objects absent from remote; real PostgreSQL concurrent tenant tests and production E2E remain BLOCKED. Do not merge/deploy.
