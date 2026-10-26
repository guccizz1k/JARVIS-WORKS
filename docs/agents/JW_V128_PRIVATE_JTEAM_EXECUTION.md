# J team private execution V12.8 — user-exclusive research/development workflow

**Purpose:** keep J team engineering code private, perform bounded local orchestration and independent verification, and avoid inadvertently turning a personal development assistant into a public B2B service.

## Topology

- GitHub repository `guccizz1k/JARVIS-WORKS` must remain **PRIVATE**; do not fork/publicize or upload its archive to public Gitingest or hosted prompt/context services. Review collaborators, third-party GitHub App installations, access tokens, Codespaces port forwarding and Actions artifact viewers before claiming sole access.
- Execution path: **user-authenticated private Codespace/PC terminal**, `python -m scripts.jw_jteam_private_cli`; **no HTTP socket and no public Render web-service deployment** for J team.
- All five specialist roles from `agents/team/jarvis_v1/team.json` remain in the same order. Local Fabric patterns are loaded through `scripts/jw_jteam_openai_runner.py` once a real call is explicitly enabled. Gitingest remains an optional **local sanitized fixture** pilot, never a SaaS/private-code export.
- The existing publicly reachable Render HTTPS probe is a transport-only stage asset; it is **NOT J team**. Do not put J team secrets on or route J team requests to it.

## Read-only startup

```bash
python -m scripts.jw_jteam_private_cli
python scripts/jw_agent_team_gate.py --root .
python scripts/jw_jteam_external_sources.py --check
```

These calls are free and do **not** start separate AI model sessions. The dry run does not create a database, GitHub PR, environment variable or network listener.

## Real model execution (still blocked until specifically verified)
- Provider key `OPENAI_API_KEY` must be configured by the user in **private Codespaces secrets/local secret store**, never chat, code, PR text, stdout or Actions logs.
- Per-run human approval id `JTEAM_OPERATOR_PRIVATE_APPROVAL_ID`, a supported model `JTEAM_MODEL`, explicit `--execute`, `JTEAM_PAID_API_APPROVED=YES`, and **independently verified** provider billing guard `JTEAM_PROVIDER_BUDGET_ENFORCED=YES` are required. The provider organization screen previously showed **'Limit not enforced'**; do not claim a provider-side hard cap merely because a UI budget/alert exists.
- The local SQLite reservation has a month-scoped, 50,000 KRW maximum (default cautious 5,000 KRW). A reserve is held in `UNCERTAIN` **before every network attempt**. Token counts and output digests are recorded, not actual converted KRW charges. The reservation is **not** a billing cap, verified invoice or final settlement. If a provider attempt has unknown status, the job remains blocked and cannot be auto-retried.
- J team model requests use `store: false`, but this is not a guarantee that cloud providers have no data retention or that no third party processes API input. Use only approved non-sensitive task text.
- Five separate provider response IDs are not proof that reviewers independently executed code in a separate browser, repository checkout or security environment. Mark independent review **NOT_ATTESTED** until an actual distinct verification run is produced.
- The CLI has no network-facing server, never invokes GitHub writes, never enables tools/code execution from model output, never persists prompts/model responses, and never exports private repo contents.

## Why this is safe to merge into main (not automatically safe to deploy)
- Local CLI is dry-run by default and does not bind ports. The J1–J6 harness and existing CI safety checks stay in place.
- Before main merge, require the *same reviewed SHA* to pass targeted J team contracts, full pytest suite, preserved Git history/source invariants, disabled paid-call negative tests, concurrency and privacy tests, and security checks. Record warnings and skipped tests separately.
- User expressly requested a reviewed main merge for internal use; J team itself must never gain merge authority. Main merge does **not** imply Render deployment.
- A GitHub branch update or scheduled workflow may still incur Actions runtime cost: preserve user's additional budget of $5/month and review Actions triggers before merging.
- No production data migration, real customer access, automatic broad PR edits, or external customer onboarding.

## Failure and recovery

- Every role step is claimed with SQLite `BEGIN IMMEDIATE`; a second worker cannot claim a `RUNNING` or `BLOCKED` step. Transactional usage receipts use exact job IDs.
- After a crash/timeout around a remote call, job becomes BLOCKED and requires provider-side request reconciliation. There is **no force-resume** or silent paid retry. Completed checkpoints are idempotently skipped.
- Use only user-owned local SQLite outside the Git worktree, never send state files to CI artifacts. By default `~/.local/share/jteam/private.sqlite3` is mode 0600 when created on POSIX.
- Recovery of model output content is **NOT implemented**: output is only hashed and the model response id is retained. This favors no secret retention over an unencrypted research archive. Before relying on this for production coding, implement encrypted output artifacts with backups and real approval gates.

## Open items tracked separately

1. Real 5× OpenAI Responses execution: **NOT RUN** (requires user-configured secret and verified billing guard).
2. Independent browser/PG exact-SHA negative tests and code-changing agent tools: **NOT RUN** for the new runtime; existing J1–J6 tests are separate.
3. Secure remote worker server and persistent task queue: **NOT DEPLOYED**; optional later only if local CLI cannot meet user requirements.
4. Provider cost settlement, authenticated provider receipts and recovery of uncertain outcomes: **BLOCKED pending provider evidence**.
5. Full-suite acceptance may be subject to dependency/environment warnings; use actual CI results, never infer PASS from a passing subset.

No "private means unhackable" claims. Enforce least privilege, GitHub 2FA, narrow third-party access, secret expiry/rotation and periodic security review.
