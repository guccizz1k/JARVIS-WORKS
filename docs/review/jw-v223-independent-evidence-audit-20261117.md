# JARVIS-WORKS V22.3 independent evidence audit — 2026-11-17

## Scope and provenance
Read-only GitHub API review; pinned source SHA `e4adbdef9f5a792e5a88cdf8fb8d8844c2b768ad` on `review/jw-v223-p1p0-b2b3-20261117`. This report is **not** a live B2/B3 run, not a substitute for source credentials, and not a release approval. Audit is deliberately isolated from the Codex working branch.

## Reproduced GitHub facts
- Source tree: 1,199 entries; app/ 129, tests/ 301, scripts/ 272, db/ 13.
- Compared against `3e67f942f9fdc9bc7df91070c9e7710d4c8ec019`: 50 commits ahead, 0 behind. The diff includes 32 paths, notably `app/owner_review_app_v223.py`, `app/pg_cinema_legacy_api_v1.py`, `app/static/approved_ui_operational_v223.js`, workflow files and backup scripts.
- Latest owner-authorization regression run [44004926575](https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/44004926575): completed success on pinned SHA. Its single job tests **disposable** PG17 negative/positive paths; it does not exercise authenticated Render E2E, the live backup, independent restore, or the complete regression suite.
- Issue [#142](https://github.com/guccizz1k/JARVIS-WORKS/issues/142) remains open.
- Earlier synthetic full-regression evidence at [43967909027](https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/43967909027) was on a **different SHA** (`e130c944...`); it is not evidence of a complete regression on the pinned SHA.

## Direct code review: relevant safety and regression risks
1. `scripts/ci_cinema_pg_v223_owner_live_20261117.py` performs a bounded role activation and then calls `existing.stage_login()`, `existing.stage_backup()`, `existing.stage_revoke()`, and `existing.stage_prove_closed()`. A failure in `stage_backup()` cannot be diagnosed by the outer handler alone because it emits only the exception **type**, not the originating stage's classified cause. Do not assume the signature mismatch is the root cause; the child may fail earlier.
2. The script's finally block attempts revocation and then closure verification. `revoke REPORTED_PASS` does **not** imply `closed_verified PASS`. An unverified closure is a separate security blocker, even if the restore failure is resolved.
3. `scripts/ci_cinema_pg_v223_owner_worktree_20261117.py` contains owner-only `diagnose` mode that categorizes saved child output and verdict fields without printing secrets. Prior captured output reports `CHILD_NONZERO_EXIT`, `VERDICT_REPORTED_INCOMPLETE`, `SIGNATURE_MISMATCHES_REPORTED_PRESENT`, `TABLE_COUNT_REPORTED_65`. These are **diagnostic labels, not a proven causal chain**.
4. `app/owner_review_app_v223.py`: isolated review DB path validation was added. Test symlink/ancestor paths, relative paths, default DB and allowed disposable paths.
5. `app/pg_cinema_legacy_api_v1.py`: transaction-local `Asia/Seoul` time zone was added. Test midnight boundaries and connection-pool reset behavior.
6. `app/static/approved_ui_operational_v223.js`: messenger selection generation and pending-send map changed. Test fast thread switches, delayed responses, retries, duplicate submissions and retained drafts in Chromium and WebKit.

## Ordered independent acceptance matrix
| Gate | Required evidence | Current audit verdict |
|---|---|---|
| P0 real B2/B3 | Encrypted real dev dump; independent PG17 restore; 65-table schema/data/signature comparison; safe external custody | BLOCKED — private proof not available; existing verdict incomplete |
| P1 role lifecycle | 5h bound, restricted TLS, verified NOLOGIN, 0 sessions, fresh login refused | PARTIAL — disposable CI passes; real closure not verified |
| P2 functional regression | Full Python/JS/PG17 business tests at exact current SHA, no failures/skips | NOT RUN at pinned SHA in this audit |
| P3 browser/UI | Chromium and WebKit PC/mobile exact SHA, original V22.2 UI invariants | NOT RUN at pinned SHA in this audit |
| P4 authenticated staging | Render deployment at exact SHA, authenticated real HTTPS transaction E2E | NOT RUN at pinned SHA in this audit |
| P5 CORE J1–J6 | Integrated security/recovery/functional evidence at exact SHA | NOT RUN at pinned SHA in this audit |
| P6 independent release QA | Cross-check all evidence and rollback/approval controls | BLOCKED |

## Fastest safe next action
1. Run the **existing** owner-only diagnosis on the original Codespaces branch; do not expose raw logs, credentials or private dump. Extract first failed subprocess stage and verify whether signature-mismatch indicators are *reported* or *independently verified*.
2. Before any new login grant, independently verify current role is NOLOGIN with zero sessions. A prior revocation command reporting PASS is insufficient.
3. Reproduce failure against disposable PG17 with fixture data, patch the first causal defect, then re-run exact-SHA full CI in parallel with browser regression.
4. Reattempt live B2/B3 only after new time-bounded authorization and verified local isolated target; require independent restore evidence and role closure proof. No real backup upload without approved destination.
5. Keep release NO-GO until every gate has evidence. Do not weaken the guard or suppress tests to obtain PASS.

## Status
**Independent GitHub evidence inspection: PARTIAL (selected source and CI inspected; no complete source-code audit, full test execution, independent reproduction, or live evidence verification). Product release: BLOCKED.** No database change, secret access, deployment, or test execution was performed by this audit.
