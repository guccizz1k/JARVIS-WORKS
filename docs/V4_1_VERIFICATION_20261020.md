# JARVIS WORKS V4.1 — verification evidence, 2026-10-20

## Target and provenance

- Private review branch target: `review/v41` from existing `review/v401` head `010846ff1b5d739d05c37281d38d0a0ee68430a6`.
- Purpose: synthetic PostgreSQL 17 committed replay, app-factory recreation, interrupted write rollback, counter consistency, revocation and partner recovery.
- Existing V3.7 compatibility design and V4.0 idempotent writer are reused; no production ORM, API route, user records or DB migration changed.

## Tests actually executed locally

| Gate | Result | Evidence |
| --- | --- | --- |
| Python compile and Bash shell parsing | PASS | `py_compile` and `bash -n` |
| V4.1 + V4.0 focused regression | **46/46 PASS** | `python -m pytest -q tests/test_pg_recovery_v41.py tests/test_pg_writer_v40.py --disable-warnings` |
| Complete existing application regression | **350/350 PASS** | `PYTHONPATH=. python -m pytest -q --disable-warnings`, exit 0, 155.77 seconds |
| Historical + V4.1 SHA-256 integrity manifests | **8/8 PASS** | `sha256sum --check --status` for V2_8, V3_5, V3_6, V3_7, V3_8, V3_9, V4_0, V4_1 |
| Real PG17 for new V4.1 gate in local environment | **NOT RUN** | `bash scripts/run_pg17_codespaces_v41.sh` exit 2, Docker CLI unavailable |
| Full UI/browser/physical restart | **NOT RUN** | No UI changes; fresh TestClient/app-factory is not a real server restart |
| Live SQLite-to-PG cutover, production backup, customer data | **BLOCKED / NOT APPROVED** | Out of requested safe review scope |

## Regression and threat checks

- Opt-in gate refuses execution unless V4.1, V4.0 and ephemeral write flags are jointly valid.
- The supervisor-generated libpq DSN is converted by existing V4.0.2 strictly validated URI logic; no production DB target accepted.
- Re-created test app must preserve one committed message and return matching ID/sequence on replay; partner sees it; tenant C does not.
- A simulated exception after SQL INSERT must roll back both the uncommitted row **and the per-thread sequence counter**, followed by a successful exactly-once retry.
- The revoked session must remain rejected even with fresh API instance, while the other partner succeeds.
- The test destroys no DB itself: the existing random disposable PG17 launcher remains responsible for cleanup even on failure.
- Error logs expose only fail-stage and exception class, not credentials, session tokens or SQL rows.

## Verdict

**Local candidate PASS; independent V4.1 real PostgreSQL 17 evidence still required.**
No automatic GitHub Actions, paid tasks, PR, merge, production deploy, real data migration or customer interactions occurred.

## Subsequent independent Codespaces PG17 live gate — owner screenshot

The owner provided a screenshot on **2026-10-20 (KST)** showing completion of `git fetch origin review/v41` and a **detached temporary Git worktree** running `bash scripts/*v41.sh` on the isolated Codespaces PostgreSQL 17 environment. The screenshot's actual terminal output includes:

- `PASS: V4.1 real PG17 recreated-app durable replay, bilateral read, injected rollback, retry exactly once, revocation and partner recovery`
- `PASS: V4.0 real PG17 idempotent writes, concurrent retries, monotonic sequence uniqueness, tenant RLS, revocation and rollback`
- `PASS: ephemeral PG legacy + V2.7 + V2.8 integrity attacks; cleanup confirmed`
- `PASS: PostgreSQL 17 live RLS attacks and ephemeral cleanup completed`

The preceding V3.5–V3.9 gate summaries were also PASS on the same screenshot. This **upgrades V4.1 real isolated PostgreSQL 17 verification to PASS**, independently of the prior local verification table. The terminal returned to a shell prompt, but the exact shell exit code is not explicitly shown; the runner prints its final PASS only after cleanup succeeds.

**Evidence boundary:** screenshot demonstrates durable replay across recreated FastAPI app-factory instances and connections, not a killed/restarted OS process, power-loss durability, cross-host failover, real production backup/restore, production migration, public API routing or customer data. The `BLOCKED` production cutover notices remain valid. The original screenshot is in the user's conversation, not in this GitHub repository.

**Review conclusion:** V4.1 synthetic PG17 app-instance recovery, rollback, idempotency, tenant isolation and ephemeral cleanup **PASS**. Production cutover **BLOCKED until separately designed, verified and approved**.
