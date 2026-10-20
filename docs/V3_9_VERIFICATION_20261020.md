# JARVIS WORKS V3.9 Psycopg 3 driver verification

**Status: PARTIAL / private review only** · 2026-10-20

## Scope and preservation

- Based on `review/v38` (`821a400c4259543991d2b03621be64b55e10b2a1`) with pre-existing `psycopg[binary]>=3.2,<4` confined to `requirements-postgres-check.txt`.
- V3.9 adds a verified, per-request, non-pooled PG17 cursor and synthetic actor isolation tests. Integration is limited to the existing private V3.8 **read-only laboratory**, never `app/main.py` or operational SQLite.
- No production Postgres connection, migration, app deployment, automatic GitHub Actions, ads or expense executed.

## Verified gates

1. **Code/dependency PASS**: Python compileall; Bash `-n`; existing dependency reused, no duplicate psycopg in `requirements.txt`; V2.8, V3.5, V3.6, V3.7, V3.8, V3.9 gate manifests all hash-valid.
2. **Unit correctness PASS**: 42 focused PG-driver/read-API/migration tests passed. Fails closed on unexpected DSN, privileged role, wrong PG version, revoked or unverified actor; connection rollback/closure verified via mock.
3. **Regression PARTIAL**: 33 additional PG security tests passed, total independent targeted = **75/75**. Full-suite run stalled at 17 visible test results and was terminated by time limit, so do not count as full PASS. Combined messenger+security suite reached 38 tests then timed out; split PG security subset passed independently.
4. **UI NOT RUN**: existing routes and UI unchanged, no deployed application modified.
5. **PG17 real driver test NOT RUN**: local runtime lacks Docker; CLI returns exit 2 and prints `NOT RUN`. Real Codespaces test still required; no security/performance release claim.

## Next execution

On a stopped Codespace with adequate *remaining free* usage, execute only:

`git fetch origin review/v39:v39 && git switch v39 && bash scripts/run_pg17_codespaces_v39.sh`

Check **both** the distinct V3.9 driver PASS message and the final PG17 cleanup PASS. Do not merge, promote or publish without live gate proof, comprehensive regressions, reviewer approval and isolated write-capable adapter tests.
