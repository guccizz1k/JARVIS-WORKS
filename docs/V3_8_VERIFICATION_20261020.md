# JARVIS WORKS V3.8 — PG17 compatibility read API review evidence

**2026-10-20 / PARTIAL — local PASS, V3.8 real PG17 NOT RUN, no production deployment**

- Baseline: `review/v37` commit `cf80335dee9e408fa3f5717a05618d26928a7737`; owner-provided screenshot independently shows isolated V3.7 PG17 semantic/RLS/rollback test PASS, **not V3.8**.
- Candidate code: `review/v38` commit `5d16a66614c0d18c1c4695fd0a3babc361be82c6`; 11 changed source/test/hash/documentation blobs exact-match local files (11/11 SHA-1).
- New isolated API: GET paginated text/order snapshots, attachment raw bytes with SHA-256 and no sniffing, and own-business read marker. Per-request verified synthetic session and PostgreSQL forced RLS, no user-supplied tenant identity, no HTTP listener, no route added to existing SQLite FastAPI application.
- Gate 1: Python compileall, Bash syntax, all five (V2.8–V3.8) SHA256 manifests PASS.
- Gate 2: new local input/security tests 4/4 PASS; targeted V3.6–V3.8 suite 35/35 PASS.
- Gate 3: **297/297** entire local pytest suite PASS in 164.72s, exit 0.
- Gate 4: NOT RUN (no deployed/UI changes).
- Gate 5: isolated V3.8 PG17 run NOT RUN (Docker and psycopg missing in assistant runtime, script exit code 2); production cutover/B2B live accounts/performance NOT RUN.
- `main` and `review/v37` unchanged. No merge, paid resources, PR, release, database write, real customer records or advertisements.
- Owner action (only when free Codespaces quota remains): `git fetch origin review/v38:v38 && git switch v38 && bash scripts/run_pg17_codespaces_v38.sh`. If any error arises, preserve the failing output and fix only in the review branch.

**Next gate**: actually run the new V3.8 FastAPI TestClient ↔ PostgreSQL 17 attack suite before claiming live backend readiness.