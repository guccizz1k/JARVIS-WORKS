# JARVIS-WORKS V4.5 — Full messenger evidence parity, isolated laboratory

**Baseline:** `review/v44` at `0de34de6f8c3809721d51fb8c0bfdf86bd4fc61d`.  
**Scope:** additive review-only code, zero modification of `app/main.py` or public web routes.

## Verified problem and intended solution

The user's Codespaces V4.4 output finished with:

`PASS: V4.4 cookie/PG17 shadow integration and isolated Docker cleanup`

V4.4 established authenticated web-cookie-to-PG17-RLS identity and **text-only**
history parity using disposable synthetic records. It did not validate the
attachment bytes, edits, order snapshots, receipts or read positions. The
production-shaped PG V2.8 schema stores attachment messages under `kind='attachment'`
but the existing SQLite app writes `kind='text'` and attaches a separate blob;
this shape mismatch **blocks cutover**. V3.7 already established a separate
lossless, typed, read-only legacy compatibility schema, `jw_migration_v37`.
V4.5 **reuses** it without adding another operational migration engine.

## Implementation

* `app/pg_evidence_shadow_v45.py` is a **separate in-process GET-only** FastAPI
  review app. It accepts a verified site principal from the existing
  `app.main.current_user` dependency by default, obtains its PG session binding
  only from a trusted synthetic broker and checks the tenant/actor *again*
  inside the transaction-bound PostgreSQL RLS context. Neither the HTTP client
  nor an arbitrary SQL query can inject a database token or table identifier.
* SQLite thread membership and bilateral company eligibility are verified
  **before** calling the broker. The site reads the five relevant evidence
  categories under one SQLite read transaction; PG reads the V3.7 archive in
  one verified **read-only** transaction. Limits are 100 messages, 500 rows per
  dependent type, and 16 MiB combined canonical bytes. Overflow is
  `INCOMPLETE`, never parity. PG uses fixed column lists from V3.7 and
  parameterized SQL.
* The complete stored message tuple (including immutable order snapshot,
  message kind, author, version and sequence) is compared along with original
  attachment bytes/metadata/hash, text edit history, order receipt evidence,
  and the **requester's own** read position. The comparison reuses V3.6's
  typed canonical serializer. It does not expose raw evidence or computed
  hashes. Any mismatch means `MISMATCH`. Exact equality of nonempty evidence
  means only single-thread `MATCH`, **not production go-live**.
* `scripts/test_postgres_evidence_shadow_v45.py` prepares the existing
  synthetic V3.6 in-memory archive, allocates a random 32-character thread ID,
  stages that archive into the V3.7 compatibility schema inside the already
  disposable PG17 database, then performs real `jw_app` RLS-backed HTTP reads,
  byte/receipt tampering and PG session revocation. Its synthetic cookie test
  does **not** replace V4.4's earlier **real website cookie** test, which runs
  first in the same disposable-test chain.
* `scripts/run_postgres_isolation_ci_v45.py` adds the new check *only after*
  the complete V4.4 chain succeeds, restoring the old callback on success,
  exception or failure. The V4.5 shell uses its **own new Docker PG17 container**
  and unchanged historical SHA256 manifest verification.

## What is deliberately not implemented

No operational PG schema migration, employee session issuer, general attachment
write path, public API backend swap, cross-store atomic snapshot, multi-tenant
cutover authority, production database, PR, merge or deployment. A single
matched thread is **not** a parity certificate for all organizations, both
companies' read markers, finance tables, orders, history timelines or the
whole site. The original PostgreSQL v2.8 `attachment` semantics still differ
from the SQLite web UI. Do not deploy or enable these review endpoints in
`app.main`, and do not use customer data in synthetic tests.

## Execution (Codespaces, isolated worktree)

```bash
bash scripts/check_v45_review.sh
bash scripts/run_pg17_codespaces_v45.sh
```

Both scripts must succeed. **V4.5 enforces zero pytest SKIPs with a per-run
`pytest_sessionfinish` plugin**; it is activated only while executing the
complete old pytest suite and never changes any V4.3/V4.4 source or manifest.
Any skipped *required* test, error, unsuccessful
Docker/Python setup, leftover PG schema or failed cleanup must block PASS.
`check_v45_review.sh` enforces its own manifest then the entire V4.4 full
regression, including the prior Node.js Docker fallback that addresses the
previously skipped native Node test. The real PostgreSQL step verifies
V2.8–V4.5 SHA256 manifests, recreates PG17, replays V4.4 and appends V4.5.

## Local verification performed

* Local pytest unit + runner failure-injection: **45 PASS, 0 FAIL, 0 SKIP**.
  The local runtime used genuine FastAPI TestClient and an in-memory SQLite
  fixture with a synthetic **PG cursor simulation**, not a live PG server.
* Attacker/negative cases: wrong or missing session, forged header, cross-thread
  access, invalid IDs, tenant binding mismatch, invalid agent context,
  missing partner verification, unexpected PG failure, 12 kinds of evidence
  mutation/loss, oversized thread and aggregate bytes, disabled review flag.
* Strict no-SKIP pytest plugin tests: PASS; forces a nonzero exit even
  when pytest otherwise considers skipped tests successful.
* `python -m compileall` and `bash -n`: PASS for the V4.5 files.
* Prior V4.4 isolated real PG17 test: PASS from user-provided Codespaces log.
  **V4.5 actual Codespaces PG17 test: NOT RUN** at authoring time.

## 5-Gate result

| Gate | Decision | Evidence |
|---|---|---|
| 1 — Code/environment | PARTIAL | New scripts parse/compile and hashes checked; no complete private repo local reproduction |
| 2 — Correctness | PARTIAL | 45 focused local tests PASS, actual PG17 V4.5 NOT RUN |
| 3 — Regression/data integrity | PARTIAL | Explicit fail-closed chain, typed/canonical deep parity, full repo rerun pending |
| 4 — UI/UX | NOT RUN | Production UI unchanged; actual iPhone/Safari review not exercised |
| 5 — Ops/deployment | BLOCKED | V4.5 live gate pending, no production schema compatibility or cutover approval |

### Open issue: Starlette deprecation notice

V4.4 screenshots still show one `StarletteDeprecationWarning` mentioning the
legacy `starlette.testclient`/`httpx` import path. It is a *warning*, not proof
of data corruption, but must be investigated against a supported official
Starlette/httpx combination before removal. V4.5 does not suppress it or make
an unsupported dependency upgrade merely to obtain a cosmetically clean log.

## V4.5 real PG17 failure: primary diagnostic must survive cleanup (2026-10-20)

The owner ran the isolated Codespaces V4.5 PostgreSQL 17 gate. Historical
V2.7–V4.4 tests succeeded, but V4.5 returned FAIL with:
`stage=cleanup-compatibility-schema type=AssertionError`. This reported
stage is **not reliable**: the previous runner assigned `stage='cleanup-compatibility-schema'`
inside a `finally` block *before* re-raising a prior assertion. Cleanup
problems could also be swallowed, and primary and cleanup errors could not
be distinguished from this log. No success or database corruption should be
inferred from the mislabeled stage.

The repaired runner retains the actual primary phase (`immutable-V3.7-typed-compat-stage`,
`RLS-full-evidence-HTTP-parity`, `byte-and-receipt-tamper-detection`,
`PG-session-revocation`, etc.). It reports stable error identifiers such as
`BASELINE_HTTP_503_PG_UNAVAILABLE`, `EVIDENCE_STATUS_MISMATCH`, or
`EVIDENCE_COUNT_MESSENGER_RECEIPTS`; only a fixed allowlist of response codes
can appear in diagnostics. Token values, private message content, SQL,
exception message strings and PostgreSQL DSNs are never printed. A cleanup
failure is separately reported, while both primary and cleanup failures block
PASS. It preserves all existing RLS/database guards and full historical gates.

Local regression: **47/47 PASS** using V4.4 support modules, current V4.5
code and simulated psycopg/HTTP failure injection. Two new tests prove that
an HTTP 503 is labeled at the failing HTTP phase (not as cleanup), and an
independent cleanup failure is reported without leaking secret exception text.
The local environment cannot run the user's isolated PostgreSQL 17 container,
so **the actual cause of the original AssertionError is still unresolved**.
This is a diagnostic repair, NOT a passing V4.5 integration or permission to
advance to production. Re-run Codespaces on this commit; if any live assertion
fails, use the stable diagnostic code to correct the exact cause, and repeat
the entire suite until FAIL=0 and SKIP=0.
