# JARVIS-WORKS — V5.3 eight-stage release train, not production

**Source:** `review/v52` parent, code review 2026-10-21. `main`, customer data and operational service unchanged. **Overall BLOCKED**. No inferred completion percentage.

## Corrected strategy

Historically V4.4–V5.2 repeatedly verified isolated PostgreSQL security. V5.1 connected a lab-only SQLite transactional outbox to real messenger writes. V5.2 delivered only `message.insert` references to a disposable PG17 RLS ledger. V5.3 extends this with **metadata-only evidence hashing**, reusing the same signed PG17 actor adapter and existing PG supervisor. It is not a production writer or customer migration.

### V5.3 code actually delivered (gate 01, PARTIAL)

- Typed digest records for `message.insert`, `attachment.insert`, `edit.insert`, and conditionally `receipt.insert`; no message body, file bytes, freeform actor-name, credentials, or edit body is delivered.
- Source SHA256 recomputation and size bounds for attachment bytes. A mismatch aborts the whole current batch and holds ACK.
- Immutable edit-row previous/new content hashes, version, trusted actor, tenant and source message relationship.
- Signed PG actor/tenant comparison for every event. A mixed-actor batch is blocked, not silently rerouted.
- Receipt signer must be a member of the *receiving* enterprise and the receipt record must have UPDATE/DELETE denial triggers. The original SQLite schema **does not yet have those receipt triggers**; therefore normal existing receipt streams remain **BLOCKED** until explicitly reviewed and integrated.
- Mutable `message.body_changed` and `read_position.insert/advance` cannot reconstruct the exact historical event value from V5.1's reference-only outbox. They **fail closed** without advancing ACK. The live editor can generate a body change before an edit event; that workflow is **not fully mirrored**.
- PG ledger writes are idempotent with exact replay conflict detection and forced RLS. PG commit precedes SQLite checkpoint ACK; crash after commit is tested. Source SQLite write transaction is held during PG round trip **only in disposable lab**, NOT a production concurrency design.
- A separate `jw_evidence_checkpoint_v53` is used, leaving V5.2 ACK and historical logs unchanged. Full historical backfill does not exist.
- `jw 53` uses `review/v53`, checks file integrity and full historical strict regression, then starts new disposable PG17 container. Its new stage runs only after V5.2 PostgreSQL gate succeeds. Any failure, SKIP, missing prerequisite or Docker cleanup failure blocks success.

### Local verification / missing proof

- Local isolated SQLite and strict readiness tests: see test output; does **not** certify PG17 run.
- Actual PG17 integration in Codespaces: **NOT RUN until `jw 53` executes**.
- Real browser and production customer data: NOT RUN; no `app.main` live PostgreSQL route changed.
- User production authorization, paid cloud, real external services and legal signoff: NOT GRANTED.

## Eight launch milestones — evidence and entry/exit conditions

| Gate | Deliverable required | Current judgment |
|---|---|---|
| 01 Evidence relay | Full-fidelity creation/edit/attachment/receipt/read-position replay, exact snapshots, identity and checkpoint verification | PARTIAL; mutable events & actual content still blocked |
| 02 Historical migration + restore | Bounded backfill with immutable resume cursor, no row/hash mismatch, rollback and offsite restore verified | BLOCKED; pre-outbox historical records unhandled |
| 03 Live web PostgreSQL integration | Server-side verified employee identity, all messenger API reads and writes, app reconnect/restart, tenant isolation and failback | BLOCKED; FastAPI operational routes still SQLite |
| 04 Company onboarding | Verified legal entities, duplicate business IDs, invites, roles, MFA, offboarding and account recovery | PARTIAL; basic suspension exists, real verification missing |
| 05 Commercial attachment storage | Encrypted object storage, signed URLs or authenticated streaming, malware scan, quotas, retention/erase | BLOCKED; SQLite BLOB demo only |
| 06 Customer experience | Full company search, instant messaging, attachment/order flows and notification reliability across desktop & mobile browsers | PARTIAL; browser-supported UI exists but operational acceptance absent |
| 07 Operational resilience/security | p95/SLO, load, restore RPO/RTO, alerts/on-call, secret rotation, independent pentest and DPA | BLOCKED; only isolated tests |
| 08 Controlled beta & GA | Production staging approval, beta consent, privacy policy and legal review, acceptance evidence, separate deployment consent | BLOCKED; no release |

## Fail-closed launch audit

`scripts/release_readiness_v53.py` validates `docs/RELEASE_EVIDENCE_V53.json` and reports each gate with evidence. It **always sets** `production_cutover_authorized=false` and `release_authorized=false` and returns nonzero for incomplete gates. It is a read-only status reporter, **not** an administrator approval or deployment mechanism. Do not edit statuses to PASS to bypass actual QA.

## Next engineering tasks (existing code reuse, no unnecessary version proliferation)

1. Fix V5.1 source event contract to capture immutable per-event payload digests at write time, or preserve historical snapshots in a protected ledger. Do not silently infer earlier read positions or edit bodies.
2. Add full source/messenger delta/backfill and identity mapping without modifying any live data; verify all seven legacy tables and back-pressure.
3. Develop production-ready PG data access inside the actual authenticated FastAPI routes; do not expose a public migration flag.
4. Add company invitation/legal business verification and durable object storage in a properly approved sandbox.
5. Run real browser and full regression tests on each completed integration, then independent security, recovery, monitoring and customer beta.

**STOP RULE:** If any required stage is FAIL/BLOCKED/NOT RUN or an unapproved production action is needed, DO NOT deploy, merge to `main`, migrate customer data, or declare completion. Ask for the minimum infrastructure/approval when truly needed.
