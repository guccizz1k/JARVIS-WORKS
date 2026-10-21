# JARVIS-WORKS V4.8 — Synthetic Semantic Evidence Envelope (review-only)

## Purpose / evidence

V4.7 live Codespaces PostgreSQL 17 successfully proved that **13 missing fields** could be added to disposable operational `public.messenger_*` tables within an explicit transaction, with RLS preserved and a verified unconditional ROLLBACK. The full V4.7 gate and isolated container cleanup passed, according to the user's screenshot. This **does not** make the running SQLite-backed B2B web app PostgreSQL-compatible.

The next isolated test addresses **source-semantic preservation**, not cutover:

* Existing SQLite message `kind='text'` with a linked immutable file would need `kind='attachment'` in the existing operational PostgreSQL schema. V4.8 stores BOTH `original_kind=text` and the *candidate* `attachment` kind in a temporary evidence envelope. This is an observation, **not an approved mapping** to a live operational writer.
* Order messages retain the **original immutable snapshot bytes**, order ID, message ID, user, and all version/read evidence, rather than converting the JSON to `jsonb` and changing key or spacing fidelity.
* Binary attachment, filename, MIME, byte count, SHA256, original linked message, edit versions/actors, receipt actor, and both organizations' read positions are preserved using V3.6 canonical bytes and V3.7 `build_contract` (no duplicate migration engine).
* Original timezone-offset text is retained without coercing to `timestamptz`. Naive, noncanonical and UTC-`Z` fixture inputs are refused because a reversible lexical mapping has not been proven.
* This gate needs a populated synthetic edit, order, attachment, receipt, and **bilateral read** fixture, and compares actual PostgreSQL readback bytes, digest, original/candidate kind, and row keys, not counts or hashes alone.

## Isolated PG17 execution

The unchanged V4.7 supervisor runs first, including historical V2.8–V4.7 RLS, revocation, concurrency, durable replay, recovery, SQLite/PG evidence parity and the 13-field rollback drill. V4.8 runs **only** if the full prior chain returns 0. The script verifies all historical SHA256 manifests, including V4.7, and invokes the same disposable PostgreSQL 17 container model.

V4.8 permits ONLY the disposable `jw_v20_test_<hex>` database, role `postgres`, server PG17, locally generated credentials, exact lab flags and **autocommit connection**. It reads the current public catalog with the preexisting V4.6 admin/forced-RLS guard and rejects a missing RLS table. Only inside a BEGIN/ROLLBACK transaction, it creates a **TEMP table** with the six canonical semantic fields, inserts fictional source records, reads back all rows and checks equality, then unconditionally rolls back. It requires no new persistent table, existing data mutation, public API registration or migration of real records. The absence of the temp table and catalog equivalence are verified after rollback. Any error, including cleanup or rollback failure, is FAIL and cannot be PASS. There is no deployment or `main` merge.

### How to run in Codespaces

From a fresh detached `review/v48` worktree:

```bash
bash scripts/check_v48_review.sh
bash scripts/run_pg17_codespaces_v48.sh
```

The first script runs the entire older zero-SKIP pytest chain and checks the new source hashes. The second runs the live PG17 sequence. Expected successful final markers:

```
PASS: V4.8 real PG17 synthetic semantic bytes, attachment-kind projection, order/receipt evidence and unconditional rollback
BLOCKED: V4.8 operational cutover DENIED; semantic sidecar is not a live message writer or an approved identity mapping
PASS: V4.8 PG17 semantic evidence roundtrip and rollback (cutover DENIED) with isolated Docker cleanup
```

**The BLOCKED marker is intended.** It means the operational application, all-company mapping, attachment business semantics, timestamp conversion, actual ID binding, dual-write retry, and production rollback remain unapproved.

## Implemented negative tests / limitations

New unit and failure-injection tests cover tampered raw bytes/digest/kind/row key, deletion/duplication, wrong order snapshot source, corrupted attachment hash, missing evidence families, unsafe timestamps, missing FORCE RLS, non-autocommit connection, aborted INSERT, wrong readback, failed ROLLBACK, unremoved temp table, production flag rejection, prior gate NOT RUN/FAIL, and restoration of patched supervisors. No raw payloads or secrets are emitted in the success status.

Authoring container **has no Docker or PostgreSQL daemon**. Locally, 31 V4.8 targeted tests passed using the original V4.6 catalog model and a **QA-only V3.6/V3.7 stand-in**; the actual V3.6/V3.7 implementation is present in the GitHub Codespaces target and MUST be exercised through the complete historical gates. Accordingly, neither a complete project regression PASS nor a real V4.8 PG17 PASS is claimed before Codespaces evidence.

**5 Gate state:** code/syntax `PASS` for new files; contract/failure-injection `PARTIAL` pending original V3.7 and PG17; full repository regression `NOT RUN`; UI `NOT RUN`; actual PG17 execution/production deploy `NOT RUN`/`BLOCKED`. Production migration and user-data access are prohibited by design.
