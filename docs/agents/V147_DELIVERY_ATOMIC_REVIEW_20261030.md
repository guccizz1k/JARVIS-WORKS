# V14.7 — corporate enrollment atomicity and delivery-evidence review

**Date:** 2026-10-30 KST. **Review-only parent:** Draft PR #59 exact SHA `adfb04e870ec43d1643b4c4966fc66081acb0af4`. Do not merge, deploy, modify persistent DB schemas/roles, change credentials, use customer data, or spend paid CI/API credits.

## Stage 2 — offline atomic reservation model, not actual registration

- `scripts/review/v147_enrollment_atomic_model.py` is explicitly **test-only SQLite**, never imported into the application runtime. It uses BEGIN IMMEDIATE and UNIQUE columns for request, normalized email, normalized business number and purpose-scoped consumed nonces. Invariant: either all review reservation + both nonce records commit or nothing commits.
- Two eight-way concurrent tests check only one winner per unique request and per shared business ID. Duplicate/replayed proof insertion rolls back and leaves no partial records.
- A `ReviewDecision` of `REVIEW_READY` is still **PENDING_HUMAN_REVIEW**; no user account, credentials, session, ownership change, email delivery, password reset or public signup endpoint is created.
- This is **not** evidence of PostgreSQL transaction isolation, no fake PASS. Future real product requires independent official business verification, out-of-band email verifier, atomic real PG17 proof consumption with restricted roles, tamper-resistant audit, expiry and owner signoff.
- External data source for evaluation: official free-to-apply Korea National Tax Service business-registration verification/status API, https://www.data.go.kr/data/15081808/openapi.do . No service key is configured and no API has been called; its status result alone would not prove email/company authority.

## Stage 3 — source-bound, two-party delivery evidence verifier

- `app/pg_delivery_evidence_gate_v147.py` is a **pure non-public review gate**. It reconstructs V14.5 invoice preview and verifies the exact canonical source SHA, tenant/org ID supplied by trusted session layer, order ID, each item/quantity, total amount, original document SHA, timestamp/TTL, distinct issuer/signer/nonce, and HMAC signatures from **two independent external issuer keys** for dispatch versus recipient acknowledgment.
- Denies altered/reordered/missing item, quantity change, monetary tamper, forged signed document SHA, wrong company/order, timestamp inversion, nonce replay and same-person dual approval. Sensitive input never appears in the fixed error.
- Even a positive test returns **EVIDENCE_VALIDATED_REVIEW_ONLY** with `physical_delivery_verified=false`, `invoice_posted=false`, `payment_posted=false`, `persistent_receipt_recorded=false`. It never asserts actual delivery.
- No physical delivery ledger was found by the earlier real DB catalog probe. Before an actual product posting API, still necessary: authoritative source-document verification, identity-bound human signatures, durable immutable delivery ledger + two-party evidence persistence, restricted-role PG transaction, idempotent invoice posting, duplicate/overpayment denial and actual hosted HTTPS E2E. No production schema migration is included or applied.

## Actual tests and errors corrected

- Baseline V14.6 local regressions: **56 PASS**. New V14.7 evidence + race-model tests: **51 PASS**. Full focused local suite: **107 PASS, 0 FAIL, 0 SKIP** (Python 3.13, isolated local runtime, offline).
- A test-only argument-name collision in `signed()` was resolved. A source-spoofing regression found the initial validator allowed unknown client state flags; changed to **exact preview schema and full canonical equality**. Invalid persisted-items raising HTTPException is caught and mapped to a fixed fail-closed error. All were rerun PASS.
- Parallel 8-worker SQLite transaction tests: 2 PASS, exactly one winner and 2 consumed nonces. **Not** a PG concurrency test.
- Local `compileall` and source no-route/no-write review PASS.
- DB catalog Stage3 posting prerequisite previously **BLOCKED**, exact new SHA 7/7 J1–J6 CI **NOT RUN**, hosted browser integration **NOT RUN**, independent issuer E2E **NOT RUN**. No signed Stage1–8 independent receipt was produced.

## Five gates

| Gate | Verified outcome | Unverified |
|---|---|---|
| G1 code/environment | New Python local compile/import PASS | Complete repository build and exact SHA CI |
| G2 functionality | 107 focused local tests PASS | Actual real business signup and physical delivery |
| G3 stability/regression | Atomic local SQLite contention + previous tests PASS | Real PG17 concurrent write, full J1–J6 |
| G4 UI/UX | NOT RUN | Desktop UI, accessibility and user journey |
| G5 operation/deploy | No auth/write routes, no schema/credential mutation | Hosted HTTPS E2E, customer data, independent audit, release |

**Official 8-stage release stays BLOCKED/PARTIAL; no gate is promoted on synthetic/SQLite proof.** Existing original PostgreSQL-only staging and main remain untouched.
