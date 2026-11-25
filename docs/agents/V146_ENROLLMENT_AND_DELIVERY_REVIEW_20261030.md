# V14.6 — Independent enrollment and delivery prerequisite review (2026-10-30 KST)

## Protected baseline

Parent Draft PR #58 exact SHA `70c2eb7fe60b95da447c229dee407933e200e891`. This is a review-only branch. No main merge, new Render deployment, permanent Supabase schema mutation, customer transfer, paid resource, or public signup activation. Preserve original J1–J6 and independent exact-SHA acceptance gates.

## Stage 2: implemented isolated review gate

`app/pg_signup_review_gate_v146.py` is a pure function with **no signup route and no account creation**. It validates a canonical enrollment intent and TWO independent, purpose-scoped HMAC-SHA256 proofs: externally verified email control and business ownership, each with a different server-protected issuer key. Both receipts must match the identical company/email/business/request digest, with strict issuer, 900-second TTL, malformed/forged signature, nonce collision and replay rejection. A trustworthy account-existence lookup must return exact false; missing/uncertain lookup fails closed. Output is `REVIEW_READY`, never approval, credentials, email delivery, or password reset.

**Not implemented/verified:** real external business-owner verifier, out-of-band email service, actual key provisioning, atomic account reservation/nonce spending, human final authorization, hosted signup and recovery. Only synthetic test signatures exist. Stage 2 acceptance remains PARTIAL / BLOCKED.

## Stage 3: actual DEV PostgreSQL preflight

`scripts/review/v146_delivery_posting_readiness_readonly.sql` is catalog read-only. Real DEV PostgreSQL17 query yielded:

- Orders, order lines, invoices, invoice lines, payments: PRESENT.
- Existing original `record_payment_v83` and `reverse_payment_v83` RPCs: PRESENT.
- Recognized physical delivery ledger `delivery_notes`, `delivery_notes_v146`, `shipments`: **ABSENT**.
- `posting_gate=BLOCKED_MISSING_REAL_DELIVERY_POSTING_PREREQUISITES`, physical delivery acceptance and hosted business E2E `NOT_VERIFIED`, stage 3 `BLOCKED`.

This is only a catalog prerequisite probe, **not** proof that all possible delivery mechanisms were exhausted. It must not authorize invoice or payment writes. Existing V14.5 invoice preview remains read-only.

## Test and release truth

- Local `pytest`: V14.6 signup proof **35 PASS**; SQL safety tests **2 PASS**; existing V14.5 invoice preview **19 PASS**; aggregate **56 PASS, 0 FAIL, 0 SKIP**.
- Local Python compile/import test PASS. Initial mutation-test TypeError was TEST-ONLY, corrected and rerun; uncertain account lookup now requires strictly `False` to prevent accidental success.
- Real DEV PostgreSQL read-only catalog evidence confirmed a missing prerequisite.
- New exact-head complete J1–J6 CI, hosted new-code browser E2E, independent signed stage receipts, original full product regression, UX and operational load/recovery **NOT RUN**.
- Stage 2 and 3 **PARTIAL/BLOCKED**, official 8-stage release **BLOCKED**; no CI result upgrades a stage by itself.

## Five-Gate

G1 local syntax/import PASS; full build NOT RUN.
G2 isolated verifier PASS; public end-to-end enrollment and delivery POSTING NOT RUN.
G3 56 local tests PASS; exact-head J1–J6 NOT RUN.
G4 desktop hosted UI NOT RUN.
G5 read-only DEV catalog and no mutation PASS; independent release security / operation BLOCKED.

Next change requires approved external proof issuers and an atomic, uniquely constrained, audited, restricted-role PostgreSQL enrollment transaction, plus actual physically verified delivery evidence before invoice posting. No authorization bypass.
