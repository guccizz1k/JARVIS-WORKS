# V15.2 — immutable signup and delivery evidence, actual PG17 proof (2026-10-30 KST)

**Protected parent:** Draft PR #64 HEAD `af2721151ad40b4251e30e1511840dbbb8d47ac4`. Review-only; no main merge, no production or Render deploy, no persistent DB migration, no live customer data, no paid CI/API.

## Actual changes

- Added `jw_dev.v152_reject_evidence_mutation()`, a strictly `SECURITY INVOKER` trigger function raising SQLSTATE `42501` for both UPDATE and DELETE. Attached one BEFORE UPDATE OR DELETE row trigger to each of five review-only ledgers (onboarding request, onboarding nonce, delivery receipt, delivery nonce, source delivery item).
- Explicitly revoked PUBLIC / application / anon / authenticated EXECUTE permissions on new function. This is an append-only candidate within the application's privilege boundary; it is **not** third-party immutable cryptographic storage, and table owners/superusers still have administration access.
- Existing V15.1 tests previously expected a CHECK error for post-save approval attempts. With the new protective BEFORE UPDATE trigger, an insufficient-privilege denial occurs earlier. Updated tests to treat both safe rejection SQLSTATEs as expected rather than falsely FAILing.
- Added two regression contract assertions checking all five triggers exist, no SECURITY DEFINER, no PUBLIC execution, and real PostgreSQL audit test rejects UPDATE and DELETE on every table.

## Executed connected DEV PostgreSQL proof

Fetched exact edited candidate and assertion SQL from the private GitHub review branch, verified absent COMMIT and absent writes to users/invoices/payments. Executed full PostgreSQL 17.11 test **inside BEGIN ... ROLLBACK** after verifying DEV business tables empty. Actual result:

**`PASS_V152_REAL_PG_IMMUTABLE_REVIEW_ROLLBACK`**

Test executed normal synthetic enrollment and source-order/delivery inserts in the rollback transaction, source tenant/line guards, duplicate/forged values, then attempted UPDATE and DELETE against all five nonempty review tables. All ten mutations were denied. All candidate schema objects and synthetic rows were removed by ROLLBACK. The candidate ledger and triggers remain **NOT INSTALLED** persistently.

## Python local evidence and source integrity

- Reconstructed `app/pg_delivery_review_reservation_v151.py` from the actual GitHub code; independently checked its exact Git blob SHA-1: **`cd0138f0e890b29679f673e1890a8b6ecb2cda97`** matches GitHub.
- Targeted isolated 12 tests on that exact source module PASS. Expanded local focused suite **120/120 PASS, 0 FAIL, 0 SKIP**, with fatal ResourceWarning setting. However some earlier V14.7 fixtures/modules remain local mirrors that do not match GitHub HEAD byte-for-byte. **DO NOT** equate this local suite to exact-HEAD J1–J6 or to the new GitHub V15.2 test file. New V15.2 exact checkout pytest remains **NOT RUN**.
- Actual PostgreSQL connected test is stronger evidence for schema constraints than static local test, but not a hosted user-journey E2E.

## 5-Gate, scoped vs full program

1. **G1 PARTIAL:** exact-source V15.1 module verified and isolated Python PASS; actual PG17 candidate DDL parsed/executed. Whole private repo exact HEAD build/CI NOT RUN.
2. **G2 PARTIAL:** actual PostgreSQL immutable review ledger and source guards PASS. Real externally certified business owner/email enrollment, physical proof, invoice posting still not integrated.
3. **G3 PARTIAL:** 120 local focused PASS; actual PG rollback/negative tampering PASS. Real restricted-role multi-writer PostgreSQL and full J1–J6 regression NOT RUN.
4. **G4 NOT RUN:** new candidate has no user-facing UI route. No exact-HEAD desktop Playwright/accessibility check.
5. **G5 PARTIAL:** no public grants, forced RLS and invoker functions, no durable schema side effects; no signed independent audit or hosted exact-HEAD staging E2E.

**Final program acceptance remains PARTIAL/BLOCKED.** A real all-PASS verdict requires active official issuer credentials & verification services, secure isolated staging with approved schema/grants and restricted DB logins, genuine end-to-end multi-user transactions, exact-HEAD full J1–J6 and browser CI, and independent signed launch authorization. User permission to test does not constitute observed verification success.

No production/main merge, no release, no persistent DB changes, no customer migration, no paid workflow, no stage redeploy.
