# JARVIS WORKS V2.2 — Company Trade Messenger (Review candidate)

Date: 2026-10-19 · **DEVELOPMENT CANDIDATE / NOT PRODUCTION**

## Scope implemented

1. Only organizations with a validated `messenger_companies` profile may be discovered or connected. The demo **fictional** organizations are opt-in demo-verified when `DEMO_SEED=1`; there is NO production business registration/verification or self-approval endpoint.
2. Contact request → opposing organization's administrator accepts → messaging. Pending requests cannot send.
3. Display legal organization name in correspondence; no direct off-platform contacts.
4. 2,000-character text messages; client idempotency IDs; 20 messages / minute per sender; anti-XSS escaping on output; CSRF/cookie authentication inherited.
5. Editing **text only**, initiated at `created_at + 30 minutes` deadline on SERVER, version optimistic-locking, immutable revision history, no delete API and DB delete-denial triggers.
6. Electronic **order snapshot** from existing verified order, NOT a raw uploaded PDF. Sender order must belong to sender organization, source review must not be pending, and its customer business number must match the recipient organization's operator-verified business number. Snapshot records exact line items, VAT, totals, due date and self-reported human processor. Re-sending with same request ID does not duplicate the order message.
7. Recipient can mark **received** once, with self-reported processor's name. Receipt does **not** accept the contract, issue an invoice, register a new ERP order, or mark a payment; the recipient must explicitly review the corresponding document separately.
8. Responsive desktop + narrow mobile viewport UI, manual refresh.
9. Revoked company verification immediately blocks further thread access.
10. Multi-company onboarding is a FUTURE operator-controlled function. Company profile business number is unique in DB; this candidate does NOT independently validate business registration or guarantee exactly one real-world registration.

## Not built / production blockers

- Public signup, eKYC/business-number verification, duplicate legal entity detection beyond a unique registered number.
- Full legal signature/authorized approval with per-person independent authentication; named operators are **self-reported** and not cryptographically attested.
- Typed/PDF attachments, multi-format conversion for both counterparties, automatic receiving-side quote/order/invoice creation, bilateral automatic bookkeeping.
- WebSocket push, delivery guarantees across clusters, unread counts and notifications, retention/legal hold compliance procedures.
- PostgreSQL RLS deployment and full 2-tenant live database attack audit, complete data encryption and externally audited production security.
- Database backup policies for messenger tables, cryptographic audit-log chaining and permission separation for DB operators.
- A hard guarantee against account sharing (no employee self-registration UI exists today; organization credentials are still account-based).

## Verification matrix

- G1: Python source syntax, JS `node --check`, SQLite additive migration: PASS.
- G2: 9 new API/security tests (`tests/test_messenger_v22.py`): PASS (9/9).
- G3: targeted existing quote→order→invoice→payment, tenant/CSRF and import document tests: PASS for the selected cases. Full 186 old + new test batch: **NOT COMPLETED (timed out)**, not PASS.
- G4: Real Chromium DOM interaction with actual app JS/CSS + in-process FastAPI backend: PASS desktop, responsive mobile viewport screenshot. Full HTTP localhost browser run: NOT RUN (host returned `ERR_BLOCKED_BY_ADMINISTRATOR`). No physical device UI verification.
- G5: Production environment startup remains BLOCKED; no production or GitHub deployment: NOT RUN / BLOCKED.

## Handling company credentials, data and expiry

Demo profiles use fictional company identifiers and demo password inherited from V2.1; never populate actual company documents. Database persists messages as SQLite plaintext and is unsuitable for real enterprise data until at-rest encryption, tenant isolation and compliance policies are implemented and audited. Do not claim a self-reported actor name or receipt is legal authorization. Ordinary deletion prohibited; legal deletion/retention policy remains to be built separately.

## How to run locally with fake data

Use the existing `run_demo.sh` under appropriate development controls. Login as the two demo companies. One company sends a request; the counterparty accepts; then messages and matching-buyer order snapshots become available. An order cannot be sent until the existing customer record business number matches the recipient's operator-verified identifier. `JW_ENV=production` intentionally aborts startup.

The original GitHub main and all existing feature branches were not modified by the candidate creation.
