# JARVIS WORKS V2.3 — Simplified B2B Messenger UI / API verification

2026-10-19 · Isolated review candidate. NOT PRODUCTION CERTIFIED.

## User-specified product behavior
- Company identity is shown as a company name in the messenger.
- Registered and operator/demo-verified companies only are discoverable and can exchange messages.
- Search the company directory by company name; scroll the results list with server-side offset/limit pagination (30 per request). No first-200-only search cap.
- One selection opens the business chat immediately. No invitation acceptance or message approval step.
- Minimal two-column desktop and stacked narrow-screen messenger with conversation bubbles, composer and expandable `+` menu (photo, file, existing purchase order).
- Text delivery persists immediately; current active thread re-polls the API every 4.5 seconds when visible. This is **polling**, not WebSocket push or a mobile operating-system notification.
- Existing server-enforced 30-minute editing window, all revisions recorded, end-user delete prohibited.
- Senders may attach images PNG/JPEG/WEBP, documents PDF/XLSX/DOCX, and UTF-8 TXT/CSV up to 5 MiB each; total stored attachment capacity per company limited to 40 MiB in this demo SQLite implementation.
- Attachment download is session-authenticated and conversation-participant-gated, with no-store, nosniff, and forced download of nonimages. Files are stored as immutable evidence (database triggers).
- Existing order transmission matches recipient verified business number to original customer business number; sending a document does NOT imply acceptance, financial approval, invoice or payment.

## Security boundaries
- `messenger_companies` verification in the demo is simulated by fixtures or operator controlled; real business registration and duplicate-company onboarding are not implemented.
- Upload format filters, magic-byte checks and size limits are NOT equivalent to real malware scanning, CDR, attachment sandboxing or full PDF/Office validation. Never put real customer data or production files into this candidate.
- Files are stored as SQLite binary attachments for demo. Production requires separately secured object storage, encryption, retention schedule, antivirus, total retention quotas, and completed PostgreSQL RLS integration.
- Approval was removed for **starting/sending a chat only**. Confirmation/approval for monetary business transactions must remain independent.
- User-facing delete remains disabled. Statutory retention and deletion obligations require dedicated policy and lifecycle implementation.
- Tested identities are fictional demo orgs only. Portal supports two distinct company test logins; no live third-party verification.

## Verified tests and environment
- `tests/test_messenger_v23.py` (6 cases): instant connection, SQL literal search and 64-company pagination, attachment/photo roundtrip and cross-company denial, PDF forced download and dangerous file type/oversize rejection, upgrade of prior pending requests, UI selectors/polling semantics.
- `tests/test_messenger_v22.py` (9 cases): retained text edit history, 30-minute expiry, immutable evidence, order-to-recipient identity binding, CSRF and tenant isolation; prior request acceptance expectation updated to instant chat policy.
- Test batches: messenger 15, security & RLS 73, quotation+entry 26, transactions 22, import supplement 21, smart import 37 = **194/194 PASS**.
- JavaScript `node --check`: PASS. Python `py_compile`: PASS.
- Browser: Chromium desktop 1440×900 and iPhone-sized 390×844 displayed UI and `+` menu; DOM control checks PASS. Real local HTTP browser navigation was blocked by the execution environment. Screenshots therefore use the exact client HTML/CSS/JS with injected representative demo state, not an end-to-end browser-to-HTTP transaction. API behaviors are independently verified with the FastAPI TestClient.
- PostgreSQL live RLS isolation attack tests: **NOT RUN for V2.3**; GitHub publish and real-user iPhone testing: **NOT RUN**.

## Known limitations and status
- `PASS`: specific automated tests above, desktop/mobile DOM rendering, UI layout inspection.
- `NOT RUN`: authenticated live Chromium network flow, actual iPhone Safari, PostgreSQL real isolation gate, external user validation, production deployment.
- `NOT IMPLEMENTED`: mandatory real-world business registration check, secure production file scanning/storage, push/WebSocket notifications, automated receiver-side ERP creation, actual delegated signer authentication.
- Overall judgment **PARTIAL**: independently tested V2.3 candidate, not merged or deployed. The `main` and previous verification branches are not changed.

## Review screenshots
- `proof/v23_messenger_desktop.png`
- `proof/v23_messenger_mobile.png`
