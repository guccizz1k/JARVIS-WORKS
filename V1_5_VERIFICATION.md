# JARVIS WORKS V1.5 — Verification and release boundary

Date: 2026-10-18. Offline development candidate. No production deployment.

## Done

- Priority sidebar navigation: **document automation** comes before Dashboard.
- Login opens the upload/review workflow by default.
- Dashboard provides primary file upload CTA; per-module creation is secondary exception/fallback.
- Automated review queue uses tenant/user-scoped metadata and omits original file bytes and raw line items.
- Documents must be explicitly reviewed before creating an order. Existing exact arithmetic and duplicate protection preserved.
- Extensive long analytics is opt-in with expandable panel; upload/review always visible first.
- Full product document type matrix clearly separates implemented order import from unsupported quote, delivery, invoice, payment attachments.

## Actual test evidence

- `python -m pytest -q --disable-warnings`: 100 PASS (94 existing + 6 new).
- `node --check app/static/app.js`: PASS.
- `python -m py_compile app/main.py`: PASS.
- `tests/browser_smart_import.py`: PASS, PDF/XLSX-preview-confirm workflow simulated against real FastAPI using Chromium.
- `tests/browser_import_supplement.py`: PASS, incomplete XLSX held, user confirmation only after supplement and review.
- `tests/browser_smoke.py`: PASS on desktop/mobile Chromium, prior quote→order→invoice→payment/reversal preserved.
- Screenshot: `proof/v15_automation_home_desktop.png`.

## Not delivered; do not mark complete

- Automatic quotation capture, delivery receipt posting, invoice OCR/parse and invoice pairing, verified bank receipt import/payment posting: NOT IMPLEMENTED. Current engine rejects these sources, rather than inserting them as orders.
- Free-layout unknown templates and scanned PDFs: NOT IMPLEMENTED.
- Native iPhone Safari, real customer forms, production HTTPS deployment, MFA, database-enforced tenant isolation: NOT RUN/NOT IMPLEMENTED.

## Next development gates

1. Introduce independent source-document evidence entities and no fabricated acceptance events.
2. Quotation parser + draft write only after review; match original quote to orders by quote number, business ID, values.
3. Delivery/inspection proof linking; invoice and payment evidence stages without automatic banking claims.
4. Field-level provenance/page-cell origin, confidence, drift detection and feedback-based mappings.
5. Production security baseline before real PII.
