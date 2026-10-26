# JARVIS WORKS V1.6 — Quotation Import (Review Candidate)

Date: 2026-10-18. Isolated candidate built on `feature/automation-first-v1-5`; not merged into `main`.

## Implemented and actually exercised

1. Support only explicitly identified **견적서/가격견적서** and existing **발주서/수주서/주문서** in safe `.xlsx` and selectable-text PDF layouts. Different documents are rejected; no OCR or layout guessing.
2. Quotations parse company, business number, quote date (not order date), external quotation reference, items, quantities, unit prices, tax category, per-line totals and grand totals. Additional metadata, including project, terms, validity, and quotation delivery date when available, is retained.
3. Fail closed if line item or total is inconsistent, if unsupported columns or fields occur, if source dates conflict, if customer identity differs, or if a file is structurally suspicious.
4. Preview and human supplementation of only missing company/quotation date *do not* create business records. The reviewer must explicitly confirm company, quotation date and total with a fresh preview digest.
5. After confirmation, create or match a tenant-scoped customer and create **only a quotation in `draft` state**. No purchase order, invoice, payment or external acceptance is invented. Source trace remains in `quote_date`, `source_import_id` and `source_document_meta`; existing imported orders remain unchanged.
6. Reject confirmed duplicate file SHA, duplicate external quotation references, and highly similar no-reference quotations based on tenant, company, quotation date, tax, line items and amounts.
7. Existing database fields migrated additively; manual quotation inserts updated to explicit column lists; migration idempotency and preservation of preexisting quotes tested.
8. PC user flow: one primary document intake, source review, user checkbox, quotation draft confirmation modal and link to quotation list.

## Verification evidence

- Baseline V1.5: `100 passed` before modifications.
- V1.6 server & security regression: `120 passed` using `python -m pytest -q --disable-warnings`.
- JavaScript syntax: `node --check app/static/app.js` PASS.
- Python syntax: `python -m py_compile app/main.py app/import_engine.py` PASS.
- Browser integration tests, real Chromium client UI connected to FastAPI TestClient:
  - `tests/browser_quote_import.py`: quotation XLSX preview → no business records → approval → draft quote, no order.
  - `tests/browser_smart_import.py`: existing purchase-order import and analytics PASS.
  - `tests/browser_import_supplement.py`: incomplete order information supplement and approval PASS.
  - `tests/browser_smoke.py`: desktop & mobile Chromium quotation → order → invoice → payment/reversal PASS.
- Real sample-style PDF and XLSX cross-format deterministic extraction and PDF API confirmation tested with synthetic Korean documents.
- Visual screenshots: `proof/v16_quote_review_desktop.png`, `proof/v16_quote_confirmed_desktop.png`.

## Verification boundaries — NOT COMPLETE

- Full enterprise-specific PDF/XLSX layouts, printed scans / OCR, multi-sheet files, XLSX formulas, currencies other than integer KRW, variable tax rules, discounts, credit notes, partial deliveries and partial payments are not broadly supported.
- User-approved quotation **draft** is not proof of external client approval. External transmission or acceptance and real commercial contract status require independent evidence.
- Delivery, invoice, payment document auto-import engines remain **NOT IMPLEMENTED**. The old order-creation implementation still uses a technical internal accepted-quote link; this must eventually be replaced with independent transaction evidence.
- Real enterprise document recognition rate NOT MEASURED. 100% accuracy is neither measured nor guaranteed.
- Codespaces V1.6 live HTTPS validation, independent penetration assessment, real iPhone Safari, production MFA / DB-enforced tenant isolation and production deployment NOT RUN.
- No actual business information should be used in this demo. All fixtures are synthetic.

## Safe next steps

1. Verify V1.6 in an existing private development Codespace with only synthetic data; do not merge to `main` before confirming integrity and existing flows.
2. Create delivery-note evidence and reconciliation, then invoice document pairing, then payment evidence import with bank-source validation.
3. Build broader, explicitly reviewed document-field mapping with page/cell provenance and drift detection; use a gold-standard document corpus to quantify extraction accuracy before enterprise pilots.
4. Finish production identity access controls, MFA, database-level tenant isolation, backups and security tests before external users or personal data.
