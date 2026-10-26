---
name: jw-trade-document-integrity
description: When modifying quotes, orders, supplier purchasing, invoices, payments, refunds, PDF/XLSX imports, OCR approvals, or money reconciliations in JARVIS-WORKS.
---

# Finance and document integrity

J1–J6 subordinate project skill. Review only; `main` and company finance data unchanged. Release BLOCKED.

1. Trace the stable transaction ID, actor and approver across quote, order, delivery, statement, invoice, payment, adjustment, inventory and audit.
2. Verify strict integer KRW and deterministic VAT; reject booleans, floats, negative/overflow, ambiguous conversion or unapproved arithmetic correction.
3. Imported PDF/XLSX/OCR output is a proposal, NOT an authorized payment or order. Require original preview, source provenance, human approval and safe file/formula validation.
4. Test duplicate request IDs, concurrent money writes, wrong-company access, transaction rollback and idempotent retry with genuine persisted results in a disposable DB.
5. Measure field-level ground truth against representative documents; never turn synthetic success into claimed 100% OCR accuracy.
6. Run J1–J6 relevant gates, record actual PASS/FAIL/SKIP, distinguish NOT RUN from success, and require independent reviewer before product release.

Existing seams: `app/pg_quote_api_v92.py`, `app/pg_finance_v83.py`, `app/evidence_v64.py`.
