# JARVIS WORKS V1.5 — Automation-first UX and strict document routing

## User intent (non-negotiable)

**Upload source documents → automatically detect and extract company/date/items/quantities/prices/totals → compare with existing records and identify anomalies → explicit human review/approval → commit ALL corroborated workflow records and rollups.**

Manual entry is an exception, never the primary user action. Browser-only PC service; mobile development permitted.

## UX hierarchy

1. Primary highlighted sidebar entry, above Dashboard: **문서 업로드 · 자동 처리**.
2. After login, imports is the landing page; one hero CTA with workflow stages.
3. Dashboard begins with a shortcut to file intake, followed by alerts and totals.
4. Transaction views prioritize file intake; manual actions remain as fallback for unsupported forms.
5. Queue of files awaiting review with status and upload times. Original bytes are **not** retained; for an older review, upload source again before approving.
6. Receipt and audit state must never be fabricated. Internal shadow quote in original order-import path is an implementation artifact, **not proof of an external quote**. A subsequent migration should model independent evidence for each document type.

## Coverage matrix — verifiable current behavior

| Source document | Automatic extraction and confirmation | Accounting workflow commit |
|---|---|---|
| Supported structured purchase/order/received order (.xlsx/.pdf text) | Supported; strict per-field validation | Order + customer + internal technical quote record, after user approval |
| External quotation | NOT IMPLEMENTED; reject rather than relabel as order | None |
| Delivery/inspection evidence | NOT IMPLEMENTED; reject | None |
| Invoice/credit note | NOT IMPLEMENTED; reject | None |
| Payment receipt/bank export | NOT IMPLEMENTED; reject; no implicit payment acknowledgement | None |
| Scan/image-only PDF | NOT IMPLEMENTED; OCR not yet verified | None |

## Next architecture phase — evidence-backed independent documents

- **inbound_documents**: encrypted source, tenant, content hash, type, status, uploader, retention policy, immutable metadata; malware scan and PII minimization.
- **extracted_fields**: name/value/type/source page or cell/confidence + validation reason, multiple candidate versions, no guessed amounts.
- **correlation**: invoice/order/quotation/document number, company identifier, item/amount/date comparisons; ambiguous matches require human selection.
- **approval_transaction**: idempotency, source version + digest, immutable actor/timestamp, validated write-set, atomic commit.
- **financial state machine**: quotation draft; order accepted only on order evidence; fulfillment only on delivery evidence; invoice only on invoice evidence; payment only on external verified payment evidence, NEVER only an invoice attachment.
- **reconciliation**: item/qty/VAT/gross, partial delivery, partial payments, credit notes, cancellation/reversal with append-only events.
- **security**: tenant isolation enforced at database boundary, MFA, RBAC, encrypted documents/keys, audit log and retention governance before real client data.

### Implementation priority

A. Quotation import pipeline without false accepted quote status. B. Delivery reconciliation. C. Invoice pairing. D. Payment import and duplicate bank reference controls. E. Multi-layout and OCR after accuracy evaluation and user controls.

## Safety guarantees

- A parser should return **unsupported** or **needs_review**, never silently infer a different document type.
- A user approval cannot make contradictory amounts correct. Re-upload corrected source or reject.
- All data changes happen only through verified backend transaction and must retain source provenance.
- Accuracy '100%' cannot be promised without comprehensive in-domain reference dataset and operational testing; safe failure instead of silent auto-commit.
