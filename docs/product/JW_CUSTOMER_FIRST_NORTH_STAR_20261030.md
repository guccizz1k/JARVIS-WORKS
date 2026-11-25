# JARVIS-WORKS — Customer-first product North Star (approved direction, 2026-10-30)

## Authority and intent

This is the owner's approved target direction and long-term backlog, NOT a claim that
all the features below are already implemented, tested, deployed, or sold.
It extends—not replaces—the J1–J6 harness, V9.9–V11.0 eight-stage acceptance,
strict tenant isolation, human approval, zero-skipped tests and existing
immutable-history protection. Keep CORE and WORKS sources separate. For new
projects, reuse the engineering standards, not another project's code or data.

**Customer promise (target, not yet independently demonstrated):** ingest the
counterparty's original PDF/XLSX/photo, extract only supported fields, visually
compare each field to its source, highlight uncertain or mismatched data, require
explicit actor approval, and link the approved quote/order/delivery/invoice/
payment record by transaction ID without repeated entry. No silent posting,
no auto approval, no unverifiable numeric confidence, and no cross-tenant data use.

## Product distinction and entry market

Do not compete by cloning every ERP module at once. Win a complete, observable
workflow from inbound third-party documents through supervised trade linkage.
Initial discovery cohort: Korean wholesale/distribution businesses handling
heterogeneous counterparty purchase orders. Long-term scope remains all industries
and company sizes; this cohort is only the proposed market-entry wedge.
A feature being absent in one competitor's documented workflow is NOT proof
that no competitor offers it. gstack-style CEO/office-hours research is an
advisory framework; no actual gstack CLI review or external founder signoff is
claimed.

## Approved feature order (must not be silently skipped)

| Priority | Capability | Current project reuse | Proof required before feature PASS |
| --- | --- | --- | --- |
| P0 | Side-by-side original-document field locator and correction | evidence_v64 and evidence_quality_v70 | PDF/XLSX/photo coordinates verified against source; unknown locations shown as unknown; human review; desktop accessibility E2E |
| P0 | Priority exception inbox (missing/mismatched totals, duplicates, missing items) | exceptions_v67, reconciliation_v65, evidence_quality_v70 | no hidden exceptions, original-linked evidence, adversarial cross-tenant and immutable audit tests |
| P0 | Single trade-ID timeline quote→order→delivery→invoice→payment | automation_v62 and PG trade candidates | real PostgreSQL same-tenant E2E, idempotency, out-of-order/reversal, zero KRW mismatch |
| P0 | Existing customer Excel/ERP export | automation_v62's draft XLSX | spreadsheet formula injection, round-trip totals, no unsupported tax/legal posting claims |
| P1 | Tenant-local supplier document-format rules | existing import and evidence engines | no training or sharing across tenants, versioning, rollback, measured error rate |
| P1 | Three-way PO/delivery/invoice reconciliation | reconciliation_v65/v66 | split deliveries, extra/missing lines, price/tax discrepancies, documented human decision |
| P1 | Optional mailbox / file-folder ingestion | existing upload queue | explicit consent, isolation, idempotency, malware scanning, clear revoke control |
| P1 | Measured work-time savings dashboard | existing confirmed measurement requirement | same-task before/after measured, samples & confidence intervals shown, no invented savings |
| P2 | Cross-company shared confirmation workspace | messenger_v90 candidates | bilateral permission, 30-minute edit, no deletion, immutable history, safe attachments |

Existing functionality is reused; no functionality is declared complete from
a roadmap checkmark or a green test of a mock. No production/customer data for QA.

## UX constraints

Primary desktop navigation: **문서 등록 → 검토·승인 → 거래 현황**.
Show original document and evidence on the same view; prioritize exceptions
rather than make operators inspect every extracted value. Errors have actionable
plain-Korean messages, and every unverified field visibly requires human review.
Separate advanced ERP/admin controls from the default workflow. Preserve
search+scroll company selection, simple messenger, source/draft immutability,
company display names and actor attribution. Support keyboard, readable text,
responsive layout and browser accessibility tests; never fabricate screen tests.

## Claims, measurements and zero-error gate

Never advertise '100% accuracy', 'zero errors', '90% faster', 'Korea No.1',
'first ever', or superiority to a named competitor without independent
like-for-like measurements. Zero critical money, cross-tenant, unauthorized
posting or missing evidence errors is a **test acceptance goal** on a defined
sample, not a universal warranty. The core sales evidence will be actual
task completion time, manual correction count, accounting mismatches,
task completion without coaching, retention and confirmed willingness to pay.
Keep unknowns as NOT MEASURED, failed tests as FAIL, and out-of-scope as NOT RUN.

## Non-negotiable release gates

1. Preserve existing exact-sha J1–J6 and five engineering gates.
2. Preserve 8 JARVIS-WORKS acceptance stages: authenticated tenant A/B/C,
   full auth/MFA, linked trade lifecycle, real messenger, source-grounded OCR,
   full HTTPS cross-browser service, realistic restore/recovery, independent QA.
3. Any FAIL, ERROR, PARTIAL, SKIP, BLOCKED, NOT RUN or missing independent
   proof means whole release gate = FAIL_NOT_APPROVED.
4. The review-only staging TLS/empty-tenant probe cannot be promoted to
   a real customer app E2E; synthetic PG cannot substitute for the real backend.
5. Require separated reviewer custody, source/command/check inventory,
   blind holdout when demanded, evidence replay defenses and adverse cases.
6. Prohibit unilateral main merge, production/public rollout, real data
   migration, destructive data operations and new paid API usage.
7. GitHub Actions owner budget hard cap remains USD 20 monthly; verify
   current remaining billing allowance before any manually dispatched run.
   Successful runner execution and $0.006/min calculations are NOT billing receipts.
8. Keep incident ledger: symptom → root cause → minimal fix → regression →
   independently reproducible evidence → recurrence prevention.
9. Marketing/CEO/gstack conclusions are unverified hypotheses until actual
   user-observation and measured results substantiate them.

## Engineering rollout sequence

1. Consolidate current UI/DB paths; inventory existing helpers and avoid clones.
2. Finish single tenant-restricted PostgreSQL quote-to-payment happy path
   with source-linked approval, then negative paths, idempotency and recovery.
3. Integrate evidence review UI and exception inbox on the SAME real backend.
4. Introduce guarded integrations and measured task-savings trials.
5. Complete eight-stage independent acceptance, receive explicit owner
   release authorization separately, then and only then plan deployment.

**Status at adoption:** directional requirements ACCEPTED; implementation and
independent business outcome validation NOT COMPLETE; production RELEASE BLOCKED.
