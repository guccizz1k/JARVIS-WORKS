# NARUV ONE integrated completion register

Baseline bb23f16486a3bdb2035461b562891e3a258a2a20, draft PR #164. CI 45573568059 and 45573568185 completed successfully (11 jobs, including three isolated file transaction services). Preserve evidence at exact SHA; not production acceptance.

## Current wave
- Native review route: existing V90 PostgreSQL session and role validation; admin-only, exact HTTPS origin/CSRF, streamed 1 MiB bound and upload timeout, revalidation after upload, server-owned source lookup with forced RLS, exact CSV/XLSX parser, no persistence or write permission. Registration is explicit and default-off; not mounted on legacy app.
- New independent PG17 HTTP tests use the existing disposable V90/V92 session fixture, not a simulated DB. HTTPS origin is emulated, not real TLS. Registry is synthetic; no actual ERP target or production authorization. The existing lab transaction implementation is unchanged.
- Known integration boundary: lab transaction roles map one login per tenant, while native sessions use a shared nonprivileged business login. Do not bridge these with superuser credentials or a user-controlled tenant GUC. A dedicated reviewed native write boundary, production source registry, durable approval/receipt authorization and retention controls are required before enabling writes.
- Earlier missing FastAPI test dependency fixed at baseline. New tests use the full existing dev requirements. Keep negative controls, report only actual results.

## Remaining release tracks (no guessed completion percent)
| Track | Status / acceptance condition |
| --- | --- |
| Existing WORKS/V22.3 candidate integration | reconcile approved SHA/UI and previous evidence; verify integration conflicts before change |
| ERP migration | isolated file/approval/write/restore PASS at baseline; native preview candidate, actual ERP vendor profiles, source registry, import permissions, durable writes and audit not complete |
| Shared tenant identity and authorization | native review candidate only; role/session revocation, same-transaction authorization for writes, real auth/TLS and all module RLS required |
| Sales, purchasing, invoicing, messenger | existing assets; integration and end-to-end workflow acceptance outstanding |
| Finance/accounting | actual ledger, period locks, KRW/VAT, reconciliation, legal/accounting acceptance; scope not frozen by this document |
| HR/payroll, inventory/logistics, production | requirements and domain constraints must be reconciled before writes; no fake completed modules |
| Document automation and NARUV AI | provenance, deterministic calculations, approval guard, privacy, prompt injection defense, validated corpus and exact acceptance cases |
| Approved UI | preserve original; integrate server APIs and test real desktop browser, accessibility and workflows |
| Security, backup, recovery, performance | preserve evidence; new candidate threat model, independent QA, recovery of integrated schema, load/limits and actual operations tests |
| Release | all required conditions PASS, no unresolved P0/P1, independent review; separate user authorization for merge/deploy/production changes |

P0 security/data loss and P1 blocking dependency errors are resolved before dependent work; independent tracks may proceed while P2-P4 defects are recorded. No PARTIAL counts as PASS. Do not confuse feature tests with full-project completion. Independent tool evidence, official docs, and CI logs must be identified separately from model review. No changes to main, production DB, UI, Render, backups/recovery keys, CORE or TOOLKIT from this wave.
