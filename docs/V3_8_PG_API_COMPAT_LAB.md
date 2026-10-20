# JARVIS WORKS V3.8 — Typed PG17 compatibility API laboratory

**REVIEW ONLY, NO LIVE API OR PRODUCTION MIGRATION.** The owner-provided V3.7 Codespaces screenshot confirmed the previous isolated PG17 gate PASS. This does not authorize operational cutover.

## Precisely scoped development

The existing V3.7 typed compatibility archive and RLS remain untouched. This new API factory (`app/pg_compat_read_api_v38.py`) can **only** use the disposable `jw_v20_test_*` localhost PostgreSQL 17 DB, the `jw_app` role and explicit synthetic gate flags. It is not imported/mounted by `app/main.py` and does not listen on a network port. Every request binds an independent verified synthetic session to a fresh PostgreSQL connection. Database forced RLS (not claimed tenant fields from HTTP) selects visible data.

Three bounded GET endpoints:
- message page with exact order-ID/order-snapshot metadata and version, page limit ≤100;
- an attachment streamed as forced octet-stream with no sniffing, exact content SHA-256 and no user-provided filename in the header;
- own-tenant read-position. None accepts a client-supplied organization ID.

Security tests include denied third-party messages/attachments/receipt visibility, expired/revoked synthetic session, outsider inaccessible thread, no write endpoint, malformed pagination, order snapshot evidence, byte integrity, preservation of original V3.7 record data and atomic teardown.

## Approval/operational boundary

Not a production PostgreSQL adapter. Does not migrate real organizations/users, run external HTTP, alter SQLite, use real company data, send advertisements, collect leads, spend cloud money or merge main. Requires owner-run short Codespaces command for **new V3.8 live PG17** proof.

## Engineering and go-to-market quality

- `/FIRSTPRINCIPLES`: any leaked/misread order evidence undermines B2B trust more than new UI features.
- `/SKEPTIC`, `/COUNTER`, `/RISK`: try tenant C, credential revocation, tampered attachment, URL traversal, hidden mutation.
- `/TESTIT`, `/VERIFY`, `/FINALCHECK`: local static/functional/regr and live PG17 gates must be distinguished.
- `/PERSONA`, `/MARKET`, `/HOOK`, `/KPI`: value proposition for a verified business pilot is **correct bilateral context**, measured as end-to-end task completion with opt-in businesses; no claims of market success or paid ads without data.

Next separate phase: design write-capable PG transactional adapter with enterprise identity provisioning, idempotency, consistent order snapshot semantics, backup, recoverable migration/rollback, and UI test. No switch of live runtime before proofs.
