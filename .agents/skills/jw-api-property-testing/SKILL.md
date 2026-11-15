---
name: jw-api-property-testing
description: Design bounded property-based negative API and financial invariant tests for JARVIS-WORKS FastAPI validation tenant permissions idempotency and document conversion.
---

# JARVIS-WORKS API property and negative-case verifier

J1–J6 subordinate review-only skill. Never fuzz an external production endpoint or main; product release BLOCKED until independent E2E.

1. Inventory actual FastAPI routes and documented OpenAPI contract in a safe checked-out fixture. Separate SQLite demo endpoints from optional PG17 staged routes.
2. Test input boundaries: missing/null fields, bool-as-int, negative or overflow KRW, duplicate idempotency keys, invalid date/time zone, malformed file bytes, XLSX formula injection, overlong company identifiers and concurrency conflicts.
3. Explicitly check authenticated company A/B/C identity, CSRF, session revocation, RLS CRUD/RPC denial and document/attachment permission; no real customer records.
4. Verify arithmetic invariants, order→invoice→payment reconciliation, atomic transaction rollback and replay consistency. OCR suggestions require source preview and explicit human approval.
5. Use existing pytest FastAPI TestClient and disposable PG17 fixtures first. Hypothesis and Schemathesis are optional future test libraries: NOT INSTALLED by this skill. Schemathesis may WRITE data, so never aim it at Render/Supabase shared databases.
6. Save reproducible minimal input, SHA, environment, seed, passed/failed/skipped and rollback. Unexecuted fuzz and HTTP tests are NOT RUN, not PASS.
7. Protect J1–J6 cost limits and enterprise data. Independent acceptance and real browser/DB proof remain BLOCKED before release.
