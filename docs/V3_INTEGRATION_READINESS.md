# JARVIS WORKS — V2.9–V3.4 staged integration readiness

**Local review candidate, 2026-10-19. NOT PRODUCTION.** No enterprise/customer data is permitted.

## Product and source contract

The B2B messenger is immediate, company-name-centered and searchable by company name and paginated directory; text, photo, file and order snapshots remain supported. Message history, edits, evidence immutability, server-side tenant authorization and money-related approval gates must remain intact. Preserve the historical V2.8 ZIP verbatim.

## Changes actually implemented in this candidate

### V2.9 — Staff offboarding in the existing SQLite demo

- Add `staff_disabled` as a separate forward-only table, **not** a new `users` column: preserves seven-column historical inserts and data. Disable and enable require same-tenant administrator and fresh password reauthentication. A disabled user's server sessions are deleted and login denied. Historical business data, order receipts and message authorship are not deleted. Enable does not recreate a session.
- Refuse disabling one's own currently authenticated administrator account; other-company IDs yield 404. Enforce CSRF and audit `staff_disabled`/`staff_enabled` events without storing the admin password. Add admin UI in security center with a dedicated password form, and responsive staff controls.
- **Not implemented:** new employee invitation/acceptance, independent email verification, government business-registry validation, broad enterprise role lifecycle, verified support recovery, high-assurance reauthentication, official security audit.

### V3.0 — Isolated PostgreSQL adapter review seam (NOT connected)

- `app/pg_messenger_review.py` defines parameterized list/send/read operations with a verified actor/session-binding contract. All connection attempts are refused unless an explicit local `jw_app` URI points to `jw_v20_test_<12 hex>`; database name, role and PostgreSQL major version are checked again on the connection.
- Read queries start a READ ONLY transaction before any SELECT. SQL statement timeouts are set via parameterizable `set_config`; missing `psycopg`, invalid token, wrong identity/role/host/schema fail closed. A dependency-free fake-cursor contract test validates query ordering and isolation assumptions but **is not live PostgreSQL proof**.
- **Not implemented:** actual FastAPI routing to PG, verified trusted PG auth session provisioning, actual PostgreSQL policy acceptance/execution, migration/rollback of all data, object storage/antivirus/key rotation.

### V3.1 — Company onboarding/employee lifecycle

- Only administrator-controlled staff suspension and restoration are implemented in the running SQLite demo. Verified company enrollment and self-service invitation remain blocked until a trusted business-registry source and identity-verification workflow are approved and tested. The existing demo company identities are synthetic and must not be presented as verified legal entities.

### V3.2 — Recovery drill

- Tests verify encrypted, authenticated SQLite snapshot backup, restore to a **new** destination, row-level semantic equality, SQLite integrity, failure on tampering and wrong key, refusal to overwrite existing target. Only synthetic data is tested; production RTO/RPO and remote restore remain unknown.

### V3.3 — Load smoke

- Three independent runs, each 160 synthetic messages with 8 concurrent SQLite writers, recording throughput and write p95/max latency. The test asserts zero missing rows, monotonically increasing durable sequences and SQLite integrity. Not a capacity benchmark of a network/PG service.

### V3.4 — UI and integration

- Chromium desktop 1440x900 and mobile 390x844 runs: staff suspension/restoration with FastAPI TestClient backend bridge. Existing messenger Chromium flow re-tested (company directory, pagination, new messages, draft preservation, plus menu). All previous source screenshots restored without overwriting archived evidence.
- Full pytest and source syntax are required to pass against the **final** version. Browser tests are in-process API bridges, not actual iPhone Safari or publicly reachable servers.

## Hard release gates (do not bypass)

1. PostgreSQL 17 + psycopg + fresh disposable instance: execute existing V2.8 RLS attack gate **for real**, inspect catalog, roles and SQLSTATE, retain clean teardown evidence. Until then: `NOT RUN`.
2. Review/Fix all errors from that run; only then wire a transaction-scoped PG adapter to individual FastAPI routes on a nonproduction branch. Dual-run synthetic migration + downgrade/rollback with exact row counts, message/attachment SHA-256 and order snapshot equality.
3. Operator-verified business registry and lifecycle: proofs of authority to enroll a company, duplicate-business handling, role approvals, employee invite/revoke, MFA, independent recovery.
4. Object storage encrypted at rest, virus/CDR processing, access audit, quotas, retention and deletion obligations; separate approval for real customer information.
5. Adversarial multi-tenant integration, performance and failure/restart/backup drills, physical browsers and independent security review, then deployment approval. **No remote code publishing or production deployment has been done.**

## PostgreSQL RLS threat model

`ENABLE ROW LEVEL SECURITY` alone is not sufficient: superusers / `BYPASSRLS` bypass it; ordinary table owners bypass without `FORCE ROW LEVEL SECURITY`; `TRUNCATE` and `REFERENCES` are not RLS-covered. Inspect grants, ownership, `FORCE`, roles, `SECURITY DEFINER`, sessions, connections and revocation behavior against the official PostgreSQL 17 specification: https://www.postgresql.org/docs/17/ddl-rowsecurity.html.
