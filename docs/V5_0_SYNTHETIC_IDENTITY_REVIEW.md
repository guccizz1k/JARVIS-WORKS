# V5.0 — Synthetic organization/employee identity consistency gate

**Review-only; never wire this module to public B2B routes, real employees or production databases.**

The previously verified V4.9 mobile shortcut works with this branch via `jw 50` (after publishing). The gate reuses V4.8's full historical PostgreSQL chain and V4.4's existing `MessengerReviewAdapter.verified_transaction()` signed, RLS-enforced actor context. It does not replace user authentication or issue tokens to the public client.

Synthetic SQLite users are compared to synthetic PostgreSQL `public.users`; all links are supplied by trusted test fixtures, not user input. Audit requires **two distinct tenants**, collision-free one-to-one employee mapping, tenant affiliation, non-disabled source users, live signed PG actor confirmation under `jw_app`, and explicit PG17 disposable admin safeguards. Revoked tokens, aliases across tenants, missing users and contradictory data are rejected. Response contains only aggregate counts and an unconditional `cutover_approved=False`.

Disposable real PG17 integration inserts only two synthetic organizations/users and short-lived synthetic signed sessions in the V2.8 test supervisor's existing disposable database; it tests a positive roster, cross-tenant mapping denial, SQLite staff disablement, and PostgreSQL signed-session revocation. The parent supervisor is solely responsible for dropping the disposable database and Docker container. It preserves historical V2.8~V4.9 manifests and main application code. No production DDL, customer data, branch merge or deployment is performed.

**Remaining blockers:** actual employee migration/identity attestation, production-safe token issuance, bidirectional credential lifecycle, dual-write ordering/idempotency, operational rollback, approved production cutover. Passing this synthetic audit does **not** resolve those blockers.

`bash scripts/check_v50_review.sh` runs historical strict local regressions. `bash scripts/run_pg17_codespaces_v50.sh` runs the isolated PG17 chain. In Codespaces use the previously installed CLI: `jw 50`. All SKIPs/FAILs must be investigated, never claimed as PASS.
